/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \node{sc_ps_packer}
 *
 * \brief Takes individual packets as input and packs them into packed-stream
 * format.
 *
 * \nodedetails
 * Takes individual packets as input and packs them into packed-stream
 * format, outputting larger packed buffers.
 *
 * Control the size of the packed buffers via the 'buf_size' attribute
 * of the attributes you pass in when instantiating the node.
 *
 * \namedinputlinks
 * None
 *
 * \outputlinks
 * Link     | Description
 * -------- | -----------------------------------
 *  ""      | Packed-stream buffers are forwarded on this link
 *
 * \cond NODOC
 */

#include <sc_internal.h>
#include <sc_internal/appliance.h>
#include <sc_internal/packed_stream.h>

#define FLUSH_TIMEOUT_NS 100000000 /* 100 ms */

struct sc_ps_packer_input;
static const struct sc_node_factory sc_ps_packer_input_sc_node_factory;

struct sc_ps_packer {
  struct sc_node*                  node;
  const struct sc_node_link*       next_hop;

  struct sc_ps_packer_input*       pi;

  struct sc_pool*                  pool;
  struct sc_callback*              pool_cb;
  struct sc_attr*                  pool_attr;

  bool                             add_disk_header;
  struct sc_packet*                buffer;
  struct sc_packed_packet*         last_pkt;
  int                              buffer_free;
  uint64_t                         pkt_index;
  uint32_t                         pkt_count;

  struct sc_callback*              flush_cb;
  int                              flush_timeout_ns;
};


struct sc_ps_packer_input {
  struct sc_node*                  node;
  const struct sc_node_link*       next_hop;
  struct sc_ps_packer*             pp;
  struct sc_packet_list            backlog;
};


static bool sc_ps_packer_get_buffer(struct sc_ps_packer* pp)
{
  struct sc_packet_list pl;
  __sc_packet_list_init(&pl);
  if( sc_pool_get_packets(&pl, pp->pool, 1, 1) != 1 ) {
    sc_pool_on_threshold(pp->pool, pp->pool_cb, 1);
    return false;
  }
  pp->buffer = pl.head;
  pp->buffer->flags |= SC_PACKED_STREAM;
  pp->buffer_free = pp->buffer->iov[0].iov_len;
  sc_timer_expire_after_ns(pp->flush_cb, pp->flush_timeout_ns);
  return true;
}


static void sc_ps_packer_emit_buffer(struct sc_ps_packer* pp)
{
  pp->buffer->iov[0].iov_len -= pp->buffer_free;
  if( pp->add_disk_header ) {
    struct sc_packed_packet* hdr = pp->buffer->iov[0].iov_base;
    struct sc_appliance_buffer_header* disk_hdr = (void*)(hdr + 1);
    disk_hdr->data.pkt_count = pp->pkt_count;
    disk_hdr->data.pkts_len = disk_hdr->data.buffer_len - pp->buffer_free;
  }

  sc_forward(pp->node, pp->next_hop, pp->buffer);
  pp->buffer = NULL;
  pp->last_pkt = NULL;
  pp->buffer_free = 0;
  pp->pkt_count = 0;
}


static void sc_ps_packer_go(struct sc_ps_packer* pp)
{
  while( ! sc_packet_list_is_empty(&pp->pi->backlog) ) {
    struct sc_packet* pkt = pp->pi->backlog.head;
    struct sc_packed_packet* hdr;
    struct sc_appliance_buffer_header* disk_hdr;

    int header_len = sizeof(*hdr);
    if( pp->buffer_free < (header_len + pkt->iov[0].iov_len) ) {
      if( pp->buffer )
        sc_ps_packer_emit_buffer(pp);
      if( ! sc_ps_packer_get_buffer(pp) )
        return;
    }

    if( pp->last_pkt == NULL && pp->add_disk_header )
      header_len += sizeof(*disk_hdr);

    int req_bytes = header_len + pkt->iov[0].iov_len;
    SC_TEST( pp->buffer_free >= req_bytes );

    if( pp->last_pkt != NULL )
      hdr = (void*) (((uint8_t*)pp->last_pkt) + pp->last_pkt->ps_next_offset);
    else
      hdr = pp->buffer->iov[0].iov_base;

    pp->last_pkt = hdr;

    hdr->ps_next_offset = req_bytes;
    hdr->ps_pkt_start_offset = header_len;
    hdr->ps_cap_len = pkt->iov[0].iov_len;
    hdr->ps_orig_len = pkt->frame_len;
    hdr->ps_ts_sec = pkt->ts_sec;
    hdr->ps_ts_nsec = pkt->ts_nsec;

    if( header_len > sizeof(*hdr) ) {
      struct sc_appliance_buffer_header* disk_hdr = (void*)(hdr + 1);
      disk_hdr->hdr.prh_type = SC_PACKED_RECORD_APPLIANCE_BLOCK_HEADER;
      disk_hdr->hdr.prh_len = sizeof(disk_hdr->data);
      disk_hdr->data.endianness = PBH_LITTLE_ENDIAN;
      disk_hdr->data.version = PBH_VERSION;
      disk_hdr->data.pkt_index = pp->pkt_index;
      disk_hdr->data.pkt_count = 0;
      disk_hdr->data.buffer_len = pp->buffer_free;
      disk_hdr->data.pkts_len = 0;
      sprintf(disk_hdr->data.stream_id, "sc_ps_packer");
    }

    void* data_ptr = ((uint8_t*) hdr) + hdr->ps_pkt_start_offset;
    memcpy(data_ptr, pkt->iov[0].iov_base, pkt->iov[0].iov_len);

    pp->buffer_free -= req_bytes;
    sc_forward(pp->pi->node, pp->pi->next_hop,
               sc_packet_list_pop_head(&pp->pi->backlog));
    ++pp->pkt_index;
    ++pp->pkt_count;
  }
}


static void sc_ps_packer_pool_cb(struct sc_callback* cb, void* event_info) {
  struct sc_ps_packer* pp = cb->cb_private;
  sc_ps_packer_go(pp);
}


static void sc_ps_packer_flush_cb(struct sc_callback* cb, void* event_info) {
  struct sc_ps_packer* pp = cb->cb_private;
  if( pp->buffer )
    sc_ps_packer_emit_buffer(pp);
}


static int sc_ps_packer_prep(struct sc_node* node,
                             const struct sc_node_link*const* links,
                             int n_links)
{
  struct sc_ps_packer* pp = node->nd_private;
  pp->next_hop = sc_node_prep_get_link_or_free(node, "");

  int rc = sc_node_prep_get_pool(&pp->pool, pp->pool_attr, node, NULL, 0);
  if( rc < 0 )
    return sc_node_fwd_error(node, rc);

  return 0;
}


static struct sc_node* sc_ps_packer_select_subnode(struct sc_node* node,
                                                   const char* name,
                                                   char** new_name_out)
{
  struct sc_ps_packer* pp = node->nd_private;
  return pp->pi->node;
}


static int sc_ps_packer_setup_input(struct sc_ps_packer* pp,
                                    const struct sc_attr* attr)
{
  struct sc_node* node;

  int rc = sc_node_alloc(&node, attr, sc_node_get_thread(pp->node),
                         &sc_ps_packer_input_sc_node_factory, NULL, 0);

  if( rc != 0 )
    return rc;

  pp->pi = node->nd_private;
  pp->pi->pp = pp;

  return 0;
}


static int sc_ps_packer_init(struct sc_node* node,
                             const struct sc_attr* attr,
                             const struct sc_node_factory* factory)
{
  struct sc_thread* thread = sc_node_get_thread(node);
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_prep_fn = sc_ps_packer_prep;
    nt->nt_select_subnode_fn = sc_ps_packer_select_subnode;
  }
  node->nd_type = nt;

  struct sc_ps_packer* pp = sc_thread_calloc(thread, sizeof(*pp));
  node->nd_private = pp;
  pp->node = node;

  int tmp;
  if( sc_node_init_get_arg_int(&tmp, node, "add_disk_header", 0) < 0 )
    return -1;
  pp->add_disk_header = !!tmp;

  if( sc_node_init_get_arg_int(&pp->flush_timeout_ns, node, "flush_timeout_ns",
                               FLUSH_TIMEOUT_NS) < 0 )
    return -1;

  sc_callback_alloc(&pp->flush_cb, attr, thread);
  pp->flush_cb->cb_private = pp;
  pp->flush_cb->cb_handler_fn = sc_ps_packer_flush_cb;

  sc_callback_alloc(&pp->pool_cb, attr, thread);
  pp->pool_cb->cb_private = pp;
  pp->pool_cb->cb_handler_fn = sc_ps_packer_pool_cb;

  pp->pool_attr = sc_attr_dup(attr);
  sc_attr_set_int(pp->pool_attr, "private_pool", 1);

  return sc_ps_packer_setup_input(pp, attr);
}


const struct sc_node_factory sc_ps_packer_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_ps_packer",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_ps_packer_init,
};


static void sc_ps_packer_input_pkts(struct sc_node* node,
                                    struct sc_packet_list* pl)
{
  struct sc_ps_packer_input* pi = node->nd_private;
  bool was_empty = sc_packet_list_is_empty(&pi->backlog);
  sc_packet_list_append_list(&pi->backlog, pl);
  if( was_empty )
    sc_ps_packer_go(pi->pp);
}


static void sc_ps_packer_input_end_of_stream(struct sc_node* node)
{
  struct sc_ps_packer_input* pi = node->nd_private;
  sc_node_link_end_of_stream(pi->node, pi->next_hop);
  if( pi->pp->buffer )
    sc_ps_packer_emit_buffer(pi->pp);
  sc_node_link_end_of_stream(pi->pp->node, pi->pp->next_hop);
}


static int sc_ps_packer_input_prep(struct sc_node* node,
                                   const struct sc_node_link*const* links,
                                   int n_links)
{
  struct sc_ps_packer_input* pi = node->nd_private;
  pi->next_hop = sc_node_prep_get_link_or_free(node, "");
  return 0;
}


static int sc_ps_packer_input_init(struct sc_node* node,
                                    const struct sc_attr* attr,
                                    const struct sc_node_factory* factory)
{
  struct sc_thread* thread = sc_node_get_thread(node);
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_prep_fn = sc_ps_packer_input_prep;
    nt->nt_pkts_fn = sc_ps_packer_input_pkts;
    nt->nt_end_of_stream_fn = sc_ps_packer_input_end_of_stream;
  }
  node->nd_type = nt;

  struct sc_ps_packer_input* pi = sc_thread_calloc(thread, sizeof(*pi));
  node->nd_private = pi;
  pi->node = node;
  sc_packet_list_init(&pi->backlog);
  return 0;
}


static const struct sc_node_factory sc_ps_packer_input_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_ps_packer_input",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_ps_packer_input_init,
};

/** \endcond NODOC */
