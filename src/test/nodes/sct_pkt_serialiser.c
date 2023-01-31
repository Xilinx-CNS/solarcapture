/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \addtogroup scnode SolarCapture Nodes
 * @{
 * \struct sc_catchup
 * \brief Node that takes in individual packets and serialises them into blocks
 *        with packet header information (defined in sct_pkt_serialiser.h)
 *        included. Reverses the deserialisers node's operation.
 *
 * \nodeargs
 * No arguments
 *
 * \namedinputlinks
 * None
 *
 * \outputlinks
 * Link  | Description
 * ------| -----------------------------------
 *  ""   | Input packets with packet header information extracted from the packet's attributes in blocks.
 *
 * \cond NODOC
 */
#include <sc_internal.h>
#include <sc_internal/builtin_nodes.h>
#include <solar_capture/nodes/subnode_helper.h>
#include <solar_capture/iovec.h>

#include <errno.h>

#include "sct_pkt_serialiser.h"

struct sct_pkt_serialiser_internal
{
  struct sc_node*              node;
  struct sc_attr*              attr;
  struct sc_subnode_helper*    sh;

  unsigned int                 header_fill;
  unsigned int                 metadata_fill;
  unsigned int                 packet_fill;

  uint32_t                     metadata_len;

  int                          out_pkt_len;
  struct sc_packet*            out_pkt;
  struct sc_serialised_pkt_hdr current_pkt_hdr;

  struct sc_iovec_ptr          in_packet_iovec;
};


static void sct_pkt_serialiser_handle_packets(struct sc_subnode_helper* sh)
{
  struct sct_pkt_serialiser_internal* ps = sh->sh_private;
  struct sc_packet_list pl;
  unsigned int space_left;
  unsigned int written;

  /* Set iovec to point to first packet */
  if( ps->in_packet_iovec.iov == NULL )
    sc_iovec_ptr_init_packet(&ps->in_packet_iovec, sh->sh_backlog.head);

  while( !sc_packet_list_is_empty(&sh->sh_backlog) ) {
    /* fetch an output packet */
    if( ps->out_pkt == NULL ) {
      sc_packet_list_init(&pl);
      if( sc_pool_get_packets(&pl, sh->sh_pool, 1, 1) != 1 )
        return; /* Pool empty */
      ps->out_pkt = pl.head;
      ps->out_pkt_len = ps->out_pkt->iov[0].iov_len;
      ps->out_pkt->iov[0].iov_len = 0;
    }

    space_left = ps->out_pkt_len - ps->out_pkt->iov[0].iov_len;
    /* Need to write a header into the outgoing packet */
    if( ps->header_fill < sizeof(ps->current_pkt_hdr) ) {
      /* Create header data for packet */
      ps->current_pkt_hdr.packet_length = sc_iovec_ptr_bytes(&ps->in_packet_iovec);
      ps->current_pkt_hdr.metadata_length = ps->metadata_len;
      ps->current_pkt_hdr.flags = sh->sh_backlog.head->flags;
      ps->current_pkt_hdr.ts_sec = sh->sh_backlog.head->ts_sec;
      ps->current_pkt_hdr.ts_nsec = sh->sh_backlog.head->ts_nsec;
      ps->current_pkt_hdr.frame_len = sh->sh_backlog.head->frame_len;

      /* Write header data into outgoing packet */
      unsigned int header_size_write = sizeof(ps->current_pkt_hdr) - ps->header_fill;

      /* Don't write off the end of a packet */
      if(header_size_write > space_left)
        header_size_write = space_left;

      /* Write */
      memcpy((uint8_t*)ps->out_pkt->iov[0].iov_base + ps->out_pkt->iov[0].iov_len,
             (uint8_t*)(&ps->current_pkt_hdr) + ps->header_fill, header_size_write);

      ps->header_fill += header_size_write;
      ps->out_pkt->iov[0].iov_len += header_size_write;
      space_left -= header_size_write;
    }
    /* we have the header now write the metadata */
    else if( ps->metadata_fill < ps->metadata_len ) {
      unsigned int metadata_bytes_to_write = ps->metadata_len - ps->metadata_fill;
      if( metadata_bytes_to_write > space_left )
        metadata_bytes_to_write = space_left;

      memcpy((uint8_t*)ps->out_pkt->iov[0].iov_base + ps->out_pkt->iov[0].iov_len,
             (uint8_t*)sh->sh_backlog.head->metadata + ps->metadata_fill,
             metadata_bytes_to_write);
      ps->out_pkt->iov[0].iov_len += metadata_bytes_to_write;
      ps->metadata_fill += metadata_bytes_to_write;
      space_left -= metadata_bytes_to_write;
    }
    /* we have the header and the metadata, now add the data */
    else {
      unsigned int bytes_to_write = ps->current_pkt_hdr.packet_length - ps->packet_fill;
      if( bytes_to_write > space_left )
        bytes_to_write = space_left;

      /* Write in packet data */
      written = sc_iovec_ptr_copy_out(
           ((uint8_t*)ps->out_pkt->iov[0].iov_base) + ps->out_pkt->iov[0].iov_len,
           &ps->in_packet_iovec,
           bytes_to_write);
      ps->out_pkt->iov[0].iov_len += written;

      ps->packet_fill += written;
      space_left -= written;

      /* Finished  */
      if( ps->packet_fill == ps->current_pkt_hdr.packet_length ) {
        ps->header_fill = 0;
        ps->packet_fill = 0;
        ps->metadata_fill = 0;
      }
    }
    /* send packet on if we filled it */
    if( space_left == 0 ) {
      ps->out_pkt->frame_len = ps->out_pkt->iov[0].iov_len < SC_FRAME_LEN_LARGE ?
                                 ps->out_pkt->iov[0].iov_len : SC_FRAME_LEN_LARGE;
      sc_forward(sh->sh_node, sh->sh_links[0], ps->out_pkt);
      ps->out_pkt = NULL;
    }

    /* Free incoming packet */
    if( sc_iovec_ptr_bytes(&ps->in_packet_iovec) == 0 ) {
      sc_forward(sh->sh_node, sh->sh_free_link,
                 sc_packet_list_pop_head(&sh->sh_backlog));
      if( !sc_packet_list_is_empty(&sh->sh_backlog) )
        sc_iovec_ptr_init_packet(&ps->in_packet_iovec, sh->sh_backlog.head);
      else
        ps->in_packet_iovec.iov = NULL;
    }
  }
}

static void sct_pkt_serialiser_end_of_stream(struct sc_subnode_helper* sh)
{
  struct sct_pkt_serialiser_internal* ps = sh->sh_private;
  /* Empty buffered packets */
  if(ps->out_pkt != NULL) {
    sc_forward(sh->sh_node, sh->sh_links[0], ps->out_pkt);
    ps->out_pkt = NULL;
  }

  /* Forward end of stream */
  sc_node_link_end_of_stream(sh->sh_node, sh->sh_links[0]);
}

/* Node Links */
static struct sc_node* sct_pkt_serialiser_select_subnode(struct sc_node* node,
                                                  const char* name,
                                                  char** new_name_out)
{
  struct sct_pkt_serialiser_internal* ps = node->nd_private;
  return ps->sh->sh_node;
}


static int sct_pkt_serialiser_add_link(struct sc_node* from_node,
                                const char* link_name,
                                struct sc_node* to_node,
                                const char* to_name_opt)
{
  struct sct_pkt_serialiser_internal* ps = from_node->nd_private;
  return sc_node_add_link(ps->sh->sh_node, link_name, to_node, to_name_opt);
}

/* Initialisation */
static int sct_packet_setup_subnode(struct sct_pkt_serialiser_internal *ps)
{
  struct sc_node* parent = ps->node;
  struct sc_node* subnode;
  struct sc_thread* thread = sc_node_get_thread(parent);

  struct sc_arg node_args[] = {
    SC_ARG_INT("with_pool", 1),
  };

  int rc = sc_node_alloc_named(&subnode, ps->attr, thread,
                               "sc_subnode_helper", NULL, node_args,
                               sizeof(node_args)/sizeof(node_args[0]));
  if( rc < 0 )
    return sc_node_fwd_error(parent, rc);

  ps->sh = sc_subnode_helper_from_node(subnode);
  ps->sh->sh_private = ps;
  ps->sh->sh_handle_backlog_fn = sct_pkt_serialiser_handle_packets;
  ps->sh->sh_pool_threshold = 1;
  ps->sh->sh_handle_end_of_stream_fn = sct_pkt_serialiser_end_of_stream;

  return 0;
}

static int sct_pkt_serialiser_init(struct sc_node* node,
             const struct sc_attr* attr, const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    SC_TRY(sc_node_type_alloc(&nt, NULL, factory));
    nt->nt_select_subnode_fn = sct_pkt_serialiser_select_subnode;
    nt->nt_add_link_fn = sct_pkt_serialiser_add_link;
  }
  node->nd_type = nt;

  struct sct_pkt_serialiser_internal* ps =
                       sc_thread_calloc(sc_node_get_thread(node), sizeof(*ps));

  int metadata_len;
  int rc;
  if( (rc = sc_node_init_get_arg_int(&metadata_len, node, "metadata_len", 0)) < 0 ||
       metadata_len < 0 )
    return sc_node_set_error(node, EINVAL,
                             "Invalid metadata length %d\n", metadata_len);
  ps->metadata_len = metadata_len;

  ps->packet_fill = 0;
  ps->header_fill = 0;
  ps->metadata_fill = 0;

  node->nd_private = ps;
  ps->node = node;

  ps->attr = sc_attr_dup(attr);
  sc_attr_set_str(ps->attr, "name", "pkt_serialiser_subnode");

  return sct_packet_setup_subnode(ps);
}


const struct sc_node_factory sct_pkt_serialiser_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sct_pkt_serialiser",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sct_pkt_serialiser_init,
};
/** \endcond */
