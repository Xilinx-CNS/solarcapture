/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \node{sc_cpacket_encap}
 *
 * \brief This node adds cPacket timestamps to packets.
 *
 * \nodedetails
 * This node adds cPacket timestamps to packets.
 *
 * \nodeargs
 * Argument     | Optional? | Default | Type             | Description
 * ------------ | --------- | ------- | ---------------- | --------------------------------------------------------------------------------------------
 * fcs_present  | Yes       | detect  | ::SC_PARAM_INT   | Set to 0 if FCS not present in input, 1 if FCS is present.  Leave at default to auto-detect.
 *
 * \namedinputlinks
 * None
 *
 * \outputlinks
 * Link    | Description
 * ------- |----------------------------------------------------------------------------
 * ""      | Receives a copy of the input packets with cPacket encapsulation added.
 * "input" | Input packets are forwarded here unmodified.
 *
 * \cond NODOC
 */

#include <sc_internal.h>
#include <solar_capture/nodes/subnode_helper.h>

#include <arpa/inet.h>
#include <zlib.h>
#include <limits.h>


#pragma pack(push)
#pragma pack(1)

struct cpacket_trailer {  /* CPacket encapsulation */
  uint32_t  seconds;
  uint32_t  nanoseconds;
  uint8_t   version;
  uint16_t  deviceID;
  uint8_t   port;
};


struct trailer {
  uint32_t                    fcs;
  struct cpacket_trailer      cp;
};

#pragma pack(pop)


struct cpacket_encap {
  struct sc_node*             node;
  struct sc_attr*             attr;
  const struct sc_node_link*  next_hop;
  int                         fcs_present;
  struct sc_subnode_helper*   snh;

  struct trailer              trailer;
};


static void detect_fcs(struct cpacket_encap* ct,
                       const struct sc_packet_list* pl)
{
  /* Try to detect whether incoming packets have an FCS at the end.  We
   * assume an FCS is present and attempt to validate it.  We only look at
   * the first packet that claims to have a good checksum: The chances of
   * the FCS being good by chance are small.
   */
  struct sc_packet* next;
  struct sc_packet* pkt;

  for( next = pl->head; (pkt = next) && ((next = next->next), 1); )
    if( ! (pkt->flags & SC_CRC_ERROR) ) {
      uint32_t pkt_fcs;
      sc_iovec_copy_from_end(&pkt_fcs, pkt->iov, pkt->iovlen, sizeof(pkt_fcs));
      SC_TEST( pkt->iovlen == 1 );  /* ?? todo */
      uint32_t calc_fcs = crc32(0, pkt->iov[0].iov_base,
                                pkt->iov[0].iov_len - sizeof(pkt_fcs));
      ct->fcs_present = (calc_fcs == pkt_fcs);
      goto out;
    }

  ct->fcs_present = false;
 out:
  sc_node_add_info_int(ct->node, "fcs_present", ct->fcs_present);
}


static void sc_cpacket_encap_handle_backlog(struct sc_subnode_helper* snh)
{
  /* This is only invoked when the pool has a decent number of buffers in
   * it, so we know for sure we've got everything we need to do one packet.
   * (To keep things simple, we only handle one packet at a time.  The
   * subnode_helper will keep calling us until the backlog is empty).
   */
  struct sc_packet* in_pkt = sc_packet_list_pop_head(&(snh->sh_backlog));
  struct cpacket_encap* ct = snh->sh_private;

  struct sc_packet* out_pkt;
  out_pkt = sc_pool_duplicate_packet(snh->sh_pool, in_pkt, INT_MAX);
  out_pkt->ts_sec = in_pkt->ts_sec;
  out_pkt->ts_nsec = in_pkt->ts_nsec;
  ct->trailer.cp.seconds = htonl(in_pkt->ts_sec);
  ct->trailer.cp.nanoseconds = htonl(in_pkt->ts_nsec);

  struct sc_iovec_ptr iovp;
  if( ct->fcs_present ) {
    sc_iovec_ptr_init_buf(&iovp, &(ct->trailer.cp), sizeof(ct->trailer.cp));
  }
  else {
    SC_TEST( in_pkt->iovlen == 1 );  /* ?? todo */
    ct->trailer.fcs = crc32(0, in_pkt->iov[0].iov_base, in_pkt->iov[0].iov_len);
    if( in_pkt->flags & SC_CRC_ERROR )
      ct->trailer.fcs += 1;
    sc_iovec_ptr_init_buf(&iovp, &(ct->trailer), sizeof(ct->trailer));
  }
  int rc = sc_packet_append_iovec_ptr(out_pkt, snh->sh_pool, &iovp, INT_MAX);
  assert( rc == 0 );
  (void) rc;

  sc_forward(ct->node, ct->next_hop, out_pkt);
  sc_forward(snh->sh_node, snh->sh_links[0], in_pkt);
}


static void sc_cpacket_encap_handle_backlog_1(struct sc_subnode_helper* snh)
{
  struct cpacket_encap* ct = snh->sh_private;

  if( ct->fcs_present < 0 )
    detect_fcs(ct, &(snh->sh_backlog));

  snh->sh_handle_backlog_fn = sc_cpacket_encap_handle_backlog;
  sc_cpacket_encap_handle_backlog(snh);
}


static void sc_cpacket_encap_end_of_stream(struct sc_subnode_helper* snh)
{
  struct cpacket_encap* ct = snh->sh_private;
  sc_node_link_end_of_stream(ct->node, ct->next_hop);
}


static struct sc_node* sc_cpacket_encap_select_subnode(struct sc_node* node,
                                                       const char* name,
                                                       char** new_name_out)
{
  struct cpacket_encap* ct = node->nd_private;
  return ct->snh->sh_node;
}


static int sc_cpacket_encap_add_link(struct sc_node* from_node,
                                     const char* link_name,
                                     struct sc_node* to_node,
                                     const char* to_name_opt)
{
  struct cpacket_encap* ct = from_node->nd_private;
  if( ! strcmp(link_name, "input") )
    return sc_node_add_link(ct->snh->sh_node, "", to_node, to_name_opt);
  else
    return sc_node_add_link(from_node, link_name, to_node, to_name_opt);
}


static int sc_cpacket_encap_prep(struct sc_node* node,
                                 const struct sc_node_link*const* links,
                                 int n_links)
{
  struct cpacket_encap* ct = node->nd_private;
  ct->next_hop = sc_node_prep_get_link_or_free(node, "");
  if( sc_node_prep_check_links(node) < 0 )
    return -1;
  SC_TEST( sc_node_prep_get_pool(&(ct->snh->sh_pool), ct->attr, node, NULL, 0)
           == 0 );
  ct->snh->sh_pool_threshold = 32;
  return 0;
}


static int sc_cpacket_encap_init(struct sc_node* node,
                                 const struct sc_attr* attr,
                                 const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_prep_fn = sc_cpacket_encap_prep;
    nt->nt_select_subnode_fn = sc_cpacket_encap_select_subnode;
    nt->nt_add_link_fn = sc_cpacket_encap_add_link;
  }
  node->nd_type = nt;

  int fcs_present;
  if( sc_node_init_get_arg_int(&fcs_present, node, "fcs_present", -1) < 0 )
    return -1;
  int device_id;
  if( sc_node_init_get_arg_int(&device_id, node, "device_id", 0) < 0 )
    return -1;
  int port;
  if( sc_node_init_get_arg_int(&port, node, "port", 0) < 0 )
    return -1;

  struct sc_thread* thread = sc_node_get_thread(node);
  struct cpacket_encap* ct = sc_thread_calloc(thread, sizeof(*ct));
  node->nd_private = ct;
  ct->node = node;
  ct->fcs_present = fcs_present;
  ct->trailer.cp.version = 1;
  ct->trailer.cp.deviceID = htons(device_id);
  ct->trailer.cp.port = port;
  SC_TEST( ct->attr = sc_attr_dup(attr) );

  struct sc_node* snh_node;
  SC_TEST( sc_node_alloc_named(&snh_node, attr, thread, "sc_subnode_helper",
                               NULL, NULL, 0) == 0 );
  ct->snh = sc_subnode_helper_from_node(snh_node);
  ct->snh->sh_private = ct;
  ct->snh->sh_handle_backlog_fn = sc_cpacket_encap_handle_backlog_1;
  ct->snh->sh_handle_end_of_stream_fn = sc_cpacket_encap_end_of_stream;
  sc_node_add_info_int(node, "fcs_present", ct->fcs_present);
  return 0;
}


const struct sc_node_factory sc_cpacket_encap_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_cpacket_encap",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_cpacket_encap_init,
};

/** \endcond NODOC */
