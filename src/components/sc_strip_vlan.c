/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/** \cond NODOC */
/*
 * NOTE: We do not want customers to use this node at this point.
 *       If you add any Doxygen documentation, mark it as \internal.
 */
#include <sc_internal.h>
#include <sc_internal/builtin_nodes.h>

#include <errno.h>
#include <net/ethernet.h>
#include <netinet/ip.h>


#ifndef ETHERTYPE_8021Q
# define ETHERTYPE_8021Q  0x8100
#endif


struct sc_strip_vlan {
  const struct sc_node_link* next_hop;
  uint16_t                   tpid_ne;
};


static void sc_strip_vlan_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct sc_strip_vlan* st = node->nd_private;
  struct sc_packet* next;
  struct sc_packet* pkt;

  for( next = pl->head; (pkt = next) && ((next = next->next) || 1); ) {
    struct ether_header* eth = pkt->iov[0].iov_base;
    uint16_t* p_ether_type = &eth->ether_type;
    if( *p_ether_type == st->tpid_ne ) {
      pkt->iov[0].iov_base = (char*) eth + 4;
      pkt->iov[0].iov_len -= 4;
      pkt->frame_len -= 4;
      memmove(pkt->iov[0].iov_base, eth, 12);
    }
  }
  sc_forward_list(node, st->next_hop, pl);
}


static void sc_strip_vlan_end_of_stream(struct sc_node* node)
{
  struct sc_strip_vlan* st = node->nd_private;
  sc_node_link_end_of_stream(node, st->next_hop);
}


static int sc_strip_vlan_prep(struct sc_node* node,
                              const struct sc_node_link*const* links,
                              int n_links)
{
  struct sc_strip_vlan* st = node->nd_private;
  st->next_hop = sc_node_prep_get_link_or_free(node, "");
  return sc_node_prep_check_links(node);
}


static int sc_strip_vlan_init(struct sc_node* node, const struct sc_attr* attr,
                             const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_prep_fn = sc_strip_vlan_prep;
    nt->nt_pkts_fn = sc_strip_vlan_pkts;
    nt->nt_end_of_stream_fn = sc_strip_vlan_end_of_stream;
  }
  node->nd_type = nt;

  struct sc_strip_vlan* st;
  st = sc_thread_calloc(sc_node_get_thread(node), sizeof(*st));
  node->nd_private = st;

  int tpid;
  if( sc_node_init_get_arg_int(&tpid, node, "tpid", ETHERTYPE_8021Q) < 0 )
    goto error;
  st->tpid_ne = htons(tpid);
  return 0;


 error:
  sc_thread_mfree(sc_node_get_thread(node), st);
  return -1;
}


const struct sc_node_factory sc_strip_vlan_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_strip_vlan",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_strip_vlan_init,
};

/** \endcond NODOC */