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

#include <stdio.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netdb.h>


#ifndef ETHERTYPE_8021Q
# define ETHERTYPE_8021Q  0x8100
#endif


struct sc_header_editor {
  const struct sc_node_link* next_hop;
  uint32_t                   ip_dest_ne;
  uint32_t                   ip_source_ne;
  uint16_t                   udp_dest_ne;
  uint16_t                   udp_source_ne;
  int                        set_mac;
  uint8_t                    dmac[6];
};


static void sc_header_editor_pkt(struct sc_header_editor* st,
                                 struct sc_packet* pkt)
{
  struct ether_header* eth = pkt->iov[0].iov_base;
  uint16_t* p_ether_type = &eth->ether_type;
  if( *p_ether_type == htons(ETHERTYPE_8021Q) )
    p_ether_type += 2;
  if( *p_ether_type != htons(ETHERTYPE_IP) )
    return;
  struct iphdr* ip = (void*) (p_ether_type + 1);
  if( st->ip_dest_ne )
    ip->daddr = st->ip_dest_ne;
  if( st->ip_source_ne )
    ip->saddr = st->ip_source_ne;
  if( st->set_mac )
    memcpy(eth->ether_dhost, st->dmac, 6);
  struct udphdr* udp;
  switch( ip->protocol ) {
  case IPPROTO_UDP:
    udp = (void*) ((uint32_t*) ip + ip->ihl);
    if( st->udp_dest_ne )
      udp->dest = st->udp_dest_ne;
    if( st->udp_source_ne )
      udp->source = st->udp_source_ne;
    break;
  default:
    break;
  }
}


static void sc_header_editor_pkts(struct sc_node* node,
                                  struct sc_packet_list* pl)
{
  struct sc_header_editor* st = node->nd_private;
  struct sc_packet* next;
  struct sc_packet* pkt;

  for( next = pl->head; (pkt = next) && ((next = next->next), 1); )
    sc_header_editor_pkt(st, pkt);

  sc_forward_list(node, st->next_hop, pl);
}


static void sc_header_editor_end_of_stream(struct sc_node* node)
{
  struct sc_header_editor* st = node->nd_private;
  sc_node_link_end_of_stream(node, st->next_hop);
}


static int sc_header_editor_prep(struct sc_node* node,
                                 const struct sc_node_link*const* links,
                                 int n_links)
{
  struct sc_header_editor* st = node->nd_private;
  st->next_hop = sc_node_prep_get_link_or_free(node, "");
  return sc_node_prep_check_links(node);
}


static int sc_header_editor_init(struct sc_node* node,
                                 const struct sc_attr* attr,
                                 const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    SC_TRY(sc_node_type_alloc(&nt, NULL, factory));
    nt->nt_pkts_fn = sc_header_editor_pkts;
    nt->nt_prep_fn = sc_header_editor_prep;
    nt->nt_end_of_stream_fn = sc_header_editor_end_of_stream;
  }
  node->nd_type = nt;

  struct sc_header_editor* st;
  st = sc_thread_calloc(sc_node_get_thread(node), sizeof(*st));
  node->nd_private = st;

  const char* s;
  int i;

  if( sc_node_init_get_arg_str(&s, node, "ip_source", NULL) < 0 )
    goto error;
  if( s != NULL ) {
    struct in_addr inaddr;
    SC_TEST(inet_aton(s, &inaddr)); /* ?? use getaddrinfo */
    st->ip_source_ne = inaddr.s_addr;
  }

  if( sc_node_init_get_arg_str(&s, node, "ip_dest", NULL) < 0 )
    goto error;
  if( s != NULL ) {
    struct in_addr inaddr;
    SC_TEST(inet_aton(s, &inaddr)); /* ?? use getaddrinfo */
    st->ip_dest_ne = inaddr.s_addr;
    if( (ntohl(st->ip_dest_ne) >> 28) == 14 ) {  /* IP is multicast */
      st->set_mac = 1;
      uint32_t ip_dest = ntohl(st->ip_dest_ne);
      st->dmac[0] = 1;
      st->dmac[1] = 0;
      st->dmac[2] = 0x5e;
      st->dmac[3] = (ip_dest >> 16) & 0x7f;
      st->dmac[4] = (ip_dest >>  8) & 0xff;
      st->dmac[5] =  ip_dest        & 0xff;
    }
  }

  if( sc_node_init_get_arg_int(&i, node, "udp_dest", 0) < 0 )
    goto error;
  if( i )
    st->udp_dest_ne = htons(i);
  if( sc_node_init_get_arg_int(&i, node, "udp_source", 0) < 0 )
    goto error;
  if( i )
    st->udp_source_ne = htons(i);

  return 0;

 error:
  sc_thread_mfree(sc_node_get_thread(node), st);
  return -1;
}


const struct sc_node_factory sc_header_editor_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_header_editor",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_header_editor_init,
};
/** \endcond NODOC */
