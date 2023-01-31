/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
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


struct sct_oprabin {
  const struct sc_node_link* next_hop;
  int                        encapsulated;
  uint64_t                   seq;
};


static void* pkt_udp_payload(struct sc_packet* pkt)
{
  struct ether_header* eth = pkt->iov[0].iov_base;
  uint16_t* p_ether_type = &eth->ether_type;
  if( *p_ether_type == htons(ETHERTYPE_8021Q) )
    p_ether_type += 2;
  if( *p_ether_type != htons(ETHERTYPE_IP) )
    return NULL;
  struct iphdr* ip = (void*) (p_ether_type + 1);
  if( ip->protocol != IPPROTO_UDP )
    return NULL;
  struct udphdr* udp = (void*) ((uint32_t*) ip + ip->ihl);
  return udp + 1;
}


static void sct_oprabin_pkt(struct sct_oprabin* st, struct sc_packet* pkt)
{
  uint8_t* ob;
  if( st->encapsulated )
    ob = pkt_udp_payload(pkt);
  else
    ob = pkt->iov[0].iov_base;

  if( ob != NULL ) {
    const uint8_t* pseq = (void*) &st->seq;
    int i;
    for( i = 0; i < 4; ++i )
      ob[6+i] = pseq[3-i];
    ++st->seq;
  }
}


static void sct_oprabin_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct sct_oprabin* st = node->nd_private;
  struct sc_packet* next;
  struct sc_packet* pkt;

  for( next = pl->head; (pkt = next) && ((next = next->next), 1); )
    sct_oprabin_pkt(st, pkt);

  sc_forward_list(node, st->next_hop, pl);
}


static int sct_oprabin_prep(struct sc_node* node,
                            const struct sc_node_link*const* links,
                            int n_links)
{
  struct sct_oprabin* st = node->nd_private;
  st->next_hop = sc_node_prep_get_link_or_free(node, "");
  return sc_node_prep_check_links(node);
}


static int sct_oprabin_init(struct sc_node* node,
                            const struct sc_attr* attr,
                            const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    SC_TRY(sc_node_type_alloc(&nt, NULL, factory));
    nt->nt_pkts_fn = sct_oprabin_pkts;
    nt->nt_prep_fn = sct_oprabin_prep;
  }
  node->nd_type = nt;

  struct sct_oprabin* st = calloc(1, sizeof(*st));
  node->nd_private = st;
  if( sc_node_init_get_arg_int(&st->encapsulated, node, "encapsulated", 1) < 0 )
    goto error;
  return 0;

 error:
  free(st);
  return -1;
}


const struct sc_node_factory sct_oprabin_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sct_oprabin",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sct_oprabin_init,
};
