/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#include <sc_internal.h>

#include "sct.h"
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <assert.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <limits.h>


struct sender_state {
  /* Resources (constant after init and prep). */
  struct sc_node*            node;
  const struct sc_node_link* next_hop;
  struct sc_callback*        callback;
  struct sc_pool*            pool;
  struct sc_attr*            attr;

  /* Configuration (constant after init and prep). */
  int                        n;       /* -ve means forever */
  int                        frame_len;

  /* State. */
  int                        n_sent;
};


static int init_pkt_udp(void* p, int frame_len)
{
  struct sockaddr_in sa_local, sa_remote;
  sa_local.sin_addr.s_addr = inet_addr("172.168.1.1");
  sa_local.sin_port = htons(8081);
  sa_remote.sin_addr.s_addr = inet_addr("255.255.255.255");
  sa_remote.sin_port = htons(9091);

  struct ether_header* eth = p;
  memset(eth->ether_dhost, 0xff, 6);
  memset(eth->ether_shost, 0x12, 6);
  eth->ether_type = htons(ETHERTYPE_IP);

  struct iphdr* ip = (void*) (eth + 1);
  struct udphdr* udp = (void*) (ip + 1);  /* IP options not supported */
  uint8_t* payload = (void*) (udp + 1);
  uint8_t* payload_end = (uint8_t*) eth + frame_len;
  int udp_pay_len = payload_end - payload;
  assert(udp_pay_len >= 0);
  memset(payload, 0x23, udp_pay_len);

  udp->source = sa_local.sin_port;
  udp->dest = sa_remote.sin_port;
  udp->len = htons(udp_pay_len);
  udp->check = 0;

  ip->ihl = sizeof(*ip) >> 2;
  ip->version = 4;
  ip->tos = 0;
  ip->tot_len = (uint8_t*) payload_end - (uint8_t*) ip;
  ip->tot_len = htons(ip->tot_len);
  ip->id = 0;
  ip->frag_off = 0;
  ip->ttl = 1;
  ip->protocol = IPPROTO_UDP;
  ip->check = 0;
  ip->saddr = sa_local.sin_addr.s_addr;
  ip->daddr = sa_remote.sin_addr.s_addr;

  return (uint8_t*) payload_end - (uint8_t*) eth;
}


static void sender_go(struct sender_state* st)
{
  struct sc_packet_list pl;
  struct sc_packet* next;
  struct sc_packet* pkt;

  __sc_packet_list_init(&pl);
  int n = (st->n > 0) ? st->n - st->n_sent : INT_MAX;
  sc_pool_get_packets(&pl, st->pool, 0, n);

  if( pl.num_pkts > 0 ) {
    for( next = pl.head; (pkt = next) && ((next = next->next), 1); ) {
      pkt->frame_len = init_pkt_udp(pkt->iov[0].iov_base, st->frame_len);
      pkt->iov[0].iov_len = pkt->frame_len;
      pkt->ts_sec = 0;
      pkt->ts_nsec = 0;
      ++(st->n_sent);
    }
    sc_forward_list(st->node, st->next_hop, &pl);
    if( st->n_sent == st->n )
      sc_node_link_end_of_stream(st->node, st->next_hop);
  }
  if( st->n <= 0 || st->n < st->n_sent )
    sc_pool_on_threshold(st->pool, st->callback, 1);
}


static void sender_callback(struct sc_callback* cb, void* event_info)
{
  struct sender_state* st = cb->cb_private;
  sender_go(st);
}


static int sender_prep(struct sc_node* node,
                       const struct sc_node_link*const* links, int n_links)
{
  struct sender_state* st = node->nd_private;
  st->next_hop = sc_node_prep_get_link_or_free(node, "");

  TEST(sc_node_prep_get_pool(&st->pool, st->attr, node, &st->next_hop, 1) == 0);
  sc_timer_expire_after_ns(st->callback, 0);
  return sc_node_prep_check_links(node);
}


static int sender_init(struct sc_node* node, const struct sc_attr* attr,
                       const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_prep_fn = sender_prep;
  }
  node->nd_type = nt;

  struct sender_state* st;
  st = sc_thread_calloc(sc_node_get_thread(node), sizeof(*st));
  node->nd_private = st;
  st->node = node;

  if( sc_node_init_get_arg_int(&st->n, node, "n", -1) < 0 )
    goto error;
  if( sc_node_init_get_arg_int(&st->frame_len, node, "frame_len", 42) < 0 )
    goto error;
  if( st->frame_len < 42 ) {
    sc_node_set_error(node, EINVAL, "sct_sender: bad frame_len=%d (min 42)\n",
                      st->frame_len);
    goto error;
  }

  TEST(sc_callback_alloc(&st->callback, attr, sc_node_get_thread(node)) == 0);
  st->callback->cb_private = st;
  st->callback->cb_handler_fn = sender_callback;
  st->attr = sc_attr_dup(attr);
  SC_TRY(sc_attr_set_int(st->attr, "private_pool", 1));
  return 0;

 error:
  free(st);
  return -1;
}


const struct sc_node_factory sct_sender_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sct_sender",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sender_init,
};
