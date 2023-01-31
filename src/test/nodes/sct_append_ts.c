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


struct sct_append_ts {
  const struct sc_node_link* next_hop;
};


static void append_ts_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct sct_append_ts* st = node->nd_private;
  struct sc_packet* next;
  struct sc_packet* pkt;
  struct sc_iovec_ptr iovp;
  uint32_t ts[2];
  int rc;

  for( next = pl->head; (pkt = next) && ((next = next->next), 1); ) {
    ts[0] = htonl(pkt->ts_sec);
    ts[1] = htonl(pkt->ts_nsec);
    sc_iovec_ptr_init_buf(&iovp, ts, sizeof(ts));
    rc = sc_packet_append_iovec_ptr(pkt, NULL, &iovp, 1000);
    if( rc < 0 )
      fprintf(stderr, "sct_append_ts: insufficient space to append\n");
  }

  sc_forward_list(node, st->next_hop, pl);
}


static int append_ts_prep(struct sc_node* node,
                       const struct sc_node_link*const* links, int n_links)
{
  struct sct_append_ts* st = node->nd_private;
  st->next_hop = sc_node_prep_get_link_or_free(node, "");
  return sc_node_prep_check_links(node);
}


static int append_ts_init(struct sc_node* node, const struct sc_attr* attr,
                       const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_prep_fn = append_ts_prep;
    nt->nt_pkts_fn = append_ts_pkts;
  }
  node->nd_type = nt;

  struct sct_append_ts* st;
  st = sc_thread_calloc(sc_node_get_thread(node), sizeof(*st));
  node->nd_private = st;
  return 0;
}


const struct sc_node_factory sct_append_ts_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sct_append_ts",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = append_ts_init,
};
