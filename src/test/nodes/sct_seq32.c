/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#define SC_API_VER  3
#include <solar_capture.h>
#include "sct.h"

#include <time.h>


/* Default: Put sequence number at start of UDPv4 payload. */
#define DEFAULT_OFFSET  (14 + 20 + 8)


struct sct_seq32_gen {
  struct sc_node*            node;
  const struct sc_node_link* next_hop;
  int                        seq_off;
  uint32_t                   seq;
  unsigned                   secs;
};


static void seq32_gen_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct sct_seq32_gen* st = node->nd_private;
  struct sc_packet* next;
  struct sc_packet* pkt;
  uint32_t* p_pkt_seq;

  for( next = pl->head; (pkt = next) && ((next = next->next), 1); ) {
    p_pkt_seq = (void*) ((uint8_t*) pkt->iov[0].iov_base + st->seq_off);
    *p_pkt_seq = st->seq++;
    pkt->ts_sec = st->secs++;
    pkt->ts_nsec = 0;
  }
  sc_forward_list(node, st->next_hop, pl);
}


static void seq32_gen_end_of_stream(struct sc_node* node)
{
  struct sct_seq32_gen* st = node->nd_private;
  sc_node_link_end_of_stream(node, st->next_hop);
}


static int seq32_gen_prep(struct sc_node* node,
                          const struct sc_node_link*const* links,
                          int n_links)
{
  struct sct_seq32_gen* st = node->nd_private;
  st->next_hop = sc_node_prep_get_link_or_free(node, "");
  st->secs = time(NULL);
  return sc_node_prep_check_links(node);
}


static int seq32_gen_init(struct sc_node* node, const struct sc_attr* attr,
                             const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_prep_fn = seq32_gen_prep;
    nt->nt_pkts_fn = seq32_gen_pkts;
    nt->nt_end_of_stream_fn = seq32_gen_end_of_stream;
  }
  node->nd_type = nt;

  struct sct_seq32_gen* st;
  st = sc_thread_calloc(sc_node_get_thread(node), sizeof(*st));
  node->nd_private = st;
  st->node = node;
  if( sc_node_init_get_arg_int(&st->seq_off, node,
                               "offset", DEFAULT_OFFSET) < 0 )
    return -1;
  return 0;
}


const struct sc_node_factory sct_seq32_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sct_seq32",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = seq32_gen_init,
};
