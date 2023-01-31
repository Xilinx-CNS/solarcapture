/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#define SC_API_VER  3
#include <solar_capture.h>
#include "sct.h"

#define SC_TYPE_TEMPLATE  <../test/nodes/sct_seq32_check_types_tmpl.h>
#define SC_DECLARE_TYPES  sct_seq32_check_stats_declare
#include <solar_capture/declare_types.h>

#include <stdio.h>


/* Default: Sequence number is at start of UDPv4 payload. */
#define DEFAULT_OFFSET  (14 + 20 + 8)


struct sct_seq32_check {
  struct sc_node*               node;
  const struct sc_node_link*    next_hop;
  int                           seq_off;
  struct sct_seq32_check_stats* stats;

  uint32_t                      seq_expected;
  int                           in_sync;
};


static void seq32_check_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct sct_seq32_check* st = node->nd_private;
  const uint32_t* p_pkt_seq;
  struct sc_packet* next;
  struct sc_packet* pkt;

  for( next = pl->head; (pkt = next) && ((next = next->next), 1); ) {
    p_pkt_seq = (void*) ((uint8_t*) pkt->iov[0].iov_base + st->seq_off);
    if( st->in_sync ) {
      int32_t delta = *p_pkt_seq - st->seq_expected;
      if( delta == 0 ) {
        /* in order */
      }
      else if( delta > 0 ) {
        ++(st->stats->gaps);
        st->stats->drops += delta;
      }
      else if( *p_pkt_seq == 0 ) {
        ++(st->stats->resets);
      }
      else {
        ++(st->stats->backwards);
      }
    }
    else {
      st->in_sync = 1;
    }
    st->seq_expected = *p_pkt_seq + 1;
  }
  sc_forward_list(node, st->next_hop, pl);
}


static void seq32_check_end_of_stream(struct sc_node* node)
{
  struct sct_seq32_check* st = node->nd_private;
  sc_node_link_end_of_stream(node, st->next_hop);
}


static int seq32_check_prep(struct sc_node* node,
                            const struct sc_node_link*const* links,
                            int n_links)
{
  struct sct_seq32_check* st = node->nd_private;
  st->next_hop = sc_node_prep_get_link_or_free(node, "");
  return sc_node_prep_check_links(node);
}


static int seq32_check_init(struct sc_node* node, const struct sc_attr* attr,
                            const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_prep_fn = seq32_check_prep;
    nt->nt_pkts_fn = seq32_check_pkts;
    nt->nt_end_of_stream_fn = seq32_check_end_of_stream;
  }
  node->nd_type = nt;

  struct sc_thread* thread = sc_node_get_thread(node);
  struct sct_seq32_check* st;
  st = sc_thread_calloc(thread, sizeof(*st));
  node->nd_private = st;
  st->node = node;
  if( sc_node_init_get_arg_int(&st->seq_off, node,
                               "offset", DEFAULT_OFFSET) < 0 )
    return -1;
  sct_seq32_check_stats_declare(sc_thread_get_session(thread));
  sc_node_export_state(node, "sct_seq32_check_stats",
                       sizeof(struct sct_seq32_check_stats), &st->stats);
  return 0;
}


const struct sc_node_factory sct_seq32_check_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sct_seq32_check",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = seq32_check_init,
};
