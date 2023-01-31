/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#define SC_API_VER 1
#include <solar_capture.h>

#define SC_TYPE_TEMPLATE  <../test/nodes/sct_check_cap_len_types_tmpl.h>
#define SC_DECLARE_TYPES  sct_check_cap_len_stats_declare
#include <solar_capture/declare_types.h>


struct sct_check_cap_len {
  const struct sc_node_link* next_hop;
  struct sct_check_cap_len_stats* stats;
};


static void check_cap_len_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct sct_check_cap_len* st = node->nd_private;
  struct sc_packet* next;
  struct sc_packet* pkt;
  for( next = pl->head; (pkt = next) && ((next = next->next), 1); ) {
    if( pkt->frame_len < sc_packet_bytes(pkt) )
      ++st->stats->size_err;
  }

  sc_forward_list(node, st->next_hop, pl);
}


static int check_cap_len_prep(struct sc_node* node,
                       const struct sc_node_link*const* links, int n_links)
{
  struct sct_check_cap_len* st = node->nd_private;
  st->next_hop = sc_node_prep_get_link_or_free(node, "");
  return sc_node_prep_check_links(node);
}


static void check_cap_len_end_of_stream(struct sc_node* node)
{
  struct sct_check_cap_len* st = node->nd_private;
  sc_node_link_end_of_stream(node, st->next_hop);
}


static int check_cap_len_init(struct sc_node* node, const struct sc_attr* attr,
                       const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_prep_fn = check_cap_len_prep;
    nt->nt_pkts_fn = check_cap_len_pkts;
    nt->nt_end_of_stream_fn = check_cap_len_end_of_stream;
  }
  node->nd_type = nt;

  struct sct_check_cap_len* st;
  st = sc_thread_calloc(sc_node_get_thread(node), sizeof(*st));
  node->nd_private = st;
  sct_check_cap_len_stats_declare(sc_thread_get_session(sc_node_get_thread(node)));
  sc_node_export_state(node, "sct_check_cap_len_stats",
                       sizeof(struct sct_check_cap_len_stats), &st->stats);
  return 0;
}


const struct sc_node_factory sct_check_cap_len_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sct_check_cap_len",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = check_cap_len_init,
};
