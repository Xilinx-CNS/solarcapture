/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#include <sc_internal.h>

#include <errno.h>


struct sct_hold_n {
  const struct sc_node_link* next_hop;
  int                        n;
  struct sc_packet_list      backlog;
};


static void sct_hold_n_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct sct_hold_n* st = node->nd_private;

  sc_packet_list_append_list(&(st->backlog), pl);

  if( st->backlog.num_pkts > st->n ) {
    struct sc_packet_list pl2;
    __sc_packet_list_init(&pl2);
    do
      __sc_packet_list_append(&pl2, __sc_packet_list_pop_head(&(st->backlog)));
    while( st->backlog.num_pkts > st->n );
    sc_packet_list_finalise(&pl2);
    sc_forward_list2(st->next_hop, &pl2);
  }
}


static int sct_hold_n_prep(struct sc_node* node,
                           const struct sc_node_link*const* links,
                           int n_links)
{
  struct sct_hold_n* st = node->nd_private;
  st->next_hop = sc_node_prep_get_link_or_free(node, "");
  return sc_node_prep_check_links(node);
}


static int sct_hold_n_init(struct sc_node* node,
                           const struct sc_attr* attr,
                           const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    SC_TRY(sc_node_type_alloc(&nt, NULL, factory));
    nt->nt_pkts_fn = sct_hold_n_pkts;
    nt->nt_prep_fn = sct_hold_n_prep;
  }
  node->nd_type = nt;

  int n;
  if( sc_node_init_get_arg_int(&n, node, "n", 1) < 0 )
    return -1;

  struct sct_hold_n* st = calloc(1, sizeof(*st));
  SC_TEST( st != NULL );
  node->nd_private = st;
  st->n = n;
  __sc_packet_list_init(&(st->backlog));
  return 0;
}


const struct sc_node_factory sct_hold_n_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sct_hold_n",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sct_hold_n_init,
};
