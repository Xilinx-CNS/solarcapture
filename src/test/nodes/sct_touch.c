/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#include <sc_internal.h>


struct sct_touch {
  struct sc_node*            node;
  const struct sc_node_link* next_hop;
  int                        fixme;
};


static void touch_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct sct_touch* st = node->nd_private;
  /* ?? todo: options to: pass pkts individually; touch each packet in the
   * list (including frags); touch all of the payload; touch metadata
   */
  sc_forward_list(node, st->next_hop, pl);
}


static int touch_prep(struct sc_node* node,
                       const struct sc_node_link*const* links, int n_links)
{
  struct sct_touch* st = node->nd_private;
  st->next_hop = sc_node_prep_get_link_or_free(node, "");
  return sc_node_prep_check_links(node);
}


static int touch_init(struct sc_node* node, const struct sc_attr* attr,
                       const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_prep_fn = touch_prep;
    nt->nt_pkts_fn = touch_pkts;
  }
  node->nd_type = nt;

  struct sct_touch* st;
  st = sc_thread_calloc(sc_node_get_thread(node), sizeof(*st));
  node->nd_private = st;
  st->node = node;
  if( sc_node_init_get_arg_int(&st->fixme, node, "fixme", -1) < 0 )
    goto error;
  return 0;

 error:
  free(st);
  return -1;
}


const struct sc_node_factory sct_touch_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sct_touch",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = touch_init,
};
