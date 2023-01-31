/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#define SC_API_VER 1
#include <solar_capture.h>

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <stdint.h>
#include <inttypes.h>


struct scatter_state {
  const struct sc_node_link** hops;
  int                         n_hops;
  unsigned                    seed;
};


static void scatter_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct scatter_state* st = node->nd_private;
  struct sc_packet* next;
  struct sc_packet* pkt;

  for( next = pl->head; (pkt = next) && ((next = next->next) || 1); )
    sc_forward(node, st->hops[rand() % st->n_hops], pkt);
}


static int scatter_prep(struct sc_node* node,
                        const struct sc_node_link*const* links, int n_links)
{
  struct scatter_state* st = node->nd_private;
  int i;

  st->hops = malloc(n_links * sizeof(st->hops[0]));
  for( i = 0; i < n_links; ++i )
    st->hops[i] = links[i];
  st->n_hops = n_links;

  return 0;
}


static int scatter_init(struct sc_node* node, const struct sc_attr* attr,
                           const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_pkts_fn = scatter_pkts;
    nt->nt_prep_fn = scatter_prep;
  }
  node->nd_type = nt;

  struct scatter_state* st;
  st = sc_thread_calloc(sc_node_get_thread(node), sizeof(*st));
  node->nd_private = st;

  st->seed = time(NULL);  /* NB. We don't need high quality randomness! */

  return 0;
}


const struct sc_node_factory sct_scatter_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sct_scatter",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = scatter_init,
};
