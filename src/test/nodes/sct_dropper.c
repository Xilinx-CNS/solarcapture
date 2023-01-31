/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#define SC_API_VER 4
#include <solar_capture.h>

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>

struct sct_dropper {
  struct sc_node* node;
  double drop_chance;
  const struct sc_node_link* good;
  const struct sc_node_link* drop;
};


static void sct_dropper_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct sct_dropper* drp = node->nd_private;

  while (!sc_packet_list_is_empty(pl)) {
    struct sc_packet* pkt = sc_packet_list_pop_head(pl);

    if (drp->drop_chance >= ((1.0 * rand()) / RAND_MAX))
      sc_forward(node, drp->drop, pkt);
    else
      sc_forward(node, drp->good, pkt);
  }
}


static int sct_dropper_prep(struct sc_node* node,
                              const struct sc_node_link*const* links,
                              int n_links)
{
  struct sct_dropper* drp = node->nd_private;

  if( (drp->good = sc_node_prep_get_link(node, "")) == NULL )
    return sc_node_set_error(node, EINVAL, "dropper: no output.\n");

  if( (drp->drop = sc_node_prep_get_link_or_free(node, "drop")) == NULL )
    return sc_node_set_error(node, EINVAL,
      "dropper: error finding a \"drop\" output.\n");

  return sc_node_prep_check_links(node);
}

static void sct_dropper_eos(struct sc_node* node) {
  struct sct_dropper* drp = node->nd_private;

  sc_node_link_end_of_stream(node, drp->good);
  sc_node_link_end_of_stream(node, drp->drop);
}


static int sct_dropper_init(struct sc_node* node, const struct sc_attr* attr,
                              const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_pkts_fn = sct_dropper_pkts;
    nt->nt_prep_fn = sct_dropper_prep;
    nt->nt_end_of_stream_fn = sct_dropper_eos;
  }
  node->nd_type = nt;

  struct sct_dropper* drp;
  drp = sc_thread_calloc(sc_node_get_thread(node), sizeof(*drp));
  node->nd_private = drp;
  drp->node = node;

  if( sc_node_init_get_arg_dbl(&drp->drop_chance, node, "drop_chance", 0.5) < 0 ||
      drp->drop_chance < 0.0 || drp->drop_chance > 1.0 )
    goto error;

  int seed_argument;
  unsigned int seed;

  if( sc_node_init_get_arg_int(&seed_argument, node, "seed", time(NULL)) < 0)
    goto error;

  fprintf(stdout, "sct_dropper: using random seed %d\n", seed_argument);

  seed = seed_argument;
  srand(seed);

  return 0;

 error:
  return -1;
}


const struct sc_node_factory sct_dropper_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sct_dropper",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sct_dropper_init,
};
