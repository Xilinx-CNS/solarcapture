/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#define SC_API_VER 1
#include <solar_capture.h>
#include <solar_capture_ext.h>

#include <errno.h>

/*****************************************************************************/

struct sct_sorepkt_common_state {
};

struct sct_sorepkt_drop_n_state {
  struct sct_sorepkt_common_state common;

  int current_index;
  int drop_interval;

  const struct sc_node_link* forward_hop;
  const struct sc_node_link* drop_hop;
};

union sct_sorepkt_state_u {
  struct sct_sorepkt_common_state  common;
  struct sct_sorepkt_drop_n_state  drop_n;
};


static void
sct_sorepkt_init_common_state(struct sct_sorepkt_common_state* state)
{
  /* Currently a NOP. */
}


/* Maintain a running total of packets seen. Forward each [drop_interval]th
 * packet to the [drop_hop] and the rest to the [forward_hop]. */
static void
sct_sorepkt_drop_n_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct sct_sorepkt_drop_n_state* state = node->nd_private;
  struct sc_packet* pkt = pl->head;

  if( state->drop_interval > 0 ) {
    while( ! sc_packet_list_is_empty(pl) ) {
      pkt = sc_packet_list_pop_head(pl);
      sc_forward(node, ++state->current_index % state->drop_interval ?
                       state->forward_hop : state->drop_hop, pkt);
    }
  }
  else {
    sc_forward_list(node, state->forward_hop, pl);
  }
}


static void sct_sorepkt_drop_n_end_of_stream(struct sc_node* node)
{
  struct sct_sorepkt_drop_n_state* state = node->nd_private;
  sc_node_link_end_of_stream(node, state->forward_hop);
  sc_node_link_end_of_stream(node, state->drop_hop);
}


static int
sct_sorepkt_drop_n_prep(struct sc_node* node,
                        const struct sc_node_link*const* links, int n_links)
{
  struct sct_sorepkt_drop_n_state* state = node->nd_private;
  state->forward_hop = sc_node_prep_get_link_or_free(node, "");
  state->drop_hop    = sc_node_prep_get_link_or_free(node, "drop");
  return sc_node_prep_check_links(node);
}


static int
sct_sorepkt_drop_n_init(struct sc_node* node, const struct sc_attr* attr,
                        const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_prep_fn = sct_sorepkt_drop_n_prep;
    nt->nt_pkts_fn = sct_sorepkt_drop_n_pkts;
    nt->nt_end_of_stream_fn = sct_sorepkt_drop_n_end_of_stream;
  }
  node->nd_type = nt;

  struct sct_sorepkt_drop_n_state* state;
  state = sc_thread_calloc(sc_node_get_thread(node), sizeof(*state));
  node->nd_private = state;

  sct_sorepkt_init_common_state(&state->common);
  state->current_index = 0;
  if( sc_node_init_get_arg_int(&state->drop_interval, node, "n", 100) < 0 ) {
    sc_node_set_error(node, EINVAL, "%s: bad arg 'n'\n", __FUNCTION__);
    goto error;
  }

  return 0;

 error:
  sc_thread_mfree(sc_node_get_thread(node), state);
  return -1;
}


const struct sc_node_factory sct_sorepkt_drop_n_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sct_sorepkt_drop_n",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sct_sorepkt_drop_n_init,
};
