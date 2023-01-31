/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \node{sc_rr_gather}
 *
 * \brief This node receives packets from multiple inputs, and forwards one
 * packet from each input in turn in round-robin order.
 *
 * \nodedetails
 * This node receives packets from multiple inputs, and forwards one
 * packet from each input in turn in round-robin order.  See sc_rr_spreader
 * for more details.
 *
 * \nodeargs
 * None
 *
 * \namedinputlinks
 * None
 *
 * \cond NODOC
 */

#include <sc_internal.h>
#include <sc_internal/builtin_nodes.h>
#include <solar_capture/nodes/subnode_helper.h>

#include <errno.h>
#include <assert.h>


struct rr_gather {
  struct sc_attr*            attr;
  struct sc_node*            to_node;
  char*                      to_name;
  struct sc_subnode_helper** inputs;
  int                        n_inputs;
  int                        n_eos;
  int                        next_input_i;
};


static void sc_rr_gather_drain(struct rr_gather* st)
{
  struct sc_subnode_helper* snh = st->inputs[st->next_input_i];
  assert( ! sc_packet_list_is_empty(&(snh->sh_backlog)) );
  do {
    sc_forward(snh->sh_node, snh->sh_links[0],
               sc_packet_list_pop_head(&(snh->sh_backlog)));
    if( ++(st->next_input_i) == st->n_inputs )
      st->next_input_i = 0;
    snh = st->inputs[st->next_input_i];
  } while( ! sc_packet_list_is_empty(&(snh->sh_backlog)) );
}


static void sc_rr_gather_pkts(struct sc_subnode_helper* snh)
{
  struct rr_gather* st = snh->sh_private;
  assert( ! sc_packet_list_is_empty(&(snh->sh_backlog)) );
  if( st->inputs[st->next_input_i] == snh )
    sc_rr_gather_drain(st);
}


static void sc_rr_gather_end_of_stream(struct sc_subnode_helper* snh)
{
  struct rr_gather* st = snh->sh_private;
  SC_TEST( st->n_eos < st->n_inputs );
  if( ++(st->n_eos) == st->n_inputs ) {
    int i;
    for( i = 0; i < st->n_inputs; ++i ) {
      snh = st->inputs[i];
      SC_TEST( sc_packet_list_is_empty(&(snh->sh_backlog)) );
      sc_node_link_end_of_stream(snh->sh_node, snh->sh_links[0]);
    }
  }
}


static struct sc_node*
  sc_rr_gather_select_subnode(struct sc_node* node,
                              const char* name, char** new_name_out)
{
  struct rr_gather* st = node->nd_private;
  struct sc_node* input_node;
  SC_TRY( sc_node_alloc_named(&input_node, st->attr, sc_node_get_thread(node),
                              "sc_subnode_helper", NULL, NULL, 0) );
  struct sc_subnode_helper* snh = sc_subnode_helper_from_node(input_node);
  snh->sh_handle_backlog_fn = sc_rr_gather_pkts;
  snh->sh_handle_end_of_stream_fn = sc_rr_gather_end_of_stream;
  snh->sh_private = st;
  SC_REALLOC(&(st->inputs), st->n_inputs + 1);
  st->inputs[st->n_inputs] = snh;
  ++(st->n_inputs);
  if( st->to_node != NULL ) {
    int rc = sc_node_add_link(input_node, "", st->to_node, st->to_name);
    if( rc < 0 ) {
      sc_node_fwd_error(node, rc);
      return NULL;
    }
  }
  return input_node;
}


static int
  sc_rr_gather_add_link(struct sc_node* from_node, const char* link_name,
                        struct sc_node* to_node, const char* to_name_opt)
{
  struct rr_gather* st = from_node->nd_private;
  if( st->to_node != NULL )
    return sc_node_set_error(from_node, EINVAL, "sc_rr_gather: ERROR: only "
                             "one outgoing link allowed\n");
  st->to_node = to_node;
  st->to_name = (to_name_opt == NULL) ? NULL : strdup(to_name_opt);
  int rc, i;
  for( i = 0; i < st->n_inputs; ++i ) {
    rc = sc_node_add_link(st->inputs[i]->sh_node, "", to_node, to_name_opt);
    if( rc < 0 )
      return sc_node_fwd_error(from_node, rc);
  }
  return 0;
}


static int sc_rr_gather_init(struct sc_node* node, const struct sc_attr* attr,
                               const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_select_subnode_fn = sc_rr_gather_select_subnode;
    nt->nt_add_link_fn = sc_rr_gather_add_link;
  }
  node->nd_type = nt;

  struct rr_gather* st;
  st = sc_thread_calloc(sc_node_get_thread(node), sizeof(*st));
  node->nd_private = st;
  SC_TEST( st->attr = sc_attr_dup(attr) );
  /* st->next_input_i = 0; */
  return 0;
}


const struct sc_node_factory sc_rr_gather_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_rr_gather",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_rr_gather_init,
};

/** \endcond NODOC */
