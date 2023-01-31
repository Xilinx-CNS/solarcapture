/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \node{sc_merge_sorter}
 *
 * \brief Merges inputs to output, sorting in timestamp order.
 *
 * \nodedetails
 *
 * This node merges its inputs and forwards them to its output in timestamp
 * order.  It is assumed that within each input the packets are already
 * sorted in timestamp order.
 *
 * \nodeargs
 * None
 *
 * \cond NODOC
 */
#include <sc_internal.h>
#include <sc_internal/builtin_nodes.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>


struct sc_merge_sorter;


struct sc_merge_input {
  struct sc_merge_sorter*    merge;
  struct sc_node*            node;
  const struct sc_node_link* next_hop;
  struct sc_packet_list      pkts;
  int                        eos;
};


struct sc_merge_sorter {
  struct sc_merge_input**    inputs;
  int                        n_inputs;
  int                        outgoing_added;
};


static void sc_merge_eos(struct sc_merge_sorter* mg)
{
  int i;
  for( i = 0; i < mg->n_inputs; ++i ) {
    struct sc_merge_input* mi = mg->inputs[i];
    SC_TEST(mi->eos);
    SC_TEST(sc_packet_list_is_empty(&mi->pkts));
    sc_node_link_end_of_stream(mi->node, mi->next_hop);
  }
}


static int score(const struct sc_merge_input* mi)
{
  if( sc_packet_list_is_empty(&mi->pkts) )
    /* If no packets, put at front of list (unless EOS, in which case put
     * at back of list).
     */
    return mi->eos ? 1 : -1;
  return 0;
}


static int qsort_cmp_inputs(const void* pa, const void* pb)
{
  const struct sc_merge_input*const* pia = pa;
  const struct sc_merge_input*const* pib = pb;
  const struct sc_merge_input* ia = *pia;
  const struct sc_merge_input* ib = *pib;

  int sa = score(ia), sb = score(ib);
  if( sa || sb )
    return sa - sb;

  struct sc_packet* pka = ia->pkts.head;
  struct sc_packet* pkb = ib->pkts.head;
  if( pka->ts_sec != pkb->ts_sec )
    return (int) (pka->ts_sec - pkb->ts_sec);
  else
    return pka->ts_nsec - pkb->ts_nsec;
}


static void sc_merge_doit(struct sc_merge_sorter* mg)
{
  while( 1 ) {
    qsort(mg->inputs, mg->n_inputs, sizeof(mg->inputs[0]),
          qsort_cmp_inputs);
    struct sc_merge_input* mi = mg->inputs[0];
    if( sc_packet_list_is_empty(&mi->pkts) ) {
      if( mi->eos )
        sc_merge_eos(mg);
      break;
    }
    struct sc_packet* pkt = sc_packet_list_pop_head(&mi->pkts);
    sc_forward(mi->node, mi->next_hop, pkt);
  }
}


static void sc_merge_input_pkts(struct sc_node* node,
                                struct sc_packet_list* pl)
{
  struct sc_merge_input* mi = node->nd_private;
  sc_packet_list_append_list(&mi->pkts, pl);
  sc_merge_doit(mi->merge);
}


static void sc_merge_input_end_of_stream(struct sc_node* node)
{
  struct sc_merge_input* mi = node->nd_private;
  SC_TEST(mi->eos == 0);
  mi->eos = 1;
  sc_merge_doit(mi->merge);
}


static int sc_merge_input_prep(struct sc_node* node,
                               const struct sc_node_link*const* links,
                               int n_links)
{
  struct sc_merge_input* mi = node->nd_private;
  mi->next_hop = sc_node_prep_get_link_or_free(node, "");
  return sc_node_prep_check_links(node);
}


static int sc_merge_input_init(struct sc_node* node,
                               const struct sc_attr* attr,
                               const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_pkts_fn = sc_merge_input_pkts;
    nt->nt_prep_fn = sc_merge_input_prep;
    nt->nt_end_of_stream_fn = sc_merge_input_end_of_stream;
  }
  node->nd_type = nt;

  struct sc_merge_input* mi = calloc(1, sizeof(*mi));
  node->nd_private = mi;
  mi->node = node;
  sc_packet_list_init(&mi->pkts);
  return 0;
}


static const struct sc_node_factory sc_merge_input_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_merge_input",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_merge_input_init,
};


static int sc_merge_add_link(struct sc_node* from_node, const char* link_name,
                             struct sc_node* to_node, const char* to_name_opt)
{
  struct sc_merge_sorter* mg = from_node->nd_private;
  int i, rc;
  if( mg->n_inputs < 2 )
    sc_warn(sc_thread_get_session(sc_node_get_thread(from_node)),
            "sc_merge_sorter: WARNING: %s only has %d inputs\n",
            from_node->nd_name, mg->n_inputs);
  mg->outgoing_added = 1;
  for( i = 0; i < mg->n_inputs; ++i ) {
    rc = sc_node_add_link(mg->inputs[i]->node, link_name, to_node, to_name_opt);
    if( rc < 0 )
      sc_node_fwd_error(from_node, rc);
  }
  return 0;
}


struct sc_node* sc_merge_select_subnode(struct sc_node* node, const char* name,
                                        char** new_name_out)
{
  /* ?? TODO: Store names with inputs, so that multiple links can be made
   * into a single input.
   */

  struct sc_merge_sorter* mg = node->nd_private;
  int rc;
  if( mg->outgoing_added ) {
    sc_node_set_error(node, EINVAL, "sc_merge_sorter: ERROR: Ingress link "
                      "added after egress link\n");
    return NULL;
  }

  struct sc_node* input_node;
  struct sc_attr* attr;
  SC_TRY(sc_attr_alloc(&attr));
  rc = sc_node_alloc(&input_node, attr, sc_node_get_thread(node),
                     &sc_merge_input_sc_node_factory, NULL, 0);
  sc_attr_free(attr);
  if( rc < 0 ) {
    sc_node_fwd_error(node, rc);
    return NULL;
  }

  int id = (mg->n_inputs)++;
  mg->inputs = realloc(mg->inputs, mg->n_inputs * sizeof(mg->inputs[0]));
  SC_TEST(mg->inputs != NULL);
  mg->inputs[id] = input_node->nd_private;
  mg->inputs[id]->merge = mg;
  return input_node;
}


static int sc_merge_init(struct sc_node* node, const struct sc_attr* attr,
                         const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_add_link_fn = sc_merge_add_link;
    nt->nt_select_subnode_fn = sc_merge_select_subnode;
  }
  node->nd_type = nt;

  struct sc_merge_sorter* mg = calloc(1, sizeof(*mg));
  node->nd_private = mg;
  return 0;
}


const struct sc_node_factory sc_merge_sorter_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_merge_sorter",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_merge_init,
};

/** \endcond NODOC */
