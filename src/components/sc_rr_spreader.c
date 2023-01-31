/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \node{sc_rr_spreader}
 *
 * \brief This node spreads received packets over its set of outgoing links
 * in round-robin order.
 *
 * \nodedetails
 * This node spreads received packets over its set of outgoing links
 * in round-robin order.  It is usually used together with sc_rr_gather to
 * spread load over multiple worker threads.
 *
 * Packets are emitted by sc_rr_gather in the same order that they are
 * received by sc_rr_spreader.  (To ensure this, corresponding links must
 * be added to sc_rr_spreader and sc_rr_gather in the same order).  There
 * is no guarantee as to the order in which packets will be handled by
 * worker threads.
 *
 * This mechanism of spreading load is suitable when the packet processing
 * is stateless, and the work done per packet is either independent of the
 * packet length, or the packet lengths are distributed randomly.
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

#include <errno.h>
#include <assert.h>


struct rr_spreader {
  const struct sc_node_link** links;
  int                         n_links;
  int                         next_link_i;
};


static void sc_rr_spreader_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct rr_spreader* st = node->nd_private;
  struct sc_packet* next;
  struct sc_packet* pkt;

  for( next = pl->head; (pkt = next) && ((next = next->next), 1); ) {
    sc_forward(node, st->links[st->next_link_i], pkt);
    if( ++(st->next_link_i) == st->n_links )
      st->next_link_i = 0;
  }
}


static void sc_rr_spreader_end_of_stream(struct sc_node* node)
{
  struct rr_spreader* st = node->nd_private;
  int i;
  for( i = 0; i < st->n_links; ++i )
    sc_node_link_end_of_stream(node, st->links[i]);
}


static int sc_rr_spreader_prep(struct sc_node* node,
                               const struct sc_node_link*const* links,
                               int n_links)
{
  struct rr_spreader* st = node->nd_private;
  st->links = sc_thread_calloc(sc_node_get_thread(node),
                               n_links * sizeof(st->links[0]));
  SC_TEST(st->links != NULL);
  st->n_links = n_links;
  int i;
  for( i = 0; i < n_links; ++i )
    st->links[i] = links[i];
  return 0;
}


static int sc_rr_spreader_init(struct sc_node* node, const struct sc_attr* attr,
                               const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_pkts_fn = sc_rr_spreader_pkts;
    nt->nt_prep_fn = sc_rr_spreader_prep;
    nt->nt_end_of_stream_fn = sc_rr_spreader_end_of_stream;
  }
  node->nd_type = nt;

  struct rr_spreader* st;
  st = sc_thread_calloc(sc_node_get_thread(node), sizeof(*st));
  node->nd_private = st;
  /* st->next_link_i = 0; */
  return 0;
}


const struct sc_node_factory sc_rr_spreader_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_rr_spreader",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_rr_spreader_init,
};

/** \endcond NODOC */
