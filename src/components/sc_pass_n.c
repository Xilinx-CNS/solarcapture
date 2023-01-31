/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \node{sc_pass_n}
 *
 * \brief A node which forwards a fixed number of packets.
 *
 * \nodedetails
 * This node forwards the indicated number of packets to its default output
 * link.  Any further packets that arrive at this node are either leaked
 * (default) or forwarded to an output named "the_rest" (if it exists).
 *
 * \nodeargs
 * Argument         | Optional? | Default | Type           | Description
 * ---------------- | --------- | ------- | -------------- | -----------------------------------------------------------------
 * n                | No        |         | ::SC_PARAM_INT | Number of packets to forward.
 *
 * \outputlinks
 * Link        | Description
 * ----------- | ----------------------------------------------------------------
 *  ""         | The first n packets are forwarded here.
 *  "the_rest" | Subsequent packets are forwarded to this output if it exists.
 *
 * \cond NODOC
 */
#include <sc_internal.h>
#include <sc_internal/builtin_nodes.h>

#include <errno.h>


struct sc_pass_n {
  const struct sc_node_link* next_hop;
  const struct sc_node_link* free_hop;

  uint64_t                   n;
};


static void sc_pass_n_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct sc_pass_n* st = node->nd_private;
  if( (unsigned) pl->num_pkts <= st->n ) {
    st->n -= pl->num_pkts;
    sc_forward_list2(st->next_hop, pl);
    if( st->n == 0 )
      sc_node_link_end_of_stream2(st->next_hop);
    return;
  }
  if( st->n ) {
    struct sc_packet_list pl_fwd;
    __sc_packet_list_init(&pl_fwd);
    do {
      __sc_packet_list_append(&pl_fwd, __sc_packet_list_pop_head(pl));
    } while( --(st->n) );
    __sc_forward_list2(st->next_hop, &pl_fwd);
    sc_node_link_end_of_stream2(st->next_hop);
  }
  if( st->free_hop )
    sc_forward_list2(st->free_hop, pl);
  /* Otherwise the packets are leaked. */
}


static void sc_pass_n_end_of_stream(struct sc_node* node)
{
  struct sc_pass_n* st = node->nd_private;
  sc_node_link_end_of_stream2(st->next_hop);
  if( st->free_hop )
    sc_node_link_end_of_stream2(st->free_hop);
}


static int sc_pass_n_prep(struct sc_node* node,
                          const struct sc_node_link*const* links, int n_links)
{
  struct sc_pass_n* st = node->nd_private;
  st->next_hop = sc_node_prep_get_link_or_free(node, "");
  st->free_hop = sc_node_prep_get_link(node, "the_rest");
  return sc_node_prep_check_links(node);
}


static int sc_pass_n_init(struct sc_node* node,
                                  const struct sc_attr* attr,
                                  const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_pkts_fn = sc_pass_n_pkts;
    nt->nt_end_of_stream_fn = sc_pass_n_end_of_stream;
    nt->nt_prep_fn = sc_pass_n_prep;
  }
  node->nd_type = nt;

  int64_t n;
  int rc;
  if( (rc = sc_node_init_get_arg_int64(&n, node, "n", 0)) < 0 )
    return -1;
  if( rc != 0 )
    return sc_node_set_error(node, EINVAL, "sc_pass_n: ERROR: Required arg "
                             "'n' missing\n");

  struct sc_pass_n* st;
  st = sc_thread_calloc(sc_node_get_thread(node), sizeof(*st));
  node->nd_private = st;
  st->n = n;
  return 0;
}


const struct sc_node_factory sc_pass_n_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_pass_n",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_pass_n_init,
};

/** \endcond NODOC */
