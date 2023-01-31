/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \node{sc_no_op}
 *
 * \brief Forward inputs to output.
 *
 * \nodedetails
 * This node forwards its inputs to its output.  It is sometimes useful as
 * a convenience when setting up node graphs because it doesn't care what
 * its inputs and output are named.
 *
 * \nodeargs
 * None
 *
 * \cond NODOC
 */
#include <sc_internal.h>
#include <sc_internal/builtin_nodes.h>

#include <errno.h>


static void sc_no_op_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  const struct sc_node_link* next_hop = node->nd_private;
  sc_forward_list(node, next_hop, pl);
}


static void sc_no_op_end_of_stream(struct sc_node* node)
{
  sc_node_link_end_of_stream(node, node->nd_private);
}


static int sc_no_op_prep(struct sc_node* node,
                          const struct sc_node_link*const* links, int n_links)
{
  /* Accept any link name so long as there is just one outgoing link.  This
   * is sometimes convenient when constructing control-path pipelines...
   */
  if( n_links == 0 )
    node->nd_private = (void*) sc_node_prep_get_link_or_free(node, "");
  else if( n_links == 1 )
    node->nd_private = (void*) links[0];
  else
    return sc_node_set_error(node, EINVAL, "sc_no_op: ERROR: expected 0 or "
                             "1 outgoing links\n");
  return 0;
}


static int sc_no_op_init(struct sc_node* node, const struct sc_attr* attr,
                          const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_prep_fn = sc_no_op_prep;
    nt->nt_pkts_fn = sc_no_op_pkts;
    nt->nt_end_of_stream_fn = sc_no_op_end_of_stream;
  }
  node->nd_type = nt;
  return 0;
}


const struct sc_node_factory sc_no_op_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_no_op",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_no_op_init,
};

/** \endcond NODOC */
