/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/** \cond NODOC */
/*
 * NOTE: We do not want customers to use this node at this point.
 *       If you add any Doxygen documentation, mark it as \internal.
 */
/**
 * Nodes can delegate end of stream handling to this node.  links can be
 * registered with sc_eos_fwd_register_links. Any links registered in this way
 * see an end of stream when the eos_fwd node gets an end_of_stream.
 */

#include <sc_internal.h>
#include <errno.h>
#include <sc_internal/nodes/eos_fwd.h>


struct eos_fwd_entry {
  struct sc_dlist      link;
  const struct sc_node_link* eos_link;
};


struct sc_eos_fwd {
  struct sc_node*            node;
  const struct sc_node_link* next_hop;
  struct sc_dlist            fwd_list;
};


void sc_eos_fwd_register_link(struct sc_node* node,
                              const struct sc_node_link* eos_link)
{
  struct sc_eos_fwd* st = node->nd_private;
  struct eos_fwd_entry* entry = malloc(sizeof(struct eos_fwd_entry));
  assert(sc_node_get_thread(node) ==
         SC_NODE_LINK_IMPL_FROM_NODE_LINK(eos_link)->nl_from_node->ni_thread);
  sc_dlist_init(&entry->link);
  entry->eos_link = eos_link;
  sc_dlist_push_head(&st->fwd_list, &entry->link);
}


static void sc_eos_fwd_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct sc_eos_fwd* st = node->nd_private;
  sc_forward_list(st->node, st->next_hop, pl);
}


static void sc_eos_end_of_stream(struct sc_node* node)
{
  struct sc_eos_fwd* st = node->nd_private;
  struct eos_fwd_entry* entry;
  sc_node_link_end_of_stream(node, st->next_hop);
  SC_DLIST_FOR_EACH_OBJ(&st->fwd_list, entry, link)
    {
      struct sc_node_link_impl* nli =
        SC_NODE_LINK_IMPL_FROM_NODE_LINK(entry->eos_link);
      struct sc_node* from_node = &nli->nl_from_node->ni_node;
      sc_node_link_end_of_stream(from_node,
                                 entry->eos_link);
    }
}


static int sc_eos_fwd_prep(struct sc_node* node,
                             const struct sc_node_link*const* links,
                             int n_links)
{
  struct sc_eos_fwd* st = node->nd_private;
  st->next_hop = sc_node_prep_get_link_or_free(node, "");
  return sc_node_prep_check_links(node);
}


static int sc_eos_fwd_init(struct sc_node* node, const struct sc_attr* attr,
                            const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_prep_fn = sc_eos_fwd_prep;
    nt->nt_pkts_fn = sc_eos_fwd_pkts;
    nt->nt_end_of_stream_fn = sc_eos_end_of_stream;
  }
  node->nd_type = nt;

  struct sc_eos_fwd* st;
  st = sc_thread_calloc(sc_node_get_thread(node), sizeof(*st));
  node->nd_private = st;
  st->node = node;

  sc_dlist_init(&st->fwd_list);

  return 0;
}


const struct sc_node_factory sc_eos_fwd_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_eos_fwd",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_eos_fwd_init,
};
/** \endcond NODOC */
