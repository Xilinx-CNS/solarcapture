/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#ifndef __SC_NODE_IMPL_H__
#define __SC_NODE_IMPL_H__


#define SC_PARAM_TYPE_NAME(i)                   \
  ((i) == 0 ? "str" :                           \
   (i) == 1 ? "int" :                           \
   (i) == 2 ? "obj" :                           \
   (i) == 3 ? "dbl" : "(unknown)")

enum sc_node_link_flags {
  SC_NL_FOUND             = 0x1,
  SC_NL_EOS               = 0x2,
};


struct sc_node_link_impl {
  struct sc_node_link      nl_public;
  struct sc_node_impl*     nl_from_node;
  struct sc_node_impl*     nl_to_node;
  int                      nl_flags;
  struct sc_bitmask        nl_pools;
  char*                    nl_to_name;
};


enum sc_node_state {
  SC_NODE_INITED,
  SC_NODE_ADD_LINK,
  SC_NODE_PREPING,
  SC_NODE_PREPED,
  SC_NODE_BROKEN,
};


struct sc_node_impl {
  struct sc_node               ni_node;
  struct sc_packet_list        ni_pkt_list;
  struct sc_thread*            ni_thread;
  struct sc_node_link_impl**   ni_links;
  struct sc_node_stats*        ni_stats;
  int                          ni_n_links;
  int                          ni_n_incoming_links;
  int                          ni_n_incoming_links_preped;
  int                          ni_n_incoming_links_eos;
  enum sc_node_state           ni_state;
  int                          ni_id;
  int                          ni_dispatch_order;
  /* Bitmask of the packet pools that this node can receive packets from. */
  struct sc_bitmask            ni_src_pools;

  /* Bitmask of the nodes that this node can receive packets from. */
  struct sc_bitmask            ni_src_nodes;

  /* Is there a path from node's parent (or parent of parent ...) to it? */
  int                          ni_reachable_from_ancestor;

  /* Link for [sc_thread->dispatch_list]. */
  struct sc_dlist              ni_dispatch_link;
  /* Link for temporary lists (eg. sc_session_prep_nodes()). */
  struct sc_dlist              ni_link;
  /* Non-NULL only while invoking nf_init_fn(). */
  struct sc_args*              ni_init_args;
  int                          ni_set_forward_links;
  struct sc_node_impl*         ni_parent_node;
  struct sc_object_impl        ni_obj;
};


struct sc_node_type_impl {
  struct sc_node_type  nti_nt;
};


#define SC_NODE_IMPL_FROM_NODE(n)                       \
  SC_CONTAINER(struct sc_node_impl, ni_node, (n))

#define SC_NODE_LINK_IMPL_FROM_NODE_LINK(x)                     \
  SC_CONTAINER(struct sc_node_link_impl, nl_public, (x))


/* Just like sc_forward_list(), except that the list need not be finalised.
 * Not part of the public API, so only available to built-in nodes.
 */
#ifdef NDEBUG
# define __sc_forward_list   sc_forward_list
# define __sc_forward_list2  sc_forward_list2
#else
extern void __sc_forward_list(struct sc_node* node,
                              const struct sc_node_link* link,
                              struct sc_packet_list* pl);
extern void __sc_forward_list2(const struct sc_node_link* link,
                               struct sc_packet_list* pl);
#endif


/* Transplanted from public API in later versions.  Not a public API on
 * v1.6 branch.
 */
extern int sc_node_init_delegate(struct sc_node* node,
                                 const struct sc_attr* attr,
                                 const struct sc_node_factory* factory,
                                 const struct sc_arg* args, int n_args);


#endif  /* __SC_NODE_IMPL_H__ */
