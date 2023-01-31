/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/** \cond NODOC */
/*
 * NOTE: We do not want customers to use this node at this point.
 *       If you add any Doxygen documentation, mark it as \internal.
 */
#define SC_API_VER 4
#include <solar_capture.h>
#include <solar_capture/nodes/subnode_helper.h>
#include <sc_internal/builtin_nodes.h>

#include <errno.h>


struct sc_wrap_undo_state {
  const struct sc_node_link* next_hop;
  struct sc_pool*            pool;
  struct sc_node*            wrap_node;
};


static void sc_wrap_undo_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct sc_wrap_undo_state* run = node->nd_private;

  struct sc_packet_list fwd_pl;
  __sc_packet_list_init(&fwd_pl);

  struct sc_packet *pkt, *next;
  for( next = pl->head; (pkt = next) && ((next = next->next), 1); ) {
    assert( pkt->frags_n == 1 );
    assert( pkt->frags != NULL );
    assert( pkt->frags_tail == &(pkt->frags->next) );
    __sc_packet_list_append(&fwd_pl, pkt->frags);
    pkt->frags = NULL;
    pkt->frags_n = 0;
    pkt->frags_tail = &(pkt->frags);
  }

  sc_pool_return_packets(run->pool, pl);
  sc_packet_list_finalise(&fwd_pl);
  sc_forward_list2(run->next_hop, &fwd_pl);
}


static int sc_wrap_undo_prep(struct sc_node* node,
                              const struct sc_node_link*const* links,
                              int n_links)
{
  struct sc_wrap_undo_state* run = node->nd_private;
  /* NB. Because this node is on the free path it is possible for prep to
   * be called more than once.
   */
  if( run->next_hop != NULL )
    return 0;
  run->next_hop = sc_node_prep_get_link_or_free(node, "");
  sc_node_prep_does_not_forward(node);
  sc_node_prep_link_forwards_from_node(node, run->next_hop, run->wrap_node);
  return 0;
}


static void* get_required_obj(struct sc_node* node, const char* name,
                              enum sc_object_type obj_type)
{
  struct sc_object* obj;
  int rc = sc_node_init_get_arg_obj(&obj, node, name, obj_type);
  if( rc < 0 )
    return NULL;
  if( rc != 0 )
    return sc_node_set_error(node, EINVAL, "sc_wrap_undo: ERROR: required "
                             "arg '%s' missing\n", name), NULL;
  return obj;
}


static int sc_wrap_undo_init(struct sc_node* node,
                              const struct sc_attr* attr,
                              const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_prep_fn = sc_wrap_undo_prep;
    nt->nt_pkts_fn = sc_wrap_undo_pkts;
  }
  node->nd_type = nt;

  struct sc_object* wrap_node_o = get_required_obj(node, "node", SC_OBJ_NODE);
  if( wrap_node_o == NULL )
    return -1;
  struct sc_object* pool_o = get_required_obj(node, "pool", SC_OBJ_POOL);
  if( pool_o == NULL )
    return -1;

  struct sc_wrap_undo_state* run = calloc(1, sizeof(*run));
  node->nd_private = run;
  run->wrap_node = sc_node_from_object(wrap_node_o);
  run->pool = sc_pool_from_object(pool_o);
  return 0;
}


const struct sc_node_factory sc_wrap_undo_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_wrap_undo",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_wrap_undo_init,
};
/** \endcond NODOC */
