/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/** \cond NODOC */
/*
 * NOTE: We do not want customers to use this node at this point.
 *       If you add any Doxygen documentation, mark it as \internal.
 */
#include <sc_internal.h>
#include <sc_internal/builtin_nodes.h>
#include "../core/internal.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <string.h>


struct ref_count_undo_node {
  struct sc_node*     node;
  struct sc_pkt_pool* referenced_pp;
  struct sc_pkt_pool* referring_pp;
  const struct sc_node_link* referenced_free_hop;
};


static inline void sc_ref_count_undo_pkt(struct ref_count_undo_node* run,
                                         struct sc_pkt* pkt)
{
  assert( pkt->sp_pkt_pool_id == run->referring_pp->pp_id );
  assert( pkt->sp_ref_count == 1 );
  assert( pkt->sp_usr.frags != NULL );
  assert( pkt->sp_usr.frags_n == 1 );
  assert( pkt->sp_usr.frags_tail == &(pkt->sp_usr.frags->next) );

  struct sc_pkt* wrapped = SC_PKT_FROM_PACKET(pkt->sp_usr.frags);
  assert( wrapped->sp_pkt_pool_id == run->referenced_pp->pp_id );
  assert( wrapped->sp_ref_count > 0 );

  pkt->sp_ref_count = 0;
  pkt->sp_usr.frags = NULL;
  pkt->sp_usr.frags_n = 0;
  pkt->sp_usr.frags_tail = &(pkt->sp_usr.frags);
  sc_pkt_pool_put(run->referring_pp, pkt);

  if( --(wrapped->sp_ref_count) > 0 )
    return;
  sc_forward(run->node, run->referenced_free_hop, &wrapped->sp_usr);
}


static void sc_ref_count_undo_batch(struct sc_callback* cb, void* event_info)
{
  struct ref_count_undo_node* run = cb->cb_private;
  struct sc_pkt_pool* pp = run->referring_pp;
  struct sc_pkt* pkt;
  int batch_size = 96;  /* ?? perhaps should be tunable? */

  do {
    pkt = SC_PKT_FROM_PACKET(__sc_packet_list_pop_head(&(pp->pp_put_backlog)));
    sc_ref_count_undo_pkt(run, pkt);
    if( sc_packet_list_is_empty(&(pp->pp_put_backlog)) ) {
      pp->pp_put_backlog.tail = &pp->pp_put_backlog.head;
      break;
    }
  } while( --batch_size > 0 );

  sc_pkt_pool_post_refill(run->referring_pp);

  if( ! sc_packet_list_is_empty(&(pp->pp_put_backlog)) )
    sc_timer_expire_after_ns(cb, 1);
}


static void sc_ref_count_undo_pkts(struct sc_node* node,
                                   struct sc_packet_list* pl)
{
  struct ref_count_undo_node* run = node->nd_private;
  struct sc_pkt_pool* pp = run->referring_pp;
  sc_packet_list_append_list(&(pp->pp_put_backlog), pl);
  sc_callback_at_safe_time(pp->pp_cb_backlog);
}


static void* sc_ref_count_undo_get_pp_ptr(struct sc_node* node,
                                          const char* name)
{
  struct sc_object* obj = NULL;
  if( sc_node_init_get_arg_obj(&obj, node, name, SC_OBJ_OPAQUE) < 0 )
    return NULL;
  if( obj == NULL ) {
    sc_node_set_error(node, EINVAL,
                      "%s: ERROR: required arg '%s' missing\n", __func__, name);
    return NULL;;
  }
  return sc_opaque_get_ptr(obj);
}


/* Since this is on the free path it is possible for prep to be called more than
 * once.
 */
static int sc_ref_count_undo_prep(struct sc_node* node,
                                  const struct sc_node_link*const* links,
                                  int n_links)
{
  struct ref_count_undo_node* run = node->nd_private;
  if( run->referenced_free_hop != NULL )
    return 0;
  run->referenced_free_hop = sc_node_prep_get_link_or_free(node, "");
  struct sc_node_link_impl* nl =
    SC_NODE_LINK_IMPL_FROM_NODE_LINK(run->referenced_free_hop);
  sc_node_prep_does_not_forward(node);
  sc_bitmask_clear_all(&(nl->nl_pools));
  sc_bitmask_set(&(nl->nl_pools), run->referenced_pp->pp_id);
  return 0;
}


static const struct sc_node_type sc_ref_count_undo_node_type = {
  .nt_name    = "sc_ref_count_undo",
  .nt_prep_fn = sc_ref_count_undo_prep,
  .nt_pkts_fn = sc_ref_count_undo_pkts,
};


static int sc_ref_count_undo_init(struct sc_node* node,
                                  const struct sc_attr* attr,
                                  const struct sc_node_factory* factory)
{
  node->nd_type = &sc_ref_count_undo_node_type;

  struct ref_count_undo_node* run = calloc(1, sizeof(*run));
  node->nd_private = run;
  run->node = node;
  run->referenced_pp = sc_ref_count_undo_get_pp_ptr(node, "referenced_pp_ptr");
  run->referring_pp = sc_ref_count_undo_get_pp_ptr(node, "referring_pp_ptr");

  struct sc_callback* cb = run->referring_pp->pp_cb_backlog;
  cb->cb_handler_fn = sc_ref_count_undo_batch;
  cb->cb_private = run;

  sc_pool_set_refill_node(&(run->referring_pp->pp_public), node);
  return 0;
}


const struct sc_node_factory sc_ref_count_undo_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_ref_count_undo",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_ref_count_undo_init,
};
/** \endcond NODOC */
