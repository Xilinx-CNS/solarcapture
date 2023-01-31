/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \node{sc_subnode_helper}
 *
 * \brief Node used as a sub-node to manage inputs and/or pools.
 *
 * \nodedetails
 * This node is used as a subnode to manage buffered input and/or outputs
 * that use a packet pool.  It is never instantiated on its own.  Here are
 * two example scenarios where this node is helpful:
 *
 * 1) Generating output based on the input without modifying the input.
 * The top-level node instantiates a pool and an sc_subnode_helper, and
 * directs its input to the subnode.  Incoming buffers are placed in the
 * backlog, and the handler is invoked when the backlog is non-empty and
 * the pool has buffers.  ie. When the resources are available to make
 * progress.
 *
 * 2) Keeping multiple inputs separate.  When a node receives buffers from
 * multiple input links it is not possible to tell which buffers came from
 * which input.  A solution is to use an nt_select_subnode_fn() handler to
 * instantiate a subnode for each distinct input.
 *
 * When packets are received by an sc_subnode_helper they are appended to a
 * backlog list (sc_subnode_helper::sh_backlog).  The backlog handler is
 * invoked repeatedly until either the backlog is emptied or the packet
 * handler leaves the backlog unmodified.  If
 * sc_subnode_helper::sh_pool_threshold is set, then the backlog handler is
 * only invoked so long as the pool has at least the requested number of
 * buffers available.
 *
 * If sc_subnode_helper::sh_handle_end_of_stream_fn is set then it is
 * invoked when the end-of-stream signal has been received and the backlog
 * is empty.  If sh_pool_threshold is also set, the end-of-stream handler
 * is only invoked when the pool has at least the requested number of
 * buffers available.
 *
 * If sc_subnode_helper::sh_poll_backlog_ns is set then the backlog handler
 * is invoked periodically whenever the backlog is non-empty, even if the
 * pool threshold has been set and not yet reached.
 *
 * When 'with_pool=1', a packet pool is allocated and a pointer stored at
 * sc_subnode_helper::sh_pool.  The attributes of the pool are set by the
 * attributes passed to the node allocation function.
 *
 * Alternatively sh_pool can be set to point at a pool allocated elsewhere
 * (eg. by the parent node).  This is useful when implementing nodes that
 * forward information from inputs to outputs, but in new buffers.
 *
 * By default, a link for freeing packets is allocated and placed in
 * sc_subnode_helper::sh_free_link.  If with_free_link=0 then a free link
 * is not allocated.  If with_free_link=2 then a free link is only
 * allocated if the node has no other outgoing links.
 *
 * Any outgoing links added to the node are made available via
 * sc_subnode_helper::sh_links and sc_subnode_helper::sh_n_links.  If no
 * links are added then a copy of sh_free_link (if requested) is placed at
 * sh_links[0].  This allows access sh_links[0] without having to check
 * whether any links were added.
 *
 * See also ::sc_subnode_helper for further details of the interface to
 * this node.
 *
 * \nodeargs
 * Argument                 | Optional? | Default | Type           | Description
 * ----------------------   | --------- | ------- | -------------- | ----------------------------------------
 * with_pool                | Yes       | 0       | ::SC_PARAM_INT | Whether to allocate a pool.
 * with_free_link           | Yes       | 1       | ::SC_PARAM_INT | Whether to allocate a free link.
 *
 * \outputlinks
 * You can add an arbitrary set of outgoing links to this node, and they
 * are made available via sc_subnode_helper::sh_links.
 *
 * \nodestatscopy{sc_subnode_helper}
 *
 * \cond NODOC
 */

struct sc_subnode_helper;

#include <time.h>
#include <errno.h>
#include <sc_internal.h>
#include <sc_internal/builtin_nodes.h>
#include <solar_capture/nodes/subnode_helper.h>

#define SC_TYPE_TEMPLATE  <sc_subnode_helper_types_tmpl.h>
#define SC_DECLARE_TYPES  sc_subnode_helper_stats_declare
#include <solar_capture/declare_types.h>


struct sc_input_subnode {
  struct sc_subnode_helper        sh;
  struct sc_attr*                 pool_attr;
  struct sc_subnode_helper_stats* stats;
  struct sc_callback*             pool_cb;
  struct sc_callback*             timer_cb;
  bool                            eos_seen;
  int                             with_free_link;
};


#define SH_TO_SIS(i) SC_CONTAINER(struct sc_input_subnode, sh, (i))

void sc_subnode_helper_request_callback(struct sc_subnode_helper* sh)
{
  struct sc_input_subnode* sis = SH_TO_SIS(sh);
  sc_timer_expire_after_ns(sis->timer_cb, 1);
}


static void
sc_subnode_helper_propagate_end_of_stream(struct sc_input_subnode* sis)
{
  SC_TEST( sis->eos_seen );
  SC_TEST( sc_packet_list_is_empty(&sis->sh.sh_backlog) );
  if( sis->sh.sh_handle_end_of_stream_fn == NULL ) {
    if( sis->sh.sh_free_link != NULL )
      sc_node_link_end_of_stream(sis->sh.sh_node, sis->sh.sh_free_link);
    int i;
    for( i = 0; i < sis->sh.sh_n_links; ++i )
      sc_node_link_end_of_stream(sis->sh.sh_node, sis->sh.sh_links[i]);
  }
  else {
    if( sis->sh.sh_pool_threshold > 0 &&
        sc_pool_available_bufs(sis->sh.sh_pool) < sis->sh.sh_pool_threshold )
      sc_pool_on_threshold(sis->sh.sh_pool, sis->pool_cb,
                           sis->sh.sh_pool_threshold);
    else
      sis->sh.sh_handle_end_of_stream_fn(&sis->sh);
  }
}


static void sc_subnode_helper_handle_backlog(struct sc_input_subnode* sis,
                                             bool timeout)
{
  assert( ! sc_packet_list_is_empty(&(sis->sh.sh_backlog)) );

  int prev_pool_threshold = sis->sh.sh_pool_threshold;

  while( 1 ) {
    if( sis->sh.sh_pool_threshold > 0 && ! timeout &&
        sc_pool_available_bufs(sis->sh.sh_pool) < sis->sh.sh_pool_threshold ) {
      sc_pool_on_threshold(sis->sh.sh_pool, sis->pool_cb,
                           sis->sh.sh_pool_threshold);
      break;
    }

    int prev_length = sis->sh.sh_backlog.num_pkts;
    sis->sh.sh_handle_backlog_fn(&(sis->sh));

    if( sc_packet_list_is_empty(&(sis->sh.sh_backlog)) ) {
      sc_callback_remove(sis->pool_cb);
      sc_callback_remove(sis->timer_cb);
      if( sis->eos_seen )
        sc_subnode_helper_propagate_end_of_stream(sis);
      return;
    }

    if( sis->sh.sh_backlog.num_pkts == prev_length ) {
      /* Didn't make progress. */
      struct sc_subnode_helper* sh = &sis->sh;
      if( sh->sh_pool && (sh->sh_pool_threshold != prev_pool_threshold ||
                          sc_pool_available_bufs(sh->sh_pool) <
                          sh->sh_pool_threshold ) )
        /* Pool dry or threshold changed, so re-enable the pool callback. */
        sc_pool_on_threshold(sis->sh.sh_pool, sis->pool_cb,
                             sis->sh.sh_pool_threshold);
      else if( ! timeout )
        /* Disable pool callback else may get stuck in a tight loop. */
        sc_callback_remove(sis->pool_cb);
      break;
    }
  }

  if( sis->sh.sh_poll_backlog_ns )
    sc_timer_expire_after_ns(sis->timer_cb, sis->sh.sh_poll_backlog_ns);
}


static void sc_subnode_helper_timeout(struct sc_callback* cb, void* event_info)
{
  struct sc_input_subnode* sis = cb->cb_private;
  sc_subnode_helper_handle_backlog(sis, true);
  sis->stats->backlog_len = sis->sh.sh_backlog.num_pkts;
}


static void sc_subnode_helper_pool_cb(struct sc_callback* cb, void* event_info)
{
  struct sc_input_subnode* sis = cb->cb_private;
  assert( ! sc_packet_list_is_empty(&sis->sh.sh_backlog) ||
          sis->eos_seen );
  if( ! sc_packet_list_is_empty(&sis->sh.sh_backlog) )
    sc_subnode_helper_handle_backlog(sis, false);
  else
    sc_subnode_helper_propagate_end_of_stream(sis);

  sis->stats->backlog_len = sis->sh.sh_backlog.num_pkts;
}


static void sc_subnode_helper_pkts(struct sc_node* node,
                                   struct sc_packet_list* pl)
{
  struct sc_input_subnode* sis = SH_TO_SIS(node->nd_private);
  bool was_empty = sc_packet_list_is_empty(&sis->sh.sh_backlog);
  sc_packet_list_append_list(&sis->sh.sh_backlog, pl);
  if( was_empty )
    sc_subnode_helper_handle_backlog(sis, false);
  sis->stats->backlog_len = sis->sh.sh_backlog.num_pkts;
}


static void sc_subnode_helper_end_of_stream(struct sc_node* node)
{
  struct sc_input_subnode* sis = SH_TO_SIS(node->nd_private);
  sis->eos_seen = true;
  if( sc_packet_list_is_empty(&sis->sh.sh_backlog) ) {
    assert( ! sc_callback_is_active(sis->pool_cb) );
    assert( ! sc_callback_is_active(sis->timer_cb) );
    sc_subnode_helper_propagate_end_of_stream(sis);
  }
}


static int sc_subnode_helper_prep(struct sc_node* node,
                                   const struct sc_node_link*const* links,
                                   int n_links)
{
  struct sc_input_subnode* sis = SH_TO_SIS(node->nd_private);
  if( sis->with_free_link == 1 || (sis->with_free_link == 2 && n_links == 0) )
    sis->sh.sh_free_link = sc_node_prep_get_link_or_free(node, NULL);
  int n = (n_links) ? n_links : (sis->sh.sh_free_link != 0);
  if( n ) {
    sis->sh.sh_links = sc_thread_calloc(sc_node_get_thread(node),
                                        n * sizeof(sis->sh.sh_links[0]));
    SC_TEST( sis->sh.sh_links != NULL );
    if( n_links ) {
      int i;
      for( i = 0; i < n_links; ++i )
        sis->sh.sh_links[i] = links[i];
    }
    else {
      /* For convenience we put a copy of the free link in sh_links[0], so
       * that users don't have to think about whether any links have been
       * added to this node (unless they've set with_free_link=0).
       */
      sis->sh.sh_links[0] = sis->sh.sh_free_link;
    }
  }
  sis->sh.sh_n_links = n_links;

  if( sis->pool_attr != NULL )
    if( sc_node_prep_get_pool(&sis->sh.sh_pool, sis->pool_attr, node, NULL,
                              0) < 0 )
      return -1;
  return 0;
}


static struct sc_node_type* nt_with_pkts;
static struct sc_node_type* nt_without_pkts;


static struct sc_node* sc_subnode_helper_select_subnode(struct sc_node* node,
                                                        const char* name,
                                                        char** new_name_out)
{
  node->nd_type = nt_with_pkts;
  return node;
}


static int sc_subnode_helper_init(struct sc_node* node,
                                      const struct sc_attr* attr,
                                      const struct sc_node_factory* factory)
{
  if( nt_with_pkts == NULL ) {
    SC_TRY(sc_node_type_alloc(&nt_with_pkts, NULL, factory));
    nt_with_pkts->nt_pkts_fn = sc_subnode_helper_pkts;
    nt_with_pkts->nt_prep_fn = sc_subnode_helper_prep;
    nt_with_pkts->nt_end_of_stream_fn = sc_subnode_helper_end_of_stream;
    nt_with_pkts->nt_select_subnode_fn = sc_subnode_helper_select_subnode;
  }
  if( nt_without_pkts == NULL ) {
    SC_TRY(sc_node_type_alloc(&nt_without_pkts, NULL, factory));
    nt_without_pkts->nt_prep_fn = sc_subnode_helper_prep;
    nt_without_pkts->nt_select_subnode_fn = sc_subnode_helper_select_subnode;
  }

  /* Assume we won't be receiving packets.  We update the type in the
   * select_subnode callback if any incoming links are added.
   */
  node->nd_type = nt_without_pkts;

  int with_pool;
  if( sc_node_init_get_arg_int(&with_pool, node, "with_pool", 0) < 0 )
    return -1;
  int with_free_link;
  if( sc_node_init_get_arg_int(&with_free_link, node, "with_free_link", 1) < 0 )
    return -1;

  struct sc_thread* thread = sc_node_get_thread(node);
  struct sc_input_subnode* sis = sc_thread_calloc(thread, sizeof(*sis));
  sis->sh.sh_node = node;
  node->nd_private = &sis->sh;

  if( with_pool ) {
    sis->pool_attr = sc_attr_dup(attr);
    sis->pool_attr->private_pool = 1;
  }
  sis->with_free_link = with_free_link;

  sc_packet_list_init(&sis->sh.sh_backlog);
  SC_TRY( sc_callback_alloc(&sis->timer_cb, attr, thread) );
  sis->timer_cb->cb_private = sis;
  sis->timer_cb->cb_handler_fn = sc_subnode_helper_timeout;
  SC_TRY( sc_callback_alloc(&sis->pool_cb, attr, thread) );
  sis->pool_cb->cb_private = sis;
  sis->pool_cb->cb_handler_fn = sc_subnode_helper_pool_cb;
  sc_subnode_helper_stats_declare(sc_thread_get_session(thread));
  sc_node_export_state(node, "sc_subnode_helper_stats",
                       sizeof(struct sc_subnode_helper_stats), &sis->stats);
  return 0;
}


const struct sc_node_factory sc_subnode_helper_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_subnode_helper",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_subnode_helper_init,
};

/** \endcond NODOC */
