/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \node{sc_batch_limiter}
 *
 * \brief Node to limit the batch size sent to downstream nodes.
 *
 * \nodedetails
 * This node forwards packets from its input to its output, emitting at
 * most 'max_packets' in each batch.
 *
 * By default a batch of packets is emitted in each polling loop.  If
 * mode="on_idle", then packets are only emitted when the sc_thread is
 * idle (via an idle callback).
 *
 * \nodeargs
 * Argument    | Optional? | Default | Type           | Description
 * ----------- | --------- | ------- | -------------- | ---------------------------------------------------------------
 * max_packets | Yes       | 64      | ::SC_PARAM_INT | The maximum number of packets in each batch.
 * mode        | Yes       | NULL    | ::SC_PARAM_STR | Set mode="on_idle" to only emit packets when thread is idle.
 *
 * \nodestatscopy{sc_batch_limiter}
 *
 * \cond NODOC
 */
#include <sc_internal.h>
#include <sc_internal/builtin_nodes.h>

#define SC_TYPE_TEMPLATE  <sc_batch_limiter_types_tmpl.h>
#define SC_DECLARE_TYPES  sc_batch_limiter_stats_declare
#include <solar_capture/declare_types.h>

#include <math.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>


struct sc_batch_limiter {
  struct sc_node*                node;
  const struct sc_node_link*     next_hop;
  struct sc_batch_limiter_stats* stats;
  struct sc_callback*            callback;

  struct sc_packet_list          in_q;
  int                            eos;
};


static void sc_batch_limiter_callback(struct sc_callback* cb, void* event_info)
{
  struct sc_batch_limiter* st = cb->cb_private;

  assert(!sc_packet_list_is_empty(&st->in_q));
  assert(*(st->in_q.tail) == NULL);

  if( st->in_q.num_pkts <= st->stats->max_packets ) {
    sc_forward_list(st->node, st->next_hop, &st->in_q);
    __sc_packet_list_init(&st->in_q);
    if( st->eos )
      sc_node_link_end_of_stream(st->node, st->next_hop);
  }
  else {
    struct sc_packet_list pl;
    int i;
    __sc_packet_list_init(&pl);
    for( i = 0; i < st->stats->max_packets; ++i )
      __sc_packet_list_append(&pl, __sc_packet_list_pop_head(&st->in_q));
    assert( ! sc_packet_list_is_empty(&st->in_q) );
    __sc_forward_list(st->node, st->next_hop, &pl);
    if( st->stats->fwd_on_idle )
      sc_callback_on_idle(st->callback);
    else
      sc_timer_expire_after_ns(st->callback, 1);
  }
  st->stats->backlog = st->in_q.num_pkts;
}


static void sc_batch_limiter_pkts(struct sc_node* node,
                                  struct sc_packet_list* pl)
{
  struct sc_batch_limiter* st = node->nd_private;
  int was_empty = sc_packet_list_is_empty(&st->in_q);
  sc_packet_list_append_list(&st->in_q, pl);
  if( was_empty ) {
    if( st->stats->fwd_on_idle )
      sc_callback_on_idle(st->callback);
    else
      /* NB. We do not push a batch out here, because doing so can lead to a
       * double-sized batch being pushed: One batch from a callback and a
       * second on receiving new packets.
       */
      sc_timer_expire_after_ns(st->callback, 0);
  }
}


static void sc_batch_limiter_end_of_stream(struct sc_node* node)
{
  struct sc_batch_limiter* st = node->nd_private;
  SC_TEST(st->eos == 0);
  st->eos = 1;
  if( sc_packet_list_is_empty(&st->in_q) )
    sc_node_link_end_of_stream(st->node, st->next_hop);
}


static int sc_batch_limiter_prep(struct sc_node* node,
                         const struct sc_node_link*const* links,
                         int n_links)
{
  struct sc_batch_limiter* st = node->nd_private;
  st->next_hop = sc_node_prep_get_link_or_free(node, "");
  int rc = sc_node_prep_check_links(node);
  if( rc < 0 )
    return rc;
  return 0;
}


static int sc_batch_limiter_init(struct sc_node* node,
                                 const struct sc_attr* attr,
                                 const struct sc_node_factory* factory)
{
  struct sc_thread* thread = sc_node_get_thread(node);

  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_pkts_fn = sc_batch_limiter_pkts;
    nt->nt_prep_fn = sc_batch_limiter_prep;
    nt->nt_end_of_stream_fn = sc_batch_limiter_end_of_stream;
  }
  node->nd_type = nt;
  sc_batch_limiter_stats_declare(sc_thread_get_session(thread));

  struct sc_batch_limiter* st;
  st = sc_thread_calloc(thread, sizeof(*st));
  node->nd_private = st;
  st->node = node;
  __sc_packet_list_init(&st->in_q);
  /* st->eos = 0; */

  int max_packets, fwd_on_idle = 0;
  if( sc_node_init_get_arg_int(&max_packets, node, "max_packets", 64) < 0 )
    goto error;
  const char* s;
  if( sc_node_init_get_arg_str(&s, node, "mode", NULL) < 0 )
    goto error;
  if( s != NULL ) {
    if( ! strcmp(s, "on_idle") ) {
      fwd_on_idle = 1;
    }
    else {
      sc_node_set_error(node, EINVAL, "%s: ERROR: bad mode '%s'; expected one "
                        "of: on_idle\n", __func__, s);
      goto error;
    }
  }

  SC_TRY(sc_callback_alloc(&st->callback, attr, thread));
  st->callback->cb_private = st;
  st->callback->cb_handler_fn = sc_batch_limiter_callback;
  sc_node_export_state(node, "sc_batch_limiter_stats",
                       sizeof(struct sc_batch_limiter_stats), &st->stats);
  st->stats->max_packets = max_packets;
  st->stats->fwd_on_idle = fwd_on_idle;
  st->stats->backlog = 0;
  return 0;

 error:
  sc_thread_mfree(thread, st);
  return -1;
}


const struct sc_node_factory sc_batch_limiter_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_batch_limiter",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_batch_limiter_init,
};

/** \endcond NODOC */
