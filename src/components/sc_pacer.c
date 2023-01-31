/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \node{sc_pacer}
 *
 * \brief Emits packets at the time indicated by their associated timestamp.
 *
 * \nodedetails
 * This node forwards packets to the output, but only emits them once the
 * timestamp in the packet is current or in the past.  Packets are emitted
 * in FIFO order.
 *
 * \nodeargs
 * None
 *
 * \outputlinks
 * Link | Description
 * ---- | --------------------------------------------------------------
 * ""   | Input packets are forwarded to this output.
 *
 * \cond NODOC
 */

#include <sc_internal.h>
#include <sc_internal/builtin_nodes.h>

#include <math.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>


struct sc_pacer {
  struct sc_node*            node;
  struct sc_thread*          thread;
  const struct sc_node_link* next_hop;
  struct sc_callback*        timer_cb;

  struct sc_packet_list      pl;
  bool                       eos;
};


static inline long double timespec_to_f(const struct timespec* ts)
{
  return (long double) ts->tv_sec + ts->tv_nsec * 1e-9L;
}


static inline void timespec_from_f(struct timespec* ts, long double t)
{
  long double secs = floorl(t);
  ts->tv_sec = (time_t) secs;
  ts->tv_nsec = floorl((t - secs) * 1e9L);
}


static inline long double pkt_ts_to_f(const struct sc_packet* pkt)
{
  return (long double) pkt->ts_sec + pkt->ts_nsec * 1e-9L;
}


static inline void pkt_ts_from_f(struct sc_packet* pkt, long double t)
{
  long double secs = floorl(t);
  pkt->ts_sec = (uint64_t) secs;
  pkt->ts_nsec = floorl((t - secs) * 1e9L);
}


static void sc_pacer_set_timer(struct sc_pacer* st)
{
  struct sc_packet* pkt = st->pl.head;
  struct timespec ts;
  ts.tv_sec = pkt->ts_sec;
  ts.tv_nsec = pkt->ts_nsec;
  sc_timer_expire_at(st->timer_cb, &ts);
}


static void sc_pacer_timeout(struct sc_callback* cb, void* event_info)
{
  struct sc_pacer* st = cb->cb_private;
  while( 1 ) {
    sc_forward(st->node, st->next_hop, sc_packet_list_pop_head(&st->pl));
    if( sc_packet_list_is_empty(&(st->pl)) )
      break;
    if( ! sc_timespec_le(sc_packet_timespec(st->pl.head),
                         st->thread->cur_time) ) {
      sc_pacer_set_timer(st);
      return;
    }
  }
  if( st->eos )
    sc_node_link_end_of_stream(st->node, st->next_hop);
}


static void sc_pacer_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct sc_pacer* st = node->nd_private;
  int was_empty = sc_packet_list_is_empty(&st->pl);
  sc_packet_list_append_list(&st->pl, pl);
  if( was_empty )
    sc_pacer_set_timer(st);
}


static void sc_pacer_end_of_stream(struct sc_node* node)
{
  struct sc_pacer* st = node->nd_private;
  assert( st->eos == false );
  st->eos = true;
  if( sc_packet_list_is_empty(&st->pl) )
    sc_node_link_end_of_stream(st->node, st->next_hop);
}


static int sc_pacer_prep(struct sc_node* node,
                         const struct sc_node_link*const* links,
                         int n_links)
{
  struct sc_pacer* st = node->nd_private;
  st->next_hop = sc_node_prep_get_link_or_free(node, "");
  return sc_node_prep_check_links(node);
}


static int sc_pacer_init(struct sc_node* node, const struct sc_attr* attr,
                         const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_pkts_fn = sc_pacer_pkts;
    nt->nt_prep_fn = sc_pacer_prep;
    nt->nt_end_of_stream_fn = sc_pacer_end_of_stream;
  }
  node->nd_type = nt;

  struct sc_pacer* st;
  st = sc_thread_calloc(sc_node_get_thread(node), sizeof(*st));
  node->nd_private = st;
  st->node = node;
  st->thread = sc_node_get_thread(node);
  __sc_packet_list_init(&st->pl);

  SC_TRY(sc_callback_alloc(&st->timer_cb, attr, sc_node_get_thread(node)));
  st->timer_cb->cb_private = st;
  st->timer_cb->cb_handler_fn = sc_pacer_timeout;
  return 0;
}


const struct sc_node_factory sc_pacer_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_pacer",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_pacer_init,
};

/** \endcond NODOC */
