/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#define SC_API_VER 4
#include <solar_capture.h>

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <stdint.h>
#include <inttypes.h>


struct back_pressure_state {
  struct sc_node*            node;
  const struct sc_node_link* next_hop;
  uint64_t                   period_on_ns;
  uint64_t                   period_off_ns;
  struct timespec            event_time;
  int                        active;
  struct sc_packet_list      backlog;
  struct sc_callback*        timed_cb;
};


static void increment_timespec_by_ns(struct timespec* ts, uint64_t inc_ns)
{
    ts->tv_sec  += inc_ns / 1000000000;
    ts->tv_nsec += inc_ns % 1000000000;
    if( ts->tv_nsec >= 1000000000 ) {
      ts->tv_sec += 1;
      ts->tv_nsec -= 1000000000;
    }
}


static void back_pressure_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct back_pressure_state* st = node->nd_private;
  sc_packet_list_append_list(&st->backlog, pl);
  if( st->active ) {
    sc_forward_list(st->node, st->next_hop, &st->backlog);
    sc_packet_list_init(&st->backlog);
  }
}


static void back_pressure_eos(struct sc_node* node)
{
 struct back_pressure_state* st = node->nd_private;
 sc_node_link_end_of_stream(node, st->next_hop);
}


static void back_pressure_transition(struct sc_callback* cb, void* event_info)
{
  struct back_pressure_state* st = cb->cb_private;

  if( ! sc_packet_list_is_empty(&st->backlog) )
    sc_forward_list(st->node, st->next_hop, &st->backlog);
  sc_packet_list_init(&st->backlog);

  increment_timespec_by_ns(&st->event_time, ( st->active ) ?
                           st->period_off_ns : st->period_on_ns);

  st->active = ! st->active;
  sc_timer_expire_at(cb, &st->event_time);
}


static int back_pressure_prep(struct sc_node* node,
                              const struct sc_node_link*const* links,
                              int n_links)
{
  struct back_pressure_state* st = node->nd_private;

  if( (st->next_hop = sc_node_prep_get_link(node, "")) == NULL )
    return sc_node_set_error(node, EINVAL, "back_pressure: no next hop!\n");

  st->active = 1;
  sc_thread_get_time(sc_node_get_thread(node), &st->event_time);
  increment_timespec_by_ns(&st->event_time, st->period_on_ns);
  sc_timer_expire_at(st->timed_cb, &st->event_time);

  return sc_node_prep_check_links(node);
}


static int back_pressure_init(struct sc_node* node, const struct sc_attr* attr,
                              const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_pkts_fn = back_pressure_pkts;
    nt->nt_prep_fn = back_pressure_prep;
    nt->nt_end_of_stream_fn = back_pressure_eos;
  }
  node->nd_type = nt;

  struct back_pressure_state* st;
  st = sc_thread_calloc(sc_node_get_thread(node), sizeof(*st));
  node->nd_private = st;
  st->node = node;

  int64_t period_ns;
  int     duty_cycle;
  if( sc_node_init_get_arg_int64(&period_ns, node, "period_ns", 1000000000) < 0 ||
      period_ns < 0 )
    goto error;
  if( sc_node_init_get_arg_int(&duty_cycle, node, "duty_cycle", 50) < 0 ||
      duty_cycle < 0 || duty_cycle > 100 )
    goto error;

  st->period_on_ns = period_ns * (duty_cycle / 100.0);
  st->period_off_ns = period_ns - st->period_on_ns;

  sc_packet_list_init(&st->backlog);

  if( sc_callback_alloc(&st->timed_cb, attr, sc_node_get_thread(node)) != 0 )
    goto error;

  st->timed_cb->cb_private = st;
  st->timed_cb->cb_handler_fn = back_pressure_transition;

  return 0;

 error:
  free(st);
  return -1;
}


const struct sc_node_factory sct_back_pressure_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sct_back_pressure",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = back_pressure_init,
};
