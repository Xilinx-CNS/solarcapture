/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \node{sc_rate_monitor}
 *
 * \brief Node that measures and exports packet rate and bandwidth to
 *        solar_capture_monitor.
 *
 * \nodedetails
 * This node measures and exports packet rate and bandwidth to
 * solar_capture_monitor.
 *
 * It passes packets from input to output without modification, and measures
 * packet rate and bandwidth statistics using an exponential moving average.
 *
 * The statistics can be accessed with the solar_capture_monitor tool.
 *
 * Note that the total number of packets is also available from the
 * solar_capture_monitor output in the pkts_in field, as for all nodes.
 *
 * \nodeargs
 * Argument      | Optional? | Default | Type           | Description
 * ------------- | --------- | ------- | -------------- | -------------------------------------------------------------------------------------------------------
 * alpha         | Yes       | 0.5     | ::SC_PARAM_DBL | Alpha value for the expoential moving average.  Higher values give more weight to newer samples.
 * period        | Yes       | 0.1     | ::SC_PARAM_DBL | Period in seconds over which samples are measured.
 *
 * \nodestatscopy{sc_rate_monitor}
 *
 * \cond NODOC
 */
#include <sc_internal.h>
#include <sc_internal/builtin_nodes.h>

#define SC_TYPE_TEMPLATE  <sc_rate_monitor_types_tmpl.h>
#define SC_DECLARE_TYPES  sc_rate_monitor_stats_declare
#include <solar_capture/declare_types.h>

#include <errno.h>
#include <string.h>


struct sc_rate_monitor {
  struct sc_node*               node;
  const struct sc_node_link*    next_hop;
  struct sc_callback*           timer_cb;
  struct sc_rate_monitor_stats* stats;
  double                        period;
  uint64_t                      period_ns;
  double                        alpha;

  uint64_t                      intvl_pkts;
  uint64_t                      prev_cap_bytes;
  uint64_t                      cap_bytes;
  uint64_t                      prev_link_bytes;
  uint64_t                      link_bytes;
  double                        pkt_rate;
  double                        cap_bw;
  double                        link_bw;
};


static double exp_avg(double prev_ma, double new_v, double alpha)
{
  return alpha * new_v + (1.0 - alpha) * prev_ma;
}


static void sc_rate_monitor_timeout(struct sc_callback* cb, void* event_info)
{
  struct sc_rate_monitor* st = cb->cb_private;
  double intvl_pkt_rate = st->intvl_pkts / st->period;
  double intvl_cap_bw   = (st->cap_bytes - st->prev_cap_bytes) * 8 / st->period;
  double intvl_link_bw  = (st->link_bytes - st->prev_link_bytes) *
    8 / st->period;
  st->intvl_pkts = 0;
  st->prev_cap_bytes = st->cap_bytes;
  st->prev_link_bytes = st->link_bytes;
  st->pkt_rate = exp_avg(st->pkt_rate, intvl_pkt_rate, st->alpha);
  st->cap_bw   = exp_avg(st->cap_bw,   intvl_cap_bw,   st->alpha);
  st->link_bw  = exp_avg(st->link_bw,  intvl_link_bw,  st->alpha);
  st->stats->pkt_rate = st->pkt_rate;
  st->stats->cap_bytes = st->cap_bytes;
  st->stats->cap_bw   = st->cap_bw;
  st->stats->link_bytes = st->link_bytes;
  st->stats->link_bw  = st->link_bw;
  sc_timer_push_back_ns(st->timer_cb, st->period_ns);
}


static void sc_rate_monitor_pkts(struct sc_node* node,
                                 struct sc_packet_list* pl)
{
  struct sc_rate_monitor* st = node->nd_private;
  struct sc_packet* next;
  struct sc_packet* pkt;

  st->intvl_pkts += pl->num_pkts;
  for( next = pl->head; (pkt = next) && ((next = next->next), 1); ) {
    st->link_bytes += pkt->frame_len;
    st->cap_bytes += sc_packet_bytes(pkt);
  }

  sc_forward_list(node, st->next_hop, pl);
}


static void sc_rate_monitor_end_of_stream(struct sc_node* node)
{
  struct sc_rate_monitor* st = node->nd_private;
  sc_node_link_end_of_stream(node, st->next_hop);
}


static int sc_rate_monitor_prep(struct sc_node* node,
                                const struct sc_node_link*const* links,
                                int n_links)
{
  struct sc_rate_monitor* st = node->nd_private;
  st->next_hop = sc_node_prep_get_link_or_free(node, "");
  sc_timer_expire_after_ns(st->timer_cb, st->period_ns);
  return sc_node_prep_check_links(node);
}


static int sc_rate_monitor_init(struct sc_node* node,
                                const struct sc_attr* attr,
                                const struct sc_node_factory* factory)
{
  struct sc_thread* thread = sc_node_get_thread(node);

  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_prep_fn = sc_rate_monitor_prep;
    nt->nt_pkts_fn = sc_rate_monitor_pkts;
    nt->nt_end_of_stream_fn = sc_rate_monitor_end_of_stream;
  }
  sc_rate_monitor_stats_declare(sc_thread_get_session(thread));
  node->nd_type = nt;

  struct sc_rate_monitor* st;
  st = sc_thread_calloc(thread, sizeof(*st));
  node->nd_private = st;
  st->node = node;
  SC_TRY(sc_callback_alloc(&st->timer_cb, attr, thread));
  st->timer_cb->cb_private = st;
  st->timer_cb->cb_handler_fn = sc_rate_monitor_timeout;
  if( sc_node_init_get_arg_dbl(&st->alpha, node, "alpha", 0.5) < 0 )
    goto error;
  if( sc_node_init_get_arg_dbl(&st->period, node, "period", 0.1) < 0 )
    goto error;
  st->period_ns = st->period * 1e9;
  sc_node_export_state(node, "sc_rate_monitor_stats",
                       sizeof(struct sc_rate_monitor_stats), &st->stats);
  return 0;

 error:
  sc_thread_mfree(thread, st);
  return -1;
}


const struct sc_node_factory sc_rate_monitor_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_rate_monitor",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_rate_monitor_init,
};

/** \endcond NODOC */
