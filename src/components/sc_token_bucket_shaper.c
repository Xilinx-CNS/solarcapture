/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \node{sc_token_bucket_shaper}
 *
 * \brief This node performs traffic shaping using the token bucket
 * algorithm.
 *
 * \nodedetails
 * This node performs traffic shaping using the token bucket
 * algorithm.  It can be used to limit packet rate (@p max_pps), or
 * bandwidth (@p max_bps).  It can also be used to limit a blend of packet
 * rate and bandwidth by setting @p max_bps and @p overhead.
 *
 * \nodeargs
 * Argument    | Optional? | Default | Type           | Description
 * ----------- | --------- | ------- | -------------- | ----------------------------------------------------------------------------------------------------------------------
 * max_pps     | Yes       | -       | ::SC_PARAM_DBL | Maximum packet rate in packets-per-second.
 * max_bps     | Yes       | -       | ::SC_PARAM_DBL | Maximum bandwidth in bits-per-second.
 * overhead    | Yes       | 0       | ::SC_PARAM_INT | Per packet overhead in bytes (used with @p max_bps).
 * show_config | Yes       | 0       | ::SC_PARAM_INT | When this is set to 1 the configuration is written to stderr at startup.
 *
 * \namedinputlinks
 * None
 *
 * \outputlinks
 * Link | Description
 * ---- | ------------------------------------
 *  ""  | All packets are sent down this link.
 *
 * \cond NODOC
 */

#include <sc_internal.h>
#include <sc_internal/builtin_nodes.h>

#include <errno.h>
#include <stdio.h>
#include <inttypes.h>


struct shaper_node {
  struct sc_node*            node;
  struct sc_thread*          thread;
  const struct sc_node_link* next_hop;
  struct sc_callback*        pps_cb;
  struct sc_callback*        Bps_cb;

  uint64_t                   Bps_ns;
  int64_t                    Bps_tokens_max;
  int64_t                    Bps_inc;
  int64_t                    packet_byte_overhead;

  uint64_t                   pps_ns;
  uint32_t                   pps_tokens_max;
  uint32_t                   pps_inc;

  int64_t                    Bps_tokens;
  uint32_t                   pps_tokens;
  struct sc_packet_list      backlog;
  bool                       eos;
};


static void sc_token_bucket_shaper_go(struct shaper_node* st)
{
  assert( ! sc_packet_list_is_empty(&(st->backlog)) );

  do {
    struct sc_packet* pkt = st->backlog.head;
    int64_t bytes = pkt->frame_len + st->packet_byte_overhead;
    if( st->pps_tokens == 0 || st->Bps_tokens <= 0 )
      return;
    sc_packet_list_pop_head(&(st->backlog));
    sc_forward(st->node, st->next_hop, pkt);
    st->pps_tokens -= 1;
    st->Bps_tokens -= bytes;
  } while( ! sc_packet_list_is_empty(&(st->backlog)) );

  if( st->eos )
    sc_node_link_end_of_stream(st->node, st->next_hop);
}


static void sc_token_bucket_shaper_add_pkts(struct sc_callback* cb,
                                            void* event_info)
{
  struct shaper_node* st = cb->cb_private;
  if( (st->pps_tokens += st->pps_inc) > st->pps_tokens_max )
    st->pps_tokens = st->pps_tokens_max;
  if( ! sc_packet_list_is_empty(&(st->backlog)) )
    sc_token_bucket_shaper_go(st);
  sc_timer_push_back_ns(cb, st->pps_ns);
}


static void sc_token_bucket_shaper_add_bytes(struct sc_callback* cb,
                                             void* event_info)
{
  struct shaper_node* st = cb->cb_private;
  if( (st->Bps_tokens += st->Bps_inc) > st->Bps_tokens_max )
    st->Bps_tokens = st->Bps_tokens_max;
  if( ! sc_packet_list_is_empty(&(st->backlog)) )
    sc_token_bucket_shaper_go(st);
  sc_timer_push_back_ns(cb, st->Bps_ns);
}


static void sc_token_bucket_shaper_pkts(struct sc_node* node,
                                        struct sc_packet_list* pl)
{
  struct shaper_node* st = node->nd_private;
  sc_packet_list_append_list(&st->backlog, pl);
  sc_token_bucket_shaper_go(st);
}


static void sc_token_bucket_shaper_end_of_stream(struct sc_node* node)
{
  struct shaper_node* st = node->nd_private;
  assert( st->eos == false );
  st->eos = true;
  if( sc_packet_list_is_empty(&st->backlog) )
    sc_node_link_end_of_stream(st->node, st->next_hop);
}


static int sc_token_bucket_shaper_prep(struct sc_node* node,
                                       const struct sc_node_link*const* links,
                                       int n_links)
{
  struct shaper_node* st = node->nd_private;
  st->next_hop = sc_node_prep_get_link_or_free(node, "");
  if( sc_node_prep_check_links(node) < 0 )
    return -1;
  sc_timer_expire_after_ns(st->pps_cb, st->pps_ns);
  sc_timer_expire_after_ns(st->Bps_cb, st->Bps_ns);
  return 0;
}


static int sc_token_bucket_shaper_init(struct sc_node* node,
                                       const struct sc_attr* attr,
                                       const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_pkts_fn = sc_token_bucket_shaper_pkts;
    nt->nt_prep_fn = sc_token_bucket_shaper_prep;
    nt->nt_end_of_stream_fn = sc_token_bucket_shaper_end_of_stream;
  }
  node->nd_type = nt;

  struct sc_thread* thread = sc_node_get_thread(node);

  int show_config;
  if( sc_node_init_get_arg_int(&show_config, node, "show_config", 0) < 0 )
    return -1;
  double max_pps;
  if( sc_node_init_get_arg_dbl(&max_pps, node, "max_pps", -1) < 0 )
    return -1;
  double max_bps;
  if( sc_node_init_get_arg_dbl(&max_bps, node, "max_bps", -1) < 0 )
    return -1;
  int overhead;
  if( sc_node_init_get_arg_int(&overhead, node, "overhead", 0) < 0 )
    return -1;

  uint64_t max_Bps = max_bps / 8;
  if( max_pps < 1 && max_Bps < 1 )
    return sc_node_set_error(node, EINVAL, "sc_token_bucket_shaper: ERROR: "
                             "max_pps or max_bps must be set\n");
  if( overhead && max_Bps < 1 )
    return sc_node_set_error(node, EINVAL, "sc_token_bucket_shaper: ERROR: "
                             "'overhead' arg can only be used with max_bps\n");

  struct shaper_node* st;
  st = sc_thread_calloc(thread, sizeof(*st));
  node->nd_private = st;
  st->node = node;
  st->thread = thread;
  __sc_packet_list_init(&st->backlog);
  SC_TRY( sc_callback_alloc(&st->pps_cb, attr, sc_node_get_thread(node)) );
  st->pps_cb->cb_private = st;
  st->pps_cb->cb_handler_fn = sc_token_bucket_shaper_add_pkts;
  SC_TRY( sc_callback_alloc(&st->Bps_cb, attr, sc_node_get_thread(node)) );
  st->Bps_cb->cb_private = st;
  st->Bps_cb->cb_handler_fn = sc_token_bucket_shaper_add_bytes;
  st->packet_byte_overhead = overhead;

  if( max_pps > 0 ) {
    if( (st->pps_inc = 10000 * max_pps / 1000000000) == 0 )
      st->pps_inc = 1;
    st->pps_ns = (uint64_t) st->pps_inc * 1000000000 / max_pps;
    st->pps_tokens_max = st->pps_inc;
    /* st->pps_tokens = 0; */
  }
  else {
    st->pps_inc = 1000000000;
    st->pps_ns = 1000000000;
    st->pps_tokens_max = st->pps_inc;
    st->pps_tokens = st->pps_tokens_max;
  }

  if( max_Bps > 0 ) {
    if( (st->Bps_inc = 10000 * max_Bps / 1000000000) < 60 )
      st->Bps_inc = 60;
    st->Bps_ns = st->Bps_inc * 1000000000 / max_Bps;
    st->Bps_tokens_max = st->Bps_inc;
    /* st->Bps_tokens = 0; */
  }
  else {
    st->Bps_inc = 1e12;
    st->Bps_ns = 1000000000;
    st->Bps_tokens_max = st->Bps_inc;
    st->Bps_tokens = st->Bps_tokens_max;
  }

  if( show_config ) {
    fprintf(stderr, "sc_token_bucket_shaper: pps=%u tok_max=%u inc=%u"
            " ns=%"PRIu64"\n", (unsigned) max_pps, st->pps_tokens_max,
            st->pps_inc, st->pps_ns);
    fprintf(stderr, "sc_token_bucket_shaper: Bps=%"PRIu64" tok_max=%"PRId64
            " inc=%"PRId64" ns=%"PRIu64"\n", max_Bps, st->Bps_tokens_max,
            st->Bps_inc, st->Bps_ns);
  }
  return 0;
}


const struct sc_node_factory sc_token_bucket_shaper_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_token_bucket_shaper",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_token_bucket_shaper_init,
};

/** \endcond NODOC */
