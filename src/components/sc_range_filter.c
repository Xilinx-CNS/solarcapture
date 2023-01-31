/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \node{sc_range_filter}
 *
 * \brief Node that forwards one or more ranges of packets.
 *
 * \nodedetails
 * Node that forwards one or more ranges of packets.
 *
 * Incoming packets are assigned an index starting at zero.  Packets whose
 * index lies within the ranges indicated by the "range" argument are
 * forwarded to the default output, and other packets are forwarded to the
 * "reject" output or freed.
 *
 *   * Ranges must be non-overlapping and in order.
 *   * Ranges are inclusive at both ends.
 *   * Indices are zero-based.
 *
 * \nodeargs
 * Argument         | Optional? | Default | Type           | Description
 * ---------------- | --------- | ------- | -------------- | -----------------------------------------------------------------
 * range            | No        |         | ::SC_PARAM_STR | Comma-separated list of packet ranges or indices.
 *
 * \outputlinks
 * Link        | Description
 * ----------- | ----------------------------------------------------------------
 *  ""         | Packets indicated by the "range" argument are forwarded here.
 *  "reject"   | Other packets are forwarded here.
 *
 * \nodestatscopy{sc_filter}
 *
 * \cond NODOC
 */
#define _GNU_SOURCE
#include <sc_internal.h>

#include <errno.h>
#include <stdbool.h>
#include <limits.h>
#include <inttypes.h>
#include <string.h>

#define SC_TYPE_TEMPLATE <sc_filter_types_tmpl.h>
#define SC_DECLARE_TYPES sc_range_filter_stats_declare
#include <solar_capture/declare_types.h>


enum outputs {
  REJECT = 0,
  ACCEPT = 1
};


struct rf_range {
  uint64_t   n;
  int        output_i;
  bool       eos;
};


struct sc_rf {
  struct sc_node*            node;
  struct rf_range*           ranges;
  struct sc_filter_stats*    stats;
  const struct sc_node_link* outputs[2];
  unsigned                   n_ranges;
  int                        eos_output_i;
  struct sc_callback*        callback;

  struct rf_range*           current;
};


static void sc_rf_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct sc_rf* rf = node->nd_private;

  do {
    if( pl->num_pkts < rf->current->n ) {
      rf->current->n -= pl->num_pkts;
      sc_forward_list2(rf->outputs[rf->current->output_i], pl);
      return;
    }
    struct sc_packet_list pl_fwd;
    __sc_packet_list_init(&pl_fwd);
    do {
      __sc_packet_list_append(&pl_fwd, __sc_packet_list_pop_head(pl));
    } while( --(rf->current->n) );
    __sc_forward_list2(rf->outputs[rf->current->output_i], &pl_fwd);
    if( rf->current->eos )
      sc_node_link_end_of_stream2(rf->outputs[rf->current->output_i]);
    ++(rf->current);
    assert( (rf->current - rf->ranges) < rf->n_ranges );
  } while( ! sc_packet_list_is_empty(pl) );
}


static void sc_rf_end_of_stream(struct sc_node* node)
{
  struct sc_rf* rf = node->nd_private;
  sc_node_link_end_of_stream2(rf->outputs[REJECT]);
  sc_node_link_end_of_stream2(rf->outputs[ACCEPT]);
}


static void sc_rf_early_end_of_stream(struct sc_callback* cb, void* event_info)
{
  struct sc_rf* rf = cb->cb_private;
  sc_node_link_end_of_stream2(rf->outputs[rf->eos_output_i]);
}


static int sc_rf_prep(struct sc_node* node,
                      const struct sc_node_link*const* links,
                      int n_links)
{
  struct sc_rf* rf = node->nd_private;
  rf->outputs[ACCEPT] = sc_node_prep_get_link_or_free(node, "");
  rf->outputs[REJECT] = sc_node_prep_get_link_or_free(node, "reject");
  if( sc_node_prep_check_links(node) < 0 )
    return -1;
  if( rf->eos_output_i >= 0 ) {
    struct sc_attr* attr;
    SC_TRY( sc_attr_alloc(&attr) );
    SC_TRY( sc_callback_alloc(&rf->callback, attr, sc_node_get_thread(node)) );
    sc_attr_free(attr);
    rf->callback->cb_private = rf;
    rf->callback->cb_handler_fn = sc_rf_early_end_of_stream;
    sc_timer_expire_after_ns(rf->callback, 1);
  }
  return 0;
}


static void push_range(struct sc_rf* rf, int output_i, uint64_t n)
{
  rf->ranges = realloc(rf->ranges, (rf->n_ranges + 1) * sizeof(rf->ranges[0]));
  SC_TEST( rf->ranges != NULL );
  struct rf_range* r = &(rf->ranges[rf->n_ranges++]);
  r->n = n;
  r->output_i = output_i;
  r->eos = false;
  rf->current = r;
}


static int push_accept(struct sc_rf* rf, uint64_t* next,
                      uint64_t start, uint64_t end)
{
  /* Accept packets in range [start, end).  On entry *next gives end of
   * previous accepted range (plus one) and on exit is set to the end of
   * this range (ie. end).
   */
  if( start < *next || end <= start )
    return -1;

  if( rf->current == NULL ) {
    if( start > 0 )
      push_range(rf, REJECT, start);
    push_range(rf, ACCEPT, end - start);
  }
  else if( start - *next ) {
    push_range(rf, REJECT, start - *next);
    push_range(rf, ACCEPT, end - start);
  }
  else {
    rf->current->n += end - start;
  }

  *next = end;
  return 0;
}


static int init_ranges(struct sc_rf* rf, const char* ranges)
{
  uint64_t u, end, next = 0;
  char dummy, sep;
  char* iter = NULL;  /* silly compiler! */

  rf->current = NULL;
  rf->ranges = NULL;
  rf->n_ranges = 0;

  const char* range = strtok_r(strdupa(ranges), ",", &iter);
  while( range != NULL ) {
    if( sscanf(range, "-%"PRIu64"%c", &u, &dummy) == 1 ) {
      if( push_accept(rf, &next, next, u + 1) < 0 )
        goto bad;
    }
    else if( sscanf(range, "%"PRIu64"%c%c", &u, &sep, &dummy) == 2 &&
             sep == '-' ) {
      if( push_accept(rf, &next, u, UINT64_MAX) < 0 )
        goto bad;
      if( strtok_r(NULL, ",", &iter) != NULL )
        goto bad;
      break;
    }
    else if( sscanf(range, "%"PRIu64"-%"PRIu64"%c", &u, &end, &dummy) == 2 ) {
      if( push_accept(rf, &next, u, end + 1) < 0 )
        goto bad;
    }
    else if( sscanf(range, "%"PRIu64"%c", &u, &dummy) == 1 ) {
      if( push_accept(rf, &next, u, u + 1) < 0 )
        goto bad;
    }
    else if( range[0] == '\0' ) {
      /* Empty range. */
    }
    range = strtok_r(NULL, ",", &iter);
  }

  if( rf->current == NULL ) {  /* Empty range: Reject everything. */
    push_range(rf, REJECT, UINT64_MAX);
    rf->eos_output_i = ACCEPT;
  }
  else if( rf->n_ranges == 1 && rf->current->n >= UINT64_MAX / 2 ) {
    /* Accept everything. */
    assert( rf->current->output_i == ACCEPT );
    rf->eos_output_i = REJECT;
  }
  else {
    rf->eos_output_i = -1;
  }

  if( rf->current->n < UINT64_MAX / 2 )
    push_range(rf, REJECT, UINT64_MAX);
  if( rf->n_ranges > 1 )
    rf->current[-1].eos = true;

  rf->current = rf->ranges;
  return 0;

 bad:
  return -1;
}


static int sc_rf_init(struct sc_node* node, const struct sc_attr* attr,
                      const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  struct sc_thread* thread = sc_node_get_thread(node);
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_prep_fn = sc_rf_prep;
    nt->nt_pkts_fn = sc_rf_pkts;
    nt->nt_end_of_stream_fn = sc_rf_end_of_stream;
  }
  sc_range_filter_stats_declare(sc_thread_get_session(thread));
  node->nd_type = nt;

  const char* ranges;
  if( sc_node_init_get_arg_str(&ranges, node, "range", NULL) < 0 )
    return -1;
  if( ranges == NULL )
    return sc_node_set_error(node, EINVAL, "sc_range_filter: ERROR: required "
                             "arg 'range' missing\n");
  int debug;
  if( sc_node_init_get_arg_int(&debug, node, "debug", 0) < 0 )
    return -1;

  struct sc_rf* rf;
  rf = sc_thread_calloc(thread, sizeof(*rf));
  node->nd_private = rf;
  rf->node = node;
  if( init_ranges(rf, ranges) < 0 ) {
    sc_thread_mfree(thread, rf);
    return sc_node_set_error(node, EINVAL, "sc_range_filter: ERROR: bad "
                             "range '%s'\n", ranges);
  }

  if( debug ) {
    unsigned i;
    for( i = 0; i < rf->n_ranges; ++i )
      fprintf(stderr, "sc_range_filter: %s %"PRIu64"%s\n",
              rf->ranges[i].output_i == ACCEPT ? "ACCEPT":"REJECT",
              rf->ranges[i].n, rf->ranges[i].eos ? " EOS":"");
  }

  sc_node_export_state(node, "sc_filter_stats",
                       sizeof(struct sc_filter_stats), &rf->stats);
  return 0;
}


const struct sc_node_factory sc_range_filter_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_range_filter",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_rf_init,
};

/** \endcond NODOC */
