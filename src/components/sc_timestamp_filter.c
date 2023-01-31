/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \node{sc_timestamp_filter}
 *
 * \brief Filter packets, accepting only those in a given range of
 * timestamps.
 *
 * \nodedetails

 * The range can be specified either as a start and end timestamp given in
 * seconds since 1970, or as a time range given as a string.
 *
 * \nodeargs
 * Argument      | Optional? | Default | Type           | Description
 * ------------- | --------- | ------- | -------------- | -------------------------------------------------------------------------------------------------------
 * start_time    | Yes       | -1.0    | ::SC_PARAM_DBL | Start of time range to accept (seconds since 1970).
 * end_time      | Yes       | -1.0    | ::SC_PARAM_DBL | End of time range to accept (seconds since 1970).
 * range         | Yes       | NULL    | ::SC_PARAM_STR | Time range over which packets are accepted.
 *
 * The `range` argugment takes the form `START-END`, where either `START`
 * or `END` may be omitted.  `START` and `END` should take one of the
 * following forms:
 *
 *   Format                | Description
 *   ----------------------|-----------------------------------------------------------
 *   X.Y[smh]              | Time in seconds since first packet in input file
 *   +X.Y[smh]             | Time in seconds since start of time range (END only)
 *   HH:MM:SS              | Time of day
 *   YYYY/MM/DD HH:MM:SS   | Absolute time and date
 *
 * When a time is given without a date, then the date is the date of the
 * start of the range (if given) or otherwise the date of thet first packet
 * in the input.
 *
 * \nodestatscopy{sc_filter}
 *
 * \cond NODOC
 */
/* This is needed for strptime(). */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#include <sc_internal.h>

#include <errno.h>
#include <stdbool.h>
#include <float.h>

#define SC_TYPE_TEMPLATE <sc_filter_types_tmpl.h>
#define SC_DECLARE_TYPES sc_timestamp_filter_stats_declare
#include <solar_capture/declare_types.h>


enum tf_ts_type {
  TS_OPEN,
  TS_DATETIME,
  TS_TIME,
  TS_SECONDS,
  TS_DELTA,
};


struct tf_ts {
  enum tf_ts_type type;
  double seconds; /* TS_SECONDS or TS_DELTA */
  struct tm date; /* TS_DATETIME or TS_TIME */
};


enum tf_state {
  TF_FILTERING,
  TF_FIRST_PKT,
  TF_EOS,
};


struct sc_tf {
  struct sc_node*            node;
  struct sc_filter_stats*    stats;
  bool                       abs_times;
  bool                       ooo_timestamps;
  bool                       use_todays_date;
  enum tf_state              state;
  struct tf_ts               start_ts;
  struct tf_ts               end_ts;
  double                     start_time;
  double                     end_time;

  const struct sc_node_link* accept_hop;
  const struct sc_node_link* reject_hop;
};


static void populate_date(struct tf_ts* ts, struct tm* source)
{
  ts->date.tm_mday = source->tm_mday;
  ts->date.tm_mon = source->tm_mon;
  ts->date.tm_year = source->tm_year;
  ts->type = TS_DATETIME;
}


static void init_times(struct sc_tf* tf, struct sc_packet* pkt)
{
  struct tm date_to_populate;
  time_t secs;
  if( tf->use_todays_date)
    time(&secs);
  else
    secs = pkt->ts_sec;
  localtime_r(&secs, &date_to_populate);

  /* If user specifies time without date, poulate it from */
  /* first packet or or today's date */
  if( tf->start_ts.type == TS_TIME )
    populate_date(&tf->start_ts, &date_to_populate);
  else if( tf->start_ts.type == TS_OPEN && tf->end_ts.type == TS_TIME )
    populate_date(&tf->end_ts, &date_to_populate);


  /* Convert start timespec into seconds-since-epoch */
  if( tf->start_ts.type == TS_DATETIME ) {
    tf->start_time = mktime(&tf->start_ts.date);
    if( tf->end_ts.type == TS_TIME ) /* Assume end time is same date as start */
      populate_date(&tf->end_ts, &tf->start_ts.date);
    else if( tf->end_ts.type == TS_DELTA )
      tf->end_time = tf->start_time + tf->end_ts.seconds;
  }
  else if( tf->start_ts.type == TS_SECONDS ) {
    tf->start_time = tf->start_ts.seconds;
    if( tf->end_ts.type == TS_DELTA )
      tf->end_time = tf->start_ts.seconds + tf->end_ts.seconds;
  }
  else /* tf->start_ts.type == TS_OPEN */
    tf->start_time = -1.0L;


  /* Convert end timespec into seconds-since-epoch */
  if( tf->end_ts.type == TS_DATETIME )
    tf->end_time = mktime(&tf->end_ts.date);
  else if( tf->end_ts.type == TS_SECONDS )
    tf->end_time = tf->end_ts.seconds;
  else if( tf->end_ts.type == TS_OPEN )
    tf->end_time = DBL_MAX;


  /* In non-absolute mode, offset start/end times by first packet's timestamp */
  if( !tf->abs_times ) {
    double first_time = pkt->ts_sec + pkt->ts_nsec * 1e-9L;
    if( tf->start_ts.type != TS_OPEN )
      tf->start_time += first_time;
    if( tf->end_ts.type != TS_OPEN )
      tf->end_time += first_time;
  }
  tf->state = TF_FILTERING;
}


static inline bool accept_pkt(struct sc_tf* tf, struct sc_packet* pkt)
{
  double ts = pkt->ts_sec + pkt->ts_nsec * 1e-9L;

  if( ts <= tf->end_time )
    return ts >= tf->start_time;

  if( tf->state != TF_EOS && !tf->ooo_timestamps ) {
    sc_node_link_end_of_stream(tf->node, tf->accept_hop);
    tf->state = TF_EOS;
  }
  return false;
}


static void sc_tf_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct sc_tf* tf = node->nd_private;
  struct sc_packet* pkt;

  if( tf->state != TF_FILTERING ) {
    if( tf->state == TF_EOS ) {
      tf->stats->pkts_rejected += pl->num_pkts;
      sc_forward_list(tf->node, tf->reject_hop, pl);
      return;
    }
    init_times(tf, pl->head);
  }

  while( !sc_packet_list_is_empty(pl) ) {
    pkt = sc_packet_list_pop_head(pl);
    if( accept_pkt(tf, pkt) ) {
      sc_forward(tf->node, tf->accept_hop, pkt);
    }
    else {
      ++tf->stats->pkts_rejected;
      sc_forward(tf->node, tf->reject_hop, pkt);
    }
  }
}


static void sc_tf_end_of_stream(struct sc_node* node)
{
  struct sc_tf* tf = node->nd_private;
  sc_node_link_end_of_stream(tf->node, tf->accept_hop);
  sc_node_link_end_of_stream(tf->node, tf->reject_hop);
}


static int sc_tf_prep(struct sc_node* node,
                      const struct sc_node_link*const* links,
                      int n_links)
{
  struct sc_tf* tf = node->nd_private;
  tf->accept_hop = sc_node_prep_get_link_or_free(node, "");
  tf->reject_hop = sc_node_prep_get_link_or_free(node, "reject");
  return sc_node_prep_check_links(node);
}


struct date_fmt {
  const char* fmt;
  enum tf_ts_type type;
};


static const struct date_fmt fmts[] = {
  {"%Y/%m/%d %H:%M:%S",       TS_DATETIME},
  {"%Y-%m-%d %H:%M:%S",       TS_DATETIME},
  {"%H:%M:%S",                TS_TIME},
  {NULL,                      TS_OPEN},
};


static const char* parse_date(const char* buf, char sep, struct tf_ts* ts)
{
  const char* ret;
  int i;
  for(i = 0; fmts[i].fmt != NULL; ++i) {
    ret = strptime(buf, fmts[i].fmt, &ts->date);
    if( ret != NULL && *ret == sep ) {
      ts->date.tm_isdst = -1; /* autodetect */
      ts->type = fmts[i].type;
      return ret;
    }
  }
  return NULL;
}

static int handle_unit(char unit, double* value)
{
  int rc = 0;
  switch( unit ) {
  case 'h':
    *value *= 60.0;
  case 'm':
    *value *= 60.0;
  case 's':
    break;
  default:
    rc = 1;
  }
  return rc;
}

static const char* parse_seconds(const char* buf, char sep, struct tf_ts* ts)
{
  char unit, dummy;
  int n_bytes;
  int n = (sep == 0) ? 2 : 3;
  if( sscanf(buf, "+%lf%c%n%c", &ts->seconds, &unit, &n_bytes, &dummy) == n &&
      (sep == 0 || sep == dummy) ) {
    if( handle_unit(unit, &ts->seconds) != 0 )
      return NULL;
    ts->type = TS_DELTA;
    return buf + n_bytes;
  }
  if( sscanf(buf, "%lf%c%n%c", &ts->seconds, &unit, &n_bytes, &dummy) == n &&
      (sep == 0 || sep == dummy) ) {
    if( handle_unit(unit, &ts->seconds) != 0 )
      return NULL;
    ts->type = TS_SECONDS;
    return buf + n_bytes;
  }
  return NULL;
}


static const char* parse_ts(const char* buf, struct tf_ts* ts, char sep)
{
  const char* ret = NULL;
  memset(ts, 0, sizeof(struct tf_ts));

  if( *buf == sep ) {
    ts->type = TS_OPEN;
    ret = buf;
  }
  else if( (ret = parse_seconds(buf, sep, ts)) != NULL )
    ;
  else if( (ret = parse_date(buf, sep, ts)) != NULL )
    ;
  else
    return NULL;
  SC_TEST(*ret == sep);
  return ret;
}


static bool valid_range(struct tf_ts* start, struct tf_ts* end)
{
  if( start->type == TS_DELTA )
    return false;
  else if( start->type == TS_OPEN )
    return end->type != TS_DELTA && end->type != TS_OPEN;
  else if( end->type == TS_DELTA || end->type == TS_OPEN )
    return true;
  else if( start->type == TS_SECONDS || start->type == TS_TIME )
    return end->type == start->type;
  else /* start->type == TS_DATETIME */
    return end->type == TS_DATETIME || end->type == TS_TIME;
}


static int init_range(struct sc_node* node)
{
  struct sc_tf* tf = node->nd_private;
  const char *buf, *ret;
  double start, end;

  if( sc_node_init_get_arg_dbl(&start, node, "start_time", -1.0) < 0 ||
      sc_node_init_get_arg_dbl(&end, node, "end_time", -1.0)     < 0 ||
      sc_node_init_get_arg_str(&buf, node, "range", NULL)        < 0 )
    return -1;

  if( start >= 0 && end >= 0 ) {
    tf->start_time = start;
    tf->end_time = end;
    tf->state = TF_FILTERING;
    return 0;
  }

  if( buf == NULL )
    return sc_node_set_error(node, EINVAL, "sc_timestamp_filter: ERROR: "
                             "Missing range argument\n");

  if( (ret = parse_ts(buf, &tf->start_ts, '-')) == NULL )
    goto fail;
  if( (ret = parse_ts(ret + 1, &tf->end_ts, '\0')) == NULL )
    goto fail;
  if( !valid_range(&tf->start_ts, &tf->end_ts) )
    goto fail;

  if( tf->start_ts.type == TS_SECONDS ||
      (tf->start_ts.type == TS_OPEN && tf->end_ts.type == TS_SECONDS) )
    tf->abs_times = false;

  return 0;

 fail:
  return sc_node_set_error(node, EINVAL, "sc_timestamp_filter: ERROR: "
                             "Bad range '%s'\n", buf);
}


static int sc_tf_init(struct sc_node* node, const struct sc_attr* attr,
                      const struct sc_node_factory* factory)
{
  struct sc_thread* thread = sc_node_get_thread(node);
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_prep_fn = sc_tf_prep;
    nt->nt_pkts_fn = sc_tf_pkts;
    nt->nt_end_of_stream_fn = sc_tf_end_of_stream;
    sc_timestamp_filter_stats_declare(sc_thread_get_session(thread));
  }
  node->nd_type = nt;

  struct sc_tf* tf;
  tf = sc_thread_calloc(thread, sizeof(*tf));
  node->nd_private = tf;
  tf->node = node;
  tf->abs_times = true;
  tf->state = TF_FIRST_PKT;

  int tmp;
  if( sc_node_init_get_arg_int(&tmp, node, "out_of_order_timestamps", 0) < 0 )
    return -1;
  tf->ooo_timestamps = !!tmp;

  /* Normally when the user provides a time without date, we fill
   * in the date from the first input packet; with this flag set
   * we use today's date instead */
  if( sc_node_init_get_arg_int(&tmp, node, "use_todays_date", 0) < 0 )
    return -1;
  tf->use_todays_date = !!tmp;

  if( init_range(node) != 0 )
    return -1;

  sc_node_export_state(node, "sc_filter_stats",
                       sizeof(struct sc_filter_stats), &tf->stats);

  return 0;
}


const struct sc_node_factory sc_timestamp_filter_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_timestamp_filter",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_tf_init,
};
/** \endcond NODOC */
