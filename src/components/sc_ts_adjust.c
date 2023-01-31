/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \node{sc_ts_adjust}
 *
 * \brief Adjust packet buffer timestamps
 *
 * \nodedetails
 * This node adjusts the timestamps on the packet buffers passing through.
 * Timestamps can be adjusted by a constant offset, and inter-packet gaps
 * can also be scaled, or set to a fixed packet rate or bandwidth.
 *
 * This node is often used together with \noderef{sc_pacer} to emit packets
 * in real-time (or speeded up or slowed down).  The sc_ts_adjust node is
 * used to modify the timestamps in the input so that they give the desired
 * transmit time, and sc_pacer holds buffers up until their transmit time
 * is reached.
 *
 * Here is an example using the Python bindings that reads packets from a
 * PCAP file, and transmits them through interface eth4.  The packets are
 * transmitted at a rate of 1000 packets per second, and transmitting
 * starts 5 seconds after the process begins:
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * reader = thread.new_node('sc_reader', args=dict(filename="pkts.pcap", prefill="all-input"))
 * ts_adjust = thread.new_node('sc_ts_adjust', args=dict(start_now=1, offset=5, pps=1000))
 * pacer = thread.new_node('sc_pacer')
 * injector = thread.new_node('sc_injector', args=dict(interface="eth4"))
 * reader.connect(ts_adjust).connect(pacer).connect(injector)
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * \nodeargs
 * Argument      | Optional? | Default | Type           | Description
 * ------------- | --------- | ------- | -------------- | -------------------------------------------------------------------------------------------------------
 * start_now     | Yes       | 0       | ::SC_PARAM_INT | Make the first packet timestamp be "now"
 * start_at      | Yes       | 0.0     | ::SC_PARAM_DBL | Make the first packet timestamp be the one given by this argument (in seconds since 1970)
 * offset        | Yes       | 0.0     | ::SC_PARAM_DBL | Adjust timestamps by the given relative offset (seconds)
 * speedup       | Yes       | 1.0     | ::SC_PARAM_DBL | Adjust inter-packet gap to speed up or slow down by the given factor
 * pps           | Yes       | 0.0     | ::SC_PARAM_DBL | Adjust inter-packet gap to give fixed packet rate
 * fixed_rate    | Yes       | 0.0     | ::SC_PARAM_DBL | For backward compatibility only (same as pps)
 * bw            | Yes       | 0.0     | ::SC_PARAM_DBL | Adjust inter-packet gap to give fixed bandwidth
 *
 * NB. The fixed bandwidth mode (bw) uses the actual payload length given
 * by sc_packet_bytes() rather than the frame_len field.
 *
 * \cond NODOC
 */
/*
 * NOTE: We do not want customers to use the sc_ts_adjust_ctl node.
 *       If you add any Doxygen documentation, mark it as \internal.
 */
#include <sc_internal.h>
#include <sc_internal/builtin_nodes.h>

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>


struct sc_ts_adjust_ctl;


enum adj_mode {
  adj_adjust,
  adj_fixed_pps,
  adj_fixed_bw,
};


enum ctl_mode {
  ctl_run,
  ctl_cmd,
  ctl_stop,
};


struct sc_ts_adjust {
  struct sc_node*            node;
  const struct sc_node_link* next_hop;
  int                        start_now;
  long double                start_at;

  struct sc_packet_list      in_pl;

  enum adj_mode              mode;
  int                        first;
  int                        reset_ref;
  int                        last_pkt_bytes;
  long double                ts_pkt_ref;
  long double                ts_pkt_corrected;
  long double                ts_last_o;
  long double                ts_last_n;
  long double                slowdown;
  long double                ipg;
  long double                seconds_per_byte;

  struct sc_ts_adjust_ctl*   ctl;
  enum ctl_mode              ctl_mode;
  int                        pass_n;
  long double                pass_until;
  int                        eos_in;
  int                        eos_done;
};


struct sc_ts_adjust_ctl {
  struct sc_node*            node;
  struct sc_ts_adjust*       ts_adjust;
  const struct sc_node_link* free_hop;
  struct sc_packet_list      msg_q;
};


static const struct sc_node_factory sc_ts_adjust_ctl_sc_node_factory;


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


static void sc_ts_adjust_pkt(struct sc_ts_adjust* st, struct sc_packet* pkt)
{
  long double ts_o, ts_n;

  ts_o = pkt_ts_to_f(pkt);
  switch( st->mode ) {
  case adj_adjust:
    ts_n = st->ts_pkt_corrected + (ts_o - st->ts_pkt_ref) * st->slowdown;
    break;
  case adj_fixed_pps:
    ts_n = st->ts_last_n + st->ipg;
    break;
  case adj_fixed_bw:
    ts_n = st->ts_last_n + st->seconds_per_byte * st->last_pkt_bytes;
    break;
  default:
    SC_TEST(0);
    ts_n = 0;
    break;
  }
  pkt_ts_from_f(pkt, ts_n);
  st->ts_last_o = ts_o;
  st->ts_last_n = ts_n;
  st->last_pkt_bytes = sc_packet_bytes(pkt);
}


static void sc_ts_adjust_ctl_cmd(struct sc_ts_adjust_ctl* cn, const char* msg)
{
  struct sc_ts_adjust* st = cn->ts_adjust;
  char dummy;
  char unit[3];
  double d;

  if( (sscanf(msg, "fixedrate %lf %c", &d, &dummy) == 1) ||
      (sscanf(msg, "pps %lf %c", &d, &dummy) == 1) ) {
    if( d > 0.0 ) {
      st->mode = adj_fixed_pps;
      st->ipg = 1.0L / d;
    }
    else {
      fprintf(stderr, "sc_ts_adjust_ctl: ERROR: %s\n", msg);
    }
  }
  else if( sscanf(msg, "bw %lf %c", &d, &dummy) == 1 ) {
    if( d > 0.0 ) {
      st->mode = adj_fixed_bw;
      st->seconds_per_byte = 8.0L / d;
    }
    else {
      fprintf(stderr, "sc_ts_adjust_ctl: ERROR: %s\n", msg);
    }
  }
  else if( sscanf(msg, "speedup %lf %c", &d, &dummy) == 1 ) {
    if( d > 0.0 ) {
      st->mode = adj_adjust;
      st->slowdown = 1.0L / d;  /* to avoid division later! */
      st->reset_ref = 1;
    }
    else {
      fprintf(stderr, "sc_ts_adjust_ctl: ERROR: %s\n", msg);
    }
  }
  else if( sscanf(msg, "for %lf %2s %c", &d, unit, &dummy) == 2 &&
           sc_scale_to_seconds(unit, &d) == 0 ) {
    st->ctl_mode = ctl_run;
    st->reset_ref = 1;
    st->pass_until = d;
  }
  else if( sscanf(msg, "pause %lf %2s %c", &d, unit, &dummy) == 2 &&
           sc_scale_to_seconds(unit, &d) == 0 ) {
    st->ts_last_n += d;
  }
  else if( strcmp(msg, "stop") == 0 ) {
    st->ctl_mode = ctl_stop;
    if( ! st->eos_done ) {
      sc_node_link_end_of_stream(st->node, st->next_hop);
      st->eos_done = 1;
    }
  }
  else {
    fprintf(stderr, "sc_ts_adjust_ctl: ERROR: bad input '%s'\n", msg);
  }
}


static void sc_ts_adjust_go(struct sc_ts_adjust* st)
{
  struct sc_packet* pkt;
  struct sc_packet_list out_pl;
  __sc_packet_list_init(&out_pl);

  while( 1 ) {
    switch( st->ctl_mode ) {
    case ctl_run:
      if( sc_packet_list_is_empty(&st->in_pl) )
        goto out;
      pkt = sc_packet_list_pop_head(&st->in_pl);
      if( st->reset_ref ) {
        st->reset_ref = 0;
        st->ts_pkt_ref = st->ts_last_o;
        st->ts_pkt_corrected = st->ts_last_n;
        if( st->pass_until )
          st->pass_until += st->ts_last_n;
      }
      sc_ts_adjust_pkt(st, pkt);
      if( st->pass_until && st->ts_last_n >= st->pass_until ) {
        st->ctl_mode = ctl_cmd;
        st->pass_until = 0;
      }
      sc_forward(st->node, st->next_hop, pkt);
      break;
    case ctl_cmd:
      if( sc_packet_list_is_empty(&st->ctl->msg_q) )
        goto out;
      pkt = sc_packet_list_pop_head(&st->ctl->msg_q);
      /* Upstream node should be an sc_line_reader configured to strip
       * comments and blanks (or something with similar guarantees...)
       */
      if( pkt->frame_len ) {
        SC_TEST(pkt->iovlen == 1);
        char* str = pkt->iov[0].iov_base;
        SC_TEST(str[pkt->iov[0].iov_len - 1] == '\0');
      }
      sc_ts_adjust_ctl_cmd(st->ctl, pkt->iov[0].iov_base);
      sc_forward(st->ctl->node, st->ctl->free_hop, pkt);
      break;
    case ctl_stop:
      goto out;
    }
  }

 out:
  if( st->eos_in && sc_packet_list_is_empty(&st->in_pl) && ! st->eos_done ) {
    sc_node_link_end_of_stream(st->node, st->next_hop);
    st->eos_done = 1;
  }
}


static void sc_ts_adjust_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct sc_ts_adjust* st = node->nd_private;

  if( st->first ) {
    st->first = 0;
    st->ts_last_o = pkt_ts_to_f(pl->head);
    if( st->start_now ) {
      struct sc_thread* t = sc_node_get_thread(st->node);
      st->ts_last_n += timespec_to_f(&t->cur_time);
    }
    else if( st->start_at ) {
      st->ts_last_n = st->start_at;
    }
    else {
      st->ts_last_n += st->ts_last_o;
    }
    st->reset_ref = 1;
  }

  sc_packet_list_append_list(&st->in_pl, pl);
  sc_ts_adjust_go(st);
}


static void sc_ts_adjust_end_of_stream(struct sc_node* node)
{
  struct sc_ts_adjust* st = node->nd_private;
  SC_TEST(st->eos_in == 0);
  st->eos_in = 1;
  sc_ts_adjust_go(st);
}


static int sc_ts_adjust_prep(struct sc_node* node,
                             const struct sc_node_link*const* links,
                             int n_links)
{
  struct sc_ts_adjust* st = node->nd_private;
  st->next_hop = sc_node_prep_get_link_or_free(node, "");
  return sc_node_prep_check_links(node);
}


static struct sc_node* sc_ts_adjust_select_subnode(struct sc_node* node,
                                                   const char* name,
                                                   char** new_name_out)
{
  struct sc_ts_adjust* st = node->nd_private;
  if( name != NULL && name[0] != '\0' ) {
    if( strcmp(name, "controller") ) {
      sc_node_set_error(node, EINVAL, "sc_ts_adjust: ERROR: bad incoming link "
                        "name '%s'\n", name);
      return NULL;
    }
    if( st->ctl != NULL ) {
      sc_node_set_error(node, EINVAL,
                        "sc_ts_adjust: ERROR: only one controller allowed");
      return NULL;
    }
    struct sc_attr* attr;
    SC_TRY(sc_attr_alloc(&attr));
    int rc = sc_node_alloc(&node, attr, sc_node_get_thread(node),
                           &sc_ts_adjust_ctl_sc_node_factory, NULL, 0);
    sc_attr_free(attr);
    if( rc < 0 ) {
      sc_node_fwd_error(node, rc);
      return NULL;
    }
    struct sc_ts_adjust_ctl* cn = node->nd_private;
    cn->ts_adjust = st;
    st->ctl = cn;
    st->ctl_mode = ctl_cmd;
  }
  return node;
}


static int sc_ts_adjust_add_link(struct sc_node* from_node,
                                 const char* link_name,
                                 struct sc_node* to_node,
                                 const char* to_name_opt)
{
  struct sc_ts_adjust* st = from_node->nd_private;
  int rc;
  if( ! strcmp(link_name, "") )
    rc = sc_node_add_link(from_node, link_name, to_node, to_name_opt);
  else if( ! strcmp(link_name, "controller") )
    rc = sc_node_add_link(st->ctl->node, "", to_node, to_name_opt);
  else
    return sc_node_set_error(from_node, EINVAL, "sc_ts_adjust: ERROR: bad "
                             "link name '%s'\n", link_name);
  if( rc < 0 )
    return sc_node_fwd_error(from_node, rc);
  return 0;
}


static int sc_ts_adjust_init(struct sc_node* node, const struct sc_attr* attr,
                             const struct sc_node_factory* factory)
{
  double d;

  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_pkts_fn = sc_ts_adjust_pkts;
    nt->nt_prep_fn = sc_ts_adjust_prep;
    nt->nt_select_subnode_fn = sc_ts_adjust_select_subnode;
    nt->nt_add_link_fn = sc_ts_adjust_add_link;
    nt->nt_end_of_stream_fn = sc_ts_adjust_end_of_stream;
  }
  node->nd_type = nt;

  struct sc_ts_adjust* st;
  st = sc_thread_calloc(sc_node_get_thread(node), sizeof(*st));
  node->nd_private = st;
  st->node = node;
  st->first = 1;
  sc_packet_list_init(&st->in_pl);
  st->mode = adj_adjust;
  st->slowdown = 1.0;
  st->ts_last_n = 0.0;
  st->ctl_mode = ctl_run;
  st->pass_until = 0;
  st->pass_n = 0;
  st->last_pkt_bytes = 0;

  if( sc_node_init_get_arg_int(&st->start_now, node, "start_now", 0) < 0 )
    goto error;
  if( sc_node_init_get_arg_dbl(&d, node, "start_at", 0.0) < 0 )
    goto error;
  st->start_at = d ? d : 0.0;
  if( sc_node_init_get_arg_dbl(&d, node, "offset", 0.0) < 0 )
    goto error;
  st->ts_last_n = d;
  if( sc_node_init_get_arg_dbl(&d, node, "speedup", 1.0) < 0 )
    goto error;
  st->slowdown = 1.0L / d;  /* to avoid division later! */
  if( sc_node_init_get_arg_dbl(&d, node, "pps", 0.0) < 0 )
    goto error;
  if( d ) {
    st->mode = adj_fixed_pps;
    st->ipg = 1.0L / d;
  }
  /* For backwards compat, accept "fixed_rate" as an alias for "pps" */
  if( sc_node_init_get_arg_dbl(&d, node, "fixed_rate", 0.0) < 0 )
    goto error;
  if( d ) {
    st->mode = adj_fixed_pps;
    st->ipg = 1.0L / d;
  }
  if( sc_node_init_get_arg_dbl(&d, node, "bw", 0.0) < 0 )
    goto error;
  if( d ) {
    if( st->mode == adj_fixed_pps ) {
      sc_node_set_error(node, EINVAL, "sc_ts_adjust: ERROR: Do not specify "
                        "both pps and bw\n");
      goto error;
    }
    st->mode = adj_fixed_bw;
    st->seconds_per_byte = 8.0L / d;
  }

  return 0;

 error:
  sc_thread_mfree(sc_node_get_thread(node), st);
  return -1;
}


const struct sc_node_factory sc_ts_adjust_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_ts_adjust",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_ts_adjust_init,
};


/**********************************************************************
 * sc_ts_adjust_ctl
 */

static void sc_ts_adjust_ctl_pkts(struct sc_node* node,
                                  struct sc_packet_list* pl)
{
  struct sc_ts_adjust_ctl* cn = node->nd_private;
  sc_packet_list_append_list(&cn->msg_q, pl);
  if( cn->ts_adjust->ctl_mode == ctl_cmd )
    sc_ts_adjust_go(cn->ts_adjust);
}


static int sc_ts_adjust_ctl_prep(struct sc_node* node,
                                 const struct sc_node_link*const* links,
                                 int n_links)
{
  struct sc_ts_adjust_ctl* cn = node->nd_private;
  cn->free_hop = sc_node_prep_get_link_or_free(node, "");
  return sc_node_prep_check_links(node);
}


static int sc_ts_adjust_ctl_init(struct sc_node* node,
                                 const struct sc_attr* attr,
                                 const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_pkts_fn = sc_ts_adjust_ctl_pkts;
    nt->nt_prep_fn = sc_ts_adjust_ctl_prep;
  }
  node->nd_type = nt;

  struct sc_ts_adjust_ctl* cn;
  cn = sc_thread_calloc(sc_node_get_thread(node), sizeof(*cn));
  node->nd_private = cn;
  cn->node = node;
  sc_packet_list_init(&cn->msg_q);
  return 0;
}


static const struct sc_node_factory sc_ts_adjust_ctl_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_ts_adjust_ctl",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_ts_adjust_ctl_init,
};
/** \endcond NODOC */
