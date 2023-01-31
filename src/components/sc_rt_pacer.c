/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \node{sc_rt_pacer}
 *
 * \brief Emits packets at a variable rate determined by a control input.
 *
 * \nodedetails

 * This node is used to control packet rate in real-time under the control
 * of an interactive input.  That is, this node emits packets at a rate
 * determined by the control input, and the rate can be changed immediately
 * in response to new control inputs.
 *
 * This node expects two inputs: A control input named "controller" and a
 * data-path input named "" or NULL.  The data-path input is forwarded to
 * the output under the control of commands read from the control input.
 *
 * Each buffer on the control input should contain a single command
 * formatted as a nul terminated string.  The node is initially stopped.
 * The commands are:
 *
 * Command     | Description
 * ----------- | --------------------------------------------------------------------------------------------------
 * speedup MUL | Start forwarding with speedup (MUL > 1.0) or slow down (MUL < 1.0) relative to real-time.
 * pps PPS     | Start forwarding.  PPS gives the target packet rate in packets-per-second.
 * bw BPS      | Start forwarding with constant bandwidth BPS (in bits per second).
 * stop        | Stop forwarding now.
 * n N         | Stop forwarding after N packets.
 * pause TIME  | Pause processing of commands for give time.  TIME must have suffix "s", "ms", "us", or "ns".
 * sleep TIME  | Synonym for "pause TIME".
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
#include <inttypes.h>


struct sc_rt_pacer;
struct sc_rt_pacer_ctl;
typedef void (schedule_fn)(struct sc_rt_pacer* st);


enum mode {
  MODE_STOPPED,
  MODE_SLOWDOWN,  /* proportional speedup/slowdown */
  MODE_CBR,       /* constant bit rate (bandwidth) */
  MODE_PPS,       /* constant packets-per-sec      */
};


struct sc_rt_pacer {
  struct sc_node*            node;
  struct sc_thread*          thread;
  const struct sc_node_link* next_hop;
  struct sc_callback*        timer_cb;
  bool                       log;
  int64_t                    n_packets;

  struct sc_packet_list      pl;
  bool                       eos;
  struct sc_rt_pacer_ctl*    controller;
  enum mode                  mode;
  schedule_fn*               schedule_timer;
  long double                t_ref;
  long double                t_next;
  uint16_t                   last_frame_len;
  union {
    long double              slowdown;
    long double              pps_delta;
    long double              cbr_sec_per_byte;
  };
};


struct sc_rt_pacer_ctl {
  struct sc_node*            node;
  struct sc_rt_pacer*        pacer;
  const struct sc_node_link* free_hop;
  struct sc_callback*        timer_cb;
  struct sc_packet_list      msg_q;
  bool                       eos;
};


static const struct sc_node_factory sc_rt_pacer_ctl_sc_node_factory;
static void sc_rt_pacer_stop(struct sc_rt_pacer* st);


static inline long double timespec_to_f(const struct timespec* ts)
{
  return (long double) ts->tv_sec + ts->tv_nsec * 1e-9L;
}


static inline long double pkt_ts_to_f(const struct sc_packet* pkt)
{
  return (long double) pkt->ts_sec + pkt->ts_nsec * 1e-9L;
}


static void schedule_timer(struct sc_rt_pacer* st)
{
  struct timespec ts;
  long double secs = floorl(st->t_next);
  ts.tv_sec = (time_t) secs;
  ts.tv_nsec = floorl((st->t_next - secs) * 1e9L);
  sc_timer_expire_at(st->timer_cb, &ts);
}


static void schedule_timer_slowdown(struct sc_rt_pacer* st)
{
  long double ts_next_pkt = pkt_ts_to_f(st->pl.head);
  st->t_next += (ts_next_pkt - st->t_ref) * st->slowdown;
  st->t_ref = ts_next_pkt;
  schedule_timer(st);
}


static void schedule_timer_cbr(struct sc_rt_pacer* st)
{
  st->t_next += st->last_frame_len * st->cbr_sec_per_byte;
  st->last_frame_len = st->pl.head->frame_len;
  schedule_timer(st);
}


static inline void schedule_timer_pps(struct sc_rt_pacer* st)
{
  st->t_next += st->pps_delta;
  schedule_timer(st);
}


static inline void schedule_timer_start(struct sc_rt_pacer* st)
{
  sc_timer_expire_after_ns(st->timer_cb, 0);
}


static void sc_rt_pacer_timeout(struct sc_callback* cb,
                                void* event_info)
{
  struct sc_rt_pacer* st = cb->cb_private;
  sc_forward(st->node, st->next_hop, sc_packet_list_pop_head(&st->pl));
  if( --st->n_packets == 0 )
    sc_rt_pacer_stop(st);
  else if( ! sc_packet_list_is_empty(&st->pl) )
    st->schedule_timer(st);
  else if( st->eos )
    sc_node_link_end_of_stream(st->node, st->next_hop);
}


static void sc_rt_pacer_timeout_start(struct sc_callback* cb, void* event_info)
{
  struct sc_rt_pacer* st = cb->cb_private;
  st->timer_cb->cb_handler_fn = sc_rt_pacer_timeout;
  st->t_next = timespec_to_f(&(st->thread->cur_time));
  switch( st->mode ) {
  case MODE_SLOWDOWN:
    st->schedule_timer = schedule_timer_slowdown;
    st->t_ref = pkt_ts_to_f(st->pl.head);
    break;
  case MODE_PPS:
    st->schedule_timer = schedule_timer_pps;
    break;
  case MODE_CBR:
    st->schedule_timer = schedule_timer_cbr;
    st->last_frame_len = st->pl.head->frame_len;
    break;
  default:
    SC_TEST( 0 );
    break;
  }
  st->timer_cb->cb_handler_fn(st->timer_cb, NULL);
}


static void sc_rt_pacer_start(struct sc_rt_pacer* st)
{
  st->timer_cb->cb_handler_fn = sc_rt_pacer_timeout_start;
  st->schedule_timer = schedule_timer_start;
  if( ! sc_packet_list_is_empty(&st->pl) )
    st->schedule_timer(st);
}


static void sc_rt_pacer_stop(struct sc_rt_pacer* st)
{
  st->mode = MODE_STOPPED;
  sc_callback_remove(st->timer_cb);
}


static void sc_rt_pacer_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct sc_rt_pacer* st = node->nd_private;
  int was_empty = sc_packet_list_is_empty(&st->pl);
  sc_packet_list_append_list(&st->pl, pl);
  if( st->mode != MODE_STOPPED && was_empty )
    st->schedule_timer(st);
}


static void sc_rt_pacer_end_of_stream(struct sc_node* node)
{
  struct sc_rt_pacer* st = node->nd_private;
  SC_TEST( st->eos == false );
  st->eos = true;
  if( sc_packet_list_is_empty(&st->pl) )
    sc_node_link_end_of_stream(st->node, st->next_hop);
}


static int sc_rt_pacer_prep(struct sc_node* node,
                            const struct sc_node_link*const* links,
                            int n_links)
{
  struct sc_rt_pacer* st = node->nd_private;
  st->next_hop = sc_node_prep_get_link_or_free(node, "");
  return sc_node_prep_check_links(node);
}


static struct sc_node* sc_rt_pacer_select_subnode(struct sc_node* node,
                                                  const char* name,
                                                  char** new_name_out)
{
  struct sc_rt_pacer* st = node->nd_private;
  if( name != NULL && name[0] != '\0' ) {
    if( strcmp(name, "controller") ) {
      sc_node_set_error(node, EINVAL, "sc_rt_pacer: ERROR: bad incoming link "
                        "name '%s'\n", name);
      return NULL;
    }
    return st->controller->node;
  }
  return node;
}


static int sc_rt_pacer_add_link(struct sc_node* from_node,
                                const char* link_name,
                                struct sc_node* to_node,
                                const char* to_name_opt)
{
  struct sc_rt_pacer* st = from_node->nd_private;
  int rc;
  if( ! strcmp(link_name, "") )
    rc = sc_node_add_link(from_node, link_name, to_node, to_name_opt);
  else if( ! strcmp(link_name, "controller") )
    rc = sc_node_add_link(st->controller->node, "", to_node, to_name_opt);
  else
    return sc_node_set_error(from_node, EINVAL, "sc_rt_pacer: ERROR: bad "
                             "link name '%s'\n", link_name);
  if( rc < 0 )
    return sc_node_fwd_error(from_node, rc);
  return 0;
}


static int sc_rt_pacer_init(struct sc_node* node, const struct sc_attr* attr,
                         const struct sc_node_factory* factory)
{
  struct sc_thread* thread = sc_node_get_thread(node);

  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_pkts_fn = sc_rt_pacer_pkts;
    nt->nt_prep_fn = sc_rt_pacer_prep;
    nt->nt_select_subnode_fn = sc_rt_pacer_select_subnode;
    nt->nt_add_link_fn = sc_rt_pacer_add_link;
    nt->nt_end_of_stream_fn = sc_rt_pacer_end_of_stream;
  }
  node->nd_type = nt;

  struct sc_rt_pacer* st;
  st = sc_thread_calloc(thread, sizeof(*st));
  node->nd_private = st;
  st->node = node;
  st->thread = thread;
  __sc_packet_list_init(&st->pl);
  /* st->eos = false; */
  st->mode = MODE_STOPPED;
  st->n_packets = -1;

  struct sc_node* cnode;
  int rc = sc_node_alloc(&cnode, attr, thread,
                         &sc_rt_pacer_ctl_sc_node_factory, NULL, 0);
  if( rc < 0 )
    goto error;
  struct sc_rt_pacer_ctl* pc = cnode->nd_private;
  pc->pacer = st;
  st->controller = pc;

  SC_TRY( sc_callback_alloc(&st->timer_cb, attr, thread) );
  st->timer_cb->cb_private = st;
  /* We set the handler function when we start... */
  return 0;

 error:
  sc_thread_mfree(thread, st);
  return -1;
}


const struct sc_node_factory sc_rt_pacer_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_rt_pacer",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_rt_pacer_init,
};


/**********************************************************************
 * sc_rt_pacer_ctl
 */

static void sc_rt_pacer_ctl_msg(struct sc_rt_pacer_ctl* pc, char* msg)
{
  struct sc_rt_pacer* pacer = pc->pacer;
  char unit[3];
  char dummy;
  double d;
  uint64_t u;

  if( sscanf(msg, "speedup %lf %c", &d, &dummy) == 1 ||
      sscanf(msg, "%lf %c", &d, &dummy) == 1 ) {
    if( d != 0.0 ) {
      pacer->slowdown = 1.0 / d;
    }
    else {
      pacer->slowdown = 1.0;
    }
    if( pacer->log )
      fprintf(stderr, "sc_rt_pacer_ctl: OK: speedup %lf\n", d);
    pacer->mode = MODE_SLOWDOWN;
    sc_rt_pacer_start(pacer);
  }
  else if( sscanf(msg, "pps %lf %c", &d, &dummy) == 1 ) {
    if( pacer->log )
      fprintf(stderr, "sc_rt_pacer_ctl: OK: pps %lf\n", d);
    pacer->mode = MODE_PPS;
    pacer->pps_delta = (long double) 1.0 / d;
    sc_rt_pacer_start(pacer);
  }
  else if( sscanf(msg, "n %"PRIu64" %c", &u, &dummy) == 1 ) {
    pacer->n_packets = u;
  }
  else if( sscanf(msg, "bw %lf %c", &d, &dummy) == 1 ) {
    if( pacer->log )
      fprintf(stderr, "sc_rt_pacer_ctl: OK: bw %lf\n", d);
    pacer->mode = MODE_CBR;
    pacer->cbr_sec_per_byte = (long double) 8.0 / d;
    sc_rt_pacer_start(pacer);
  }
  else if( strcmp(msg, "stop") == 0 ) {
    sc_rt_pacer_stop(pacer);
  }
  else if( (sscanf(msg, "sleep %lf %2s %c", &d, unit, &dummy) == 2 ||
            sscanf(msg, "pause %lf %2s %c", &d, unit, &dummy) == 2) &&
           sc_scale_to_seconds(unit, &d) == 0 ) {
    sc_timer_expire_after_ns(pc->timer_cb, (int64_t) (d * 1e9));
  }
  else if( sscanf(msg, "sleep %lf %c", &d, &dummy) == 1 ||
           sscanf(msg, "pause %lf %c", &d, &dummy) == 1 ) {
    sc_timer_expire_after_ns(pc->timer_cb, (int64_t) (d * 1e9));
  }
  else {
    fprintf(stderr, "sc_rt_pacer_ctl: ERROR: bad input '%s'\n", msg);
  }
}


static void sc_rt_pacer_ctl_go(struct sc_rt_pacer_ctl* pc)
{
  while( ! sc_packet_list_is_empty(&pc->msg_q) &&
         ! sc_callback_is_active(pc->timer_cb) ) {
    struct sc_packet* pkt = sc_packet_list_pop_head(&pc->msg_q);
    /* Upstream node should be an sc_line_reader configured to strip
     * comments and blanks (or something with similar guarantees...)
     */
    if( pkt->frame_len ) {
      SC_TEST( pkt->iovlen == 1 );
      char* str = pkt->iov[0].iov_base;
      SC_TEST( str[pkt->iov[0].iov_len - 1] == '\0' );
    }
    sc_rt_pacer_ctl_msg(pc, pkt->iov[0].iov_base);
    sc_forward(pc->node, pc->free_hop, pkt);
  }

  if( pc->eos && sc_packet_list_is_empty(&pc->msg_q) &&
      ! sc_callback_is_active(pc->timer_cb) )
    sc_node_link_end_of_stream(pc->node, pc->free_hop);
}


static void sc_rt_pacer_ctl_pkts(struct sc_node* node,
                                 struct sc_packet_list* pl)
{
  struct sc_rt_pacer_ctl* pc = node->nd_private;
  sc_packet_list_append_list(&pc->msg_q, pl);
  sc_rt_pacer_ctl_go(pc);
}


static void sc_rt_pacer_ctl_end_of_stream(struct sc_node* node)
{
  struct sc_rt_pacer_ctl* pc = node->nd_private;
  SC_TEST( pc->eos == false );
  pc->eos = true;
  sc_rt_pacer_ctl_go(pc);
}


static void sc_rt_pacer_ctl_timeout(struct sc_callback* cb, void* event_info)
{
  struct sc_rt_pacer_ctl* pc = cb->cb_private;
  sc_rt_pacer_ctl_go(pc);
}


static int sc_rt_pacer_ctl_prep(struct sc_node* node,
                             const struct sc_node_link*const* links,
                             int n_links)
{
  struct sc_rt_pacer_ctl* pc = node->nd_private;
  pc->free_hop = sc_node_prep_get_link_or_free(node, "");
  return sc_node_prep_check_links(node);
}


static int sc_rt_pacer_ctl_init(struct sc_node* node,
                                const struct sc_attr* attr,
                                const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_pkts_fn = sc_rt_pacer_ctl_pkts;
    nt->nt_prep_fn = sc_rt_pacer_ctl_prep;
    nt->nt_end_of_stream_fn = sc_rt_pacer_ctl_end_of_stream;
  }
  node->nd_type = nt;

  struct sc_rt_pacer_ctl* pc;
  pc = sc_thread_calloc(sc_node_get_thread(node), sizeof(*pc));
  node->nd_private = pc;
  pc->node = node;
  sc_packet_list_init(&pc->msg_q);
  SC_TRY( sc_callback_alloc(&pc->timer_cb, attr, sc_node_get_thread(node)) );
  pc->timer_cb->cb_private = pc;
  pc->timer_cb->cb_handler_fn = sc_rt_pacer_ctl_timeout;
  /* pc->eos = false; */
  return 0;
}


static const struct sc_node_factory sc_rt_pacer_ctl_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_rt_pacer_ctl",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_rt_pacer_ctl_init,
};

/** \endcond NODOC */
