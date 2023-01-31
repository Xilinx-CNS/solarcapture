/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \node{sc_repeater}
 *
 * \brief Replay packets in a loop.
 *
 * \nodedetails
 * This node plays its input to its output multiple times.  In all cases
 * the input is buffered until the end-of-stream indication is seen, and
 * then replaying to the output starts.
 *
 * After the first play-out the packet timestamps are adjusted by a
 * constant amount each time around so that the timestamp of the first
 * packet comes after the previous.  (This ensures that timestamps on the
 * output are monotonically increasing, provided that the timestamps in the
 * input are also monotonically increasing).
 *
 * If the node has an incoming link named "recycle" then it is expected
 * that this link receives packets from the output.  In this mode the input
 * is forwarded to the output without any copying.  Otherwise the input is
 * buffered and copied to the output.
 *
 * \nodeargs
 * Argument      | Optional? | Default  | Type           | Description
 * ------------- | --------- | -------- | -------------- | -------------------------------------------------------------------------------------------------------
 * n_repeats     | Yes       | infinite | ::SC_PARAM_INT | Number of times to repeat the input to output
 *
 * \cond NODOC
 */
#include <sc_internal.h>
#include <sc_internal/builtin_nodes.h>

#include <stdio.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <math.h>
#include <inttypes.h>


struct sc_repeater_recycle;


struct sc_repeater {
  struct sc_node*            node;
  struct sc_attr*            attr;
  const struct sc_node_link* next_hop;
  struct sc_pool*            pool;
  struct sc_callback*        pool_cb;
  struct sc_repeater_recycle*recycle;
  struct timespec*           timestamps;
  struct timespec            delta;

  int                        go;
  int                        n_sent;
  struct sc_packet_list      templates;

  /* Repeat only n number of times */
  int64_t                    n_repeats;
  uint64_t                   n_total_pkts;
  uint64_t                   n_curr_pkt;
};


struct sc_repeater_recycle {
  struct sc_node*            node;
  struct sc_repeater*        repeater;
  struct sc_callback*        callback;

  struct sc_packet_list      packets;
};


static const struct sc_node_factory sc_repeater_recycle_sc_node_factory;


static void sc_repeater_buffers_available(struct sc_callback* cb,
                                          void* event_info)
{
  struct sc_repeater* rptr = cb->cb_private;
  struct sc_packet* orig;
  struct sc_packet* copy;

  while( 1 ) {
    orig = rptr->templates.head;
    if( (copy = sc_pool_duplicate_packet(rptr->pool, orig, INT_MAX)) != NULL ) {
      rptr->n_curr_pkt++;
      copy->ts_sec = 0;
      copy->ts_nsec = 0;
      sc_forward(rptr->node, rptr->next_hop, copy);
      sc_packet_list_pop_head(&rptr->templates);
      sc_packet_list_append(&rptr->templates, orig);
      orig->ts_sec += rptr->delta.tv_sec;
      if( (orig->ts_nsec += rptr->delta.tv_nsec) >= 1000000000 ) {
        orig->ts_sec += 1;
        orig->ts_nsec -= 1000000000;
      }
      if( rptr->n_repeats > 0 && rptr->n_curr_pkt == rptr->n_total_pkts ) {
        sc_node_link_end_of_stream(rptr->node, rptr->next_hop);
        return;
      }
    }
    else
      break;
  }
  sc_pool_on_threshold(rptr->pool, rptr->pool_cb, orig->frags_n + 1);
}


static void sc_repeater_save_timestamps(struct sc_repeater* rptr)
{
  struct sc_packet* next;
  struct sc_packet* pkt;
  int i = 0;

  rptr->timestamps =
    malloc(rptr->templates.num_pkts * sizeof(rptr->timestamps[0]));
  SC_TEST(rptr->timestamps != NULL);

  for( next = rptr->templates.head;
       (pkt = next) && ((next = next->next), 1); ) {
    rptr->timestamps[i].tv_sec = pkt->ts_sec;
    rptr->timestamps[i].tv_nsec = pkt->ts_nsec;
    ++i;
  }
}


static void sc_repeater_go(struct sc_repeater* rptr)
{
  struct sc_packet* first = rptr->templates.head;
  struct sc_packet* last = sc_packet_list_tail(&rptr->templates);
  long double delta;

  /* We want to increase the timestamps each time around the loop, so here
   * we calculate how much to increase by.  The non-obvious bit is how much
   * gap to put between the last and the first when cycling round.  We
   * calculate the average rate, and put a gap that preserves that average.
   */
  if( last->ts_nsec >= first->ts_nsec ) {
    delta = last->ts_sec - first->ts_sec;
    delta += (last->ts_nsec - first->ts_nsec) * 1e-9L;
  }
  else {
    delta = last->ts_sec - first->ts_sec - 1;
    delta += (last->ts_nsec + 1000000000 - first->ts_nsec) * 1e-9L;
  }
  if( delta > 0.0L ) {
    delta += delta / (rptr->templates.num_pkts - 1);
    long double secs = floorl(delta);
    rptr->delta.tv_sec = (time_t) secs;
    rptr->delta.tv_nsec = floorl((delta - secs) * 1e9L);
  }
  else {
    rptr->delta.tv_sec = 0;
    rptr->delta.tv_nsec = 0;
  }

  rptr->n_total_pkts = rptr->templates.num_pkts * rptr->n_repeats;
  if( rptr->recycle != NULL ) {
    sc_repeater_save_timestamps(rptr);
    sc_forward_list(rptr->node, rptr->next_hop, &rptr->templates);
    rptr->n_curr_pkt = rptr->templates.num_pkts;
  }
  else {
    sc_pool_on_threshold(rptr->pool, rptr->pool_cb, 1);
  }
}


static void sc_repeater_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct sc_repeater* rptr = node->nd_private;
  SC_TEST(rptr->go == 0);
  sc_packet_list_append_list(&rptr->templates, pl);
}


static void sc_repeater_end_of_stream(struct sc_node* node)
{
  struct sc_repeater* rptr = node->nd_private;
  if( rptr->go == 0 ) {
    rptr->go = 1;
    if( ! sc_packet_list_is_empty(&rptr->templates) &&
        rptr->n_repeats != 0 )
      sc_repeater_go(rptr);
    else
      sc_node_link_end_of_stream(node, rptr->next_hop);
  }
}


static int sc_repeater_prep(struct sc_node* node,
                            const struct sc_node_link*const* links, int n_links)
{
  struct sc_repeater* rptr = node->nd_private;
  if( (rptr->next_hop = sc_node_prep_get_link(node, "")) == NULL )
    return sc_node_set_error(node, EINVAL,
                             "sc_repeater: ERROR: no next hop\n");
  if( sc_node_prep_check_links(node) < 0 )
    return -1;
  if( rptr->recycle == NULL ) {
    int rc = sc_node_prep_get_pool(&rptr->pool, rptr->attr, node,
                                   &rptr->next_hop, 1);
    if( rc < 0 )
      return sc_node_fwd_error(node, rc);
    sc_node_prep_does_not_forward(node);
  }
  return 0;
}


static struct sc_node* sc_repeater_select_subnode(struct sc_node* node,
                                                  const char* name,
                                                  char** new_name_out)
{
  struct sc_repeater* rptr = node->nd_private;
  if( name != NULL && name[0] != '\0' ) {
    if( strcmp(name, "recycle") ) {
      sc_node_set_error(node, EINVAL, "sc_repeater: ERROR: bad incoming link "
                        "name '%s'\n", name);
      return NULL;
    }
    if( rptr->recycle == NULL ) {
      int rc = sc_node_alloc(&node, rptr->attr, sc_node_get_thread(node),
                             &sc_repeater_recycle_sc_node_factory, NULL, 0);
      if( rc < 0 ) {
        sc_node_fwd_error(node, rc);
        return NULL;
      }
      struct sc_repeater_recycle* re = node->nd_private;
      re->repeater = rptr;
      rptr->recycle = re;
    }
    node = rptr->recycle->node;
  }
  return node;
}


static int sc_repeater_init(struct sc_node* node, const struct sc_attr* attr,
                            const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    SC_TRY(sc_node_type_alloc(&nt, NULL, factory));
    nt->nt_pkts_fn = sc_repeater_pkts;
    nt->nt_prep_fn = sc_repeater_prep;
    nt->nt_select_subnode_fn = sc_repeater_select_subnode;
    nt->nt_end_of_stream_fn = sc_repeater_end_of_stream;
  }
  node->nd_type = nt;

  struct sc_repeater* rptr;
  rptr = sc_thread_calloc(sc_node_get_thread(node), sizeof(*rptr));
  rptr->node = node;
  node->nd_private = rptr;
  SC_TEST(sc_callback_alloc(&rptr->pool_cb, attr,
                            sc_node_get_thread(node)) == 0);
  rptr->pool_cb->cb_private = rptr;
  rptr->pool_cb->cb_handler_fn = sc_repeater_buffers_available;
  sc_packet_list_init(&rptr->templates);
  rptr->attr = sc_attr_dup(attr);
  SC_TRY(sc_attr_set_int(rptr->attr, "private_pool", 1));

  /* Get arguments */
  if( sc_node_init_get_arg_int64(&rptr->n_repeats, node, "n_repeats", -1) < 0 )
    return -1;

  return 0;
}


const struct sc_node_factory sc_repeater_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_repeater",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_repeater_init,
};


/**********************************************************************
 * sc_repeater_recycle
 */

static void sc_repeater_recycle_callback(struct sc_callback* cb,
                                         void* event_info)
{
  struct sc_repeater_recycle* re = cb->cb_private;
  struct sc_repeater* rptr = re->repeater;
  struct sc_packet* pkt;

  /* Stop if already sent enough packets */
  if( rptr->n_curr_pkt == rptr->n_total_pkts ) {
    sc_node_link_end_of_stream(rptr->node, rptr->next_hop);
    return;
  }

  pkt = re->packets.head;
  while( pkt != NULL ) {
    struct timespec* ts = &(rptr->timestamps[rptr->n_sent]);
    if( ++(rptr->n_sent) == rptr->templates.num_pkts )
      rptr->n_sent = 0;
    ts->tv_sec += rptr->delta.tv_sec;
    if( (ts->tv_nsec += rptr->delta.tv_nsec) >= 1000000000 ) {
      ts->tv_sec += 1;
      ts->tv_nsec -= 1000000000;
    }
    pkt->ts_sec = ts->tv_sec;
    pkt->ts_nsec = ts->tv_nsec;
    pkt = pkt->next;
  }

  /* Stop after n repeats */
  if( rptr->n_repeats > 0 ) {
    if( rptr->n_curr_pkt + re->packets.num_pkts >= rptr->n_total_pkts ) {
      /* Send up to the repeat count */
      uint64_t i;
      uint64_t num_pkts = re->packets.num_pkts;
      for( i = 0; i < rptr->n_total_pkts - rptr->n_curr_pkt; i++ )
        sc_forward(rptr->node, rptr->next_hop, sc_packet_list_pop_head(&(re->packets)));
      sc_node_link_end_of_stream(rptr->node, rptr->next_hop);
      rptr->n_curr_pkt += num_pkts;
      return;
    }

    rptr->n_curr_pkt += re->packets.num_pkts;
  }
  sc_forward_list(rptr->node, rptr->next_hop, &(re->packets));
  __sc_packet_list_init(&(re->packets));
}


static void sc_repeater_recycle_pkts(struct sc_node* node,
                                     struct sc_packet_list* pl)
{
  /* We don't forward the packets here because doing so can put the thread
   * into a tight loop forwarding packets between nodes.
   */
  struct sc_repeater_recycle* re = node->nd_private;
  sc_packet_list_append_list(&(re->packets), pl);
  sc_callback_at_safe_time(re->callback);
}


static int sc_repeater_recycle_prep(struct sc_node* node,
                                    const struct sc_node_link*const* links,
                                    int n_links)
{
  return sc_node_prep_check_links(node);
}


static int sc_repeater_recycle_init(struct sc_node* node,
                                    const struct sc_attr* attr,
                                    const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_pkts_fn = sc_repeater_recycle_pkts;
    nt->nt_prep_fn = sc_repeater_recycle_prep;
  }
  node->nd_type = nt;

  struct sc_thread* thread = sc_node_get_thread(node);
  struct sc_repeater_recycle* re = sc_thread_calloc(thread, sizeof(*re));
  node->nd_private = re;
  re->node = node;
  SC_TRY( sc_callback_alloc(&(re->callback), attr, thread) );
  re->callback->cb_private = re;
  re->callback->cb_handler_fn = sc_repeater_recycle_callback;
  __sc_packet_list_init(&(re->packets));
  return 0;
}


static const struct sc_node_factory sc_repeater_recycle_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_repeater_recycle",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_repeater_recycle_init,
};
/** \endcond NODOC */
