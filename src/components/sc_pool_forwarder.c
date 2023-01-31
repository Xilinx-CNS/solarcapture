/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \node{sc_pool_forwarder}
 *
 * \brief Node that forwards packets from a packet pool.
 *
 * \nodedetails
 * This node allocates a pool and forwards buffers from the pool to its
 * output link.  As buffers are recycled back to the pool, they are
 * collected by this node and forwarded on again.
 *
 * Buffers are initialised as described in sc_pool_get_packets().
 *
 * If the batch_num_pkts attribute is set it determines the minimum number
 * of buffers that this node will emit in each polling loop.  If it is not
 * set then the minimum is one quarter of the pool size (or the maximum if
 * smaller).  Exported in solar_capture_monitor as 'batch_min'.
 *
 * If the batch_max_pkts attribute is set it determines the maximum number
 * of buffers that this node will emit in each polling loop.  If it is not
 * set then the maximum is one quarter of the pool size (or the minimum if
 * larger).  Exported in solar_capture_monitor as 'batch_max'.
 *
 * \nodeargs
 * None
 *
 * \cond NODOC
 */
#include <sc_internal.h>
#include <sc_internal/builtin_nodes.h>

#include <errno.h>
#include <limits.h>


struct sc_pool_forwarder {
  struct sc_node*            node;
  struct sc_attr*            attr;
  const struct sc_node_link* next_hop;
  struct sc_callback*        pool_cb;
  struct sc_pool*            pool;
  int                        batch_min;
  int                        batch_max;
};


static void sc_pool_forwarder_pool_cb(struct sc_callback* cb, void* event_info)
{
  struct sc_pool_forwarder* st = cb->cb_private;
  struct sc_packet_list pl;
  __sc_packet_list_init(&pl);
  sc_pool_get_packets(&pl, st->pool, st->batch_min, st->batch_max);
  if( pl.num_pkts ) {
    sc_forward_list(st->node, st->next_hop, &pl);
    sc_timer_expire_after_ns(st->pool_cb, 1);
  }
  else {
    sc_pool_on_threshold(st->pool, st->pool_cb, st->batch_min);
  }
}


static void sc_pool_forwarder_pool_cb_first_time(struct sc_callback* cb,
                                                 void* event_info)
{
  struct sc_pool_forwarder* st = cb->cb_private;
  cb->cb_handler_fn = sc_pool_forwarder_pool_cb;

  struct sc_pkt_pool* pp = SC_PKT_POOL_FROM_POOL(st->pool);
  unsigned pool_n_bufs = pp->pp_stats->allocated_bufs;
  st->batch_min = st->attr->batch_num_pkts;
  if( st->batch_min <= 0 ) {
    st->batch_min = pool_n_bufs / 4;
    if( st->batch_min == 0 )
      st->batch_min = 1;
  }
  if( st->batch_min > pool_n_bufs )
    st->batch_min = pool_n_bufs;
  if( st->attr->batch_max_pkts > 0 )
    st->batch_max = st->attr->batch_max_pkts;
  else
    st->batch_max = pool_n_bufs / 4;
  if( st->batch_max < st->batch_min ) {
    if( st->attr->batch_max_pkts > 0 )
      st->batch_min = st->batch_max;
    else
      st->batch_max = st->batch_min;
  }
  sc_node_add_info_int(st->node, "batch_min", st->batch_min);
  sc_node_add_info_int(st->node, "batch_max", st->batch_max);

  sc_pool_on_threshold(st->pool, st->pool_cb, st->batch_min);
}


static int sc_pool_forwarder_prep(struct sc_node* node,
                                 const struct sc_node_link*const* links,
                                 int n_links)
{
  struct sc_pool_forwarder* st = node->nd_private;
  int rc;
  st->next_hop = sc_node_prep_get_link_or_free(node, "");
  if( (rc = sc_node_prep_check_links(node)) < 0 )
    return rc;
  rc = sc_node_prep_get_pool(&st->pool, st->attr, node, &st->next_hop, 1);
  if( rc < 0 )
    return sc_node_fwd_error(node, rc);
  sc_timer_expire_after_ns(st->pool_cb, 1);
  return 0;
}


static int sc_pool_forwarder_init(struct sc_node* node,
                                  const struct sc_attr* attr,
                                  const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_prep_fn = sc_pool_forwarder_prep;
  }
  node->nd_type = nt;

  struct sc_pool_forwarder* st;
  st = sc_thread_calloc(sc_node_get_thread(node), sizeof(*st));
  node->nd_private = st;
  st->node = node;
  st->attr = sc_attr_dup(attr);
  SC_TRY(sc_attr_set_int(st->attr, "private_pool", 1));
  SC_TEST(sc_callback_alloc(&st->pool_cb, attr, sc_node_get_thread(node)) == 0);
  st->pool_cb->cb_private = st;
  st->pool_cb->cb_handler_fn = sc_pool_forwarder_pool_cb_first_time;
  return 0;
}


const struct sc_node_factory sc_pool_forwarder_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_pool_forwarder",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_pool_forwarder_init,
};

/** \endcond NODOC */
