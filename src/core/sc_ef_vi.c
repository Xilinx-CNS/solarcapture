/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#include "internal.h"
#include <sc_internal/ef_vi.h>
#include <sc_internal/stream.h>
#include <sc_internal/builtin_nodes.h>

#include <etherfabric/packedstream.h>
#include <etherfabric/capabilities.h>

#include <net/if.h>


enum sc_ef_vi_backlog_state {
  state_on_backlog,
  state_current,
};


#define BACKLOG_BATCH (64)


#define pkt_iov0_base(pkt)  ((uint8_t*) (pkt)->sp_usr.iov[0].iov_base)
#define pkt_iov0_len(pkt)   ((pkt)->sp_usr.iov[0].iov_len)
#define pkt_iov0_end(pkt)   (pkt_iov0_base(pkt) + pkt_iov0_len(pkt))

#define psp_from_ps_pkt(ps_pkt)                         \
  ((ef_packed_stream_packet*) pkt_iov0_base(ps_pkt))

#define ps_pkt_set_on_backlog(ps_pkt, on_backlog)                       \
  do { ((ps_pkt)->sp_usr.metadata = (void*)(uintptr_t) (on_backlog)); }while(0)
#define ps_pkt_is_on_backlog(ps_pkt)  ((ps_pkt)->sp_usr.metadata != NULL)

#define ef_vi_tg(vi)  ((vi)->thread->session)

#define ef_vi_set_err(vi, errno_code, ...)                                 \
  sc_set_err((vi)->thread->session, (errno_code), __VA_ARGS__)


static void sc_ef_vi_readable(struct sc_callback* cb, void* event_info);
static void sc_ef_vi_ps_try_flush(struct sc_callback* cb, void* event_info);
static void sc_ef_vi_ps_on_ref_pool_threshold(struct sc_callback* cb,
                                              void* event_info);
static void sc_ef_vi_burst_cb(struct sc_callback* cb, void* event_info);


static inline int sc_ef_vi_rx_space(struct sc_ef_vi* vi)
{
  return vi->rx_ring_max - ef_vi_receive_fill_level(&vi->vi);
}


static inline ef_addr sc_pkt_ptr_to_dma(const struct sc_pkt* pkt,
                                        int netif_id, const void* ptr)
{
  return pkt->sp_ef_addr[netif_id] + ((uint8_t*) ptr - sc_pkt_get_buf(pkt));
}


static inline int sc_packet_ptr_is_in_this_buf(const struct sc_packet* packet,
                                               const void* ptr)
{
  struct sc_pkt* pkt = SC_PKT_FROM_PACKET(packet);
  return ((uint8_t*) ptr >= sc_pkt_get_buf(pkt) &&
          (uint8_t*) ptr < sc_pkt_get_buf_end(pkt));
}


static inline struct sc_packet* sc_packet_find_buf(struct sc_packet* pkt,
                                                   const void* ptr)
{
  if( sc_packet_ptr_is_in_this_buf(pkt, ptr) )
    return pkt;
  for( pkt = pkt->frags; pkt != NULL; pkt = pkt->next )
    if( sc_packet_ptr_is_in_this_buf(pkt, ptr) )
      return pkt;
  return NULL;
}


static int __sc_ef_vi_transmit(struct sc_ef_vi* vi, struct sc_pkt* pkt)
{
  ef_iovec efiov[pkt->sp_usr.iovlen];
  struct sc_packet* bufp;
  struct sc_pkt* buf;
  int rc, i;

  for( i = 0; i < pkt->sp_usr.iovlen; ++i ) {
    bufp = sc_packet_find_buf(&pkt->sp_usr, pkt->sp_usr.iov[i].iov_base);
    assert(bufp != NULL);
    buf = SC_PKT_FROM_PACKET(bufp);
    efiov[i].iov_base = sc_pkt_ptr_to_dma(buf, vi->netif_id,
                                          pkt->sp_usr.iov[i].iov_base);
    efiov[i].iov_len = pkt->sp_usr.iov[i].iov_len;
  }
  int rq_id = vi->tx_added & ef_vi_transmit_capacity(&vi->vi);
  rc = ef_vi_transmitv_init(&vi->vi, efiov, pkt->sp_usr.iovlen, rq_id);
  if( rc == 0 ) {
    vi->tx_pkts[rq_id] = pkt;
    ++vi->tx_added;
    return 0;
  }
  else {
    return -1;
  }
}


void sc_ef_vi_transmit_list(struct sc_ef_vi* vi,
                            struct sc_packet_list* pl,
                            struct sc_injector_node* inj)
{
  /* TODO: Optimise by hitting the doorbell just once at the end of the
   * list.
   *
   * Possibly desirable to push first one out immediately, and do single
   * doorbell for the rest.
   */
  struct sc_packet* next;
  struct sc_pkt* pkt;
  int did_something = 0;

  assert(! sc_packet_list_is_empty(pl));
  assert(! vi->vi_tx_filling ||
         ef_vi_transmit_fill_level(&vi->vi) <= vi->vi_tx_stop_filling_level);
  sc_validate_list(ef_vi_tg(vi), pl, vi->name, "");

  if( vi->vi_tx_filling ) {
    while( pl->head != NULL ) {
      pkt = SC_PKT_FROM_PACKET(pl->head);
      pkt->sp_tx.injector = inj;
      if( __sc_ef_vi_transmit(vi, pkt) == 0 ) {
        pl->head = pkt->sp_usr.next;
        --pl->num_pkts;
        /* NB. We're not bothering to track [pl->num_frags]. */
        did_something = 1;
      }
      else {
        if( did_something ) {
          ef_vi_transmit_push(&vi->vi);
          ++(vi->stats->n_tx_doorbell);
        }
        vi->vi_tx_filling = 0;
        goto queue;
      }
    }
    assert(pl->num_pkts == 0);
    assert(did_something);
    ef_vi_transmit_push(&vi->vi);
    ++(vi->stats->n_tx_doorbell);
    if( ef_vi_transmit_fill_level(&vi->vi) >= vi->vi_tx_stop_filling_level )
      vi->vi_tx_filling = 0;
    return;
  }

 queue:
  if( sc_packet_list_is_empty(&(vi->vi_tx_q)) )
    ++(vi->stats->n_tx_backlog_enter);
  for( next = pl->head;
       next && (pkt = SC_PKT_FROM_PACKET(next),1) && ((next = next->next),1); )
    pkt->sp_tx.injector = inj;
  sc_packet_list_append_list(&vi->vi_tx_q, pl);
  vi->stats->tx_backlog = vi->vi_tx_q.num_pkts;
}


static void sc_ef_vi_tx_refill(struct sc_ef_vi* vi)
{
  assert(! vi->vi_tx_filling);
  assert(ef_vi_transmit_fill_level(&vi->vi) <= vi->vi_tx_refill_level);

  if( ! sc_packet_list_is_empty(&vi->vi_tx_q) ) {
    while( vi->vi_tx_q.head != NULL ) {
      struct sc_pkt* pkt = SC_PKT_FROM_PACKET(vi->vi_tx_q.head);
      if( __sc_ef_vi_transmit(vi, pkt) == 0 ) {
        vi->vi_tx_q.head = pkt->sp_usr.next;
        --vi->vi_tx_q.num_pkts;
      }
      else {
        ef_vi_transmit_push(&vi->vi);
        ++(vi->stats->n_tx_doorbell);
        vi->stats->tx_backlog = vi->vi_tx_q.num_pkts;
        return;
      }
    }
    ef_vi_transmit_push(&vi->vi);
    ++(vi->stats->n_tx_doorbell);
    assert(vi->vi_tx_q.num_pkts == 0);
    assert(vi->vi_tx_q.head == NULL);
    vi->vi_tx_q.tail = &vi->vi_tx_q.head;
  }
  if( ef_vi_transmit_fill_level(&vi->vi) < vi->vi_tx_refill_level )
    vi->vi_tx_filling = 1;
  vi->stats->tx_backlog = 0;
}


static void sc_ef_vi_rx_refill_batch(struct sc_ef_vi* vi)
{
  int i;
  assert(vi->pkt_pool->pp_n_bufs >= vi->rx_refill_batch);
  assert(ef_vi_receive_space(&vi->vi) >= vi->rx_refill_batch);
  for( i = 0; i < vi->rx_refill_batch; ++i ) {
    struct sc_pkt* pkt = sc_pkt_pool_get(vi->pkt_pool);
    unsigned rx_id = vi->rx_added & ef_vi_receive_capacity(&vi->vi);
    vi->rx_pkts[rx_id] = pkt;
    assert(pkt->sp_pkt_pool_id == vi->pkt_pool->pp_id);
    if( ! vi->packed_stream_mode ) {
      pkt->sp_usr.iov[0].iov_base =
        sc_pkt_get_buf_inline(pkt) + vi->rx_prefix_len;
      pkt->sp_usr.iovlen = 1;
    }
    ef_vi_receive_init(&vi->vi, pkt->sp_ef_addr[vi->netif_id], rx_id);
    ++vi->rx_added;
  }
  ef_vi_receive_push(&vi->vi);
}


static int get_n_bufs_rx_min(const struct sc_attr* attr)
{
  if( attr->n_bufs_rx_min >= 0 )
    return attr->n_bufs_rx_min;
  if( attr->n_bufs_rx >= 8*1024 )
    return 8*1024;
  else
    return attr->n_bufs_rx;
}


#define TUNABLE_ERR(vi, fmt, ...)                       \
  ef_vi_set_err(vi, EINVAL, "ERROR: %s: require " fmt,  \
                __func__, __VA_ARGS__)

int __sc_ef_vi_init(struct sc_thread* thread,
                    const struct sc_attr* attr, struct sc_ef_vi* vi,
                    struct sc_netif* netif, unsigned sc_ef_vi_flags)
{
  struct sc_session* tg = thread->session;

  /* Which RX error types do we want ef_vi to report as errors?
   * Specifically we don't want to report EF_VI_DISCARD_RX_ETH_LEN_ERR or
   * EF_VI_DISCARD_RX_TOBE_DISC.  (The former primarily because it is
   * reported through the same error bit as FCS error).
   */
  unsigned ef_vi_discards = ( EF_VI_DISCARD_RX_L4_CSUM_ERR |
                              EF_VI_DISCARD_RX_L3_CSUM_ERR |
                              EF_VI_DISCARD_RX_ETH_FCS_ERR );
  SC_TRY( ef_vi_receive_set_discards(&(vi->vi), ef_vi_discards) );

  /* Always discard truncated frames.  They are painful to deal with and no
   * real benefit from treating them differently from fifo overflow drops.
   */
  unsigned discard_mask;
  discard_mask = attr->discard_mask | SC_TRUNCATED;

  vi->thread = thread;
  vi->vi_running = true;

  /* TODO: Would be better do attr bounds checking at attr init time */
  if( attr->rx_refill_batch_low < attr->rx_refill_batch_high ||
      attr->rx_refill_batch_high < 1 )
    return TUNABLE_ERR(vi, "1 <= rx_refill_batch_high(%"PRId64") <= "
                       "rx_refill_batch_low(%"PRId64")\n",
                       attr->rx_refill_batch_high, attr->rx_refill_batch_low);
  if( attr->rx_ring_low < 0 || attr->rx_ring_low > attr->rx_ring_high ||
      attr->rx_ring_high > 100 )
    return TUNABLE_ERR(vi, "0 <= rx_ring_low(%"PRId64") <= rx_ring_high(%"PRId64") <= 100\n",
                       attr->rx_ring_low, attr->rx_ring_high);
  if( attr->poll_batch < 1 )
    return TUNABLE_ERR(vi, "poll_batch(%"PRId64") >= 1\n", attr->poll_batch);
  if( attr->n_bufs_rx < 1 && attr->pool_size < 1 )
      return TUNABLE_ERR(vi, "n_bufs_rx(%"PRId64") >= 1\n", attr->n_bufs_rx);
  if( attr->n_bufs_rx_min > attr->n_bufs_rx )
    return TUNABLE_ERR(vi, "n_bufs_rx_min(%"PRId64") <= n_bufs_rx(%"PRId64")\n",
                       attr->n_bufs_rx_min, attr->n_bufs_rx);

  vi->ef_events = sc_thread_calloc(thread, attr->poll_batch * sizeof(ef_event));
  TEST(vi->ef_events);
  vi->private_pool = attr->private_pool;
  vi->poll_batch = attr->poll_batch;
  vi->netif = netif;
  vi->netif_id = netif->netif_id;
  vi->rx_prefix_len = ef_vi_receive_prefix_len(&vi->vi);
  if( ef_vi_receive_capacity(&vi->vi) < attr->rx_ring_max )
    vi->rx_ring_max = ef_vi_receive_capacity(&vi->vi);
  else
    vi->rx_ring_max = attr->rx_ring_max;
  vi->rx_refill_batch_high = attr->rx_refill_batch_high;
  vi->rx_refill_batch_low = attr->rx_refill_batch_low;
  vi->rx_refill_batch = vi->rx_refill_batch_high;
  /* vi->vi_recv_node = NULL; */
  vi->discard_mask = discard_mask;
  vi->rx_ring_low_level = vi->rx_ring_max * attr->rx_ring_low / 100;
  vi->rx_ring_high_level = vi->rx_ring_max * attr->rx_ring_high / 100;
  vi->jumbo = NULL;
  sc_packet_list_init(&vi->vi_tx_q);
  vi->vi_tx_filling = 1;
  vi->vi_tx_stop_filling_level = ef_vi_transmit_capacity(&vi->vi) * 2 / 3;
  vi->vi_tx_refill_level = ef_vi_transmit_capacity(&vi->vi) * 1 / 3;
  vi->flags = sc_ef_vi_flags;
  if( attr->active_discard )
    vi->flags |= vif_active_discard;
  vi->snap = attr->snap;
  vi->packed_stream_mode = vi->flags & vif_packed_stream;
  if( vi->packed_stream_mode ) {
    bool unpack = !! attr->unpack_packed_stream;
    if( ! unpack && vi->snap > 0 )
      return ef_vi_set_err(vi, EINVAL, "ERROR: %s: snap is not supported when "
                           "unpack_packed_stream=0\n", __func__);
    struct sc_packed_stream_vi* ps_vi;
    ps_vi = sc_thread_calloc(thread, sizeof(*ps_vi));
    vi->packed_stream_vi = ps_vi;
    ps_vi->unpack = unpack;
    /* ps_vi->current_ps_pkt = NULL; */
    SC_TRY(ef_vi_packed_stream_get_params(&(vi->vi), &(ps_vi->ps_params)));
    if( ! unpack ) {
      SC_TRY( sc_callback_alloc2(&(ps_vi->flush_cb), attr,
                                 thread, "vi_ps_flush") );
      ps_vi->flush_cb->cb_private = vi;
      ps_vi->flush_cb->cb_handler_fn = sc_ef_vi_ps_try_flush;
    }
    SC_TRY( sc_callback_alloc2(&(ps_vi->backlog_cb), attr,
                               thread, "vi_ps_backlog") );
    ps_vi->backlog_cb->cb_private = vi;
    ps_vi->backlog_cb->cb_handler_fn = sc_ef_vi_ps_on_ref_pool_threshold;
    /* ps_vi->ps_flags_mask = 0; */
    if( discard_mask & SC_CSUM_ERROR )
      ps_vi->ps_flags_mask |= EF_VI_PS_FLAG_BAD_IP_CSUM;
    if( discard_mask & SC_CRC_ERROR )
      ps_vi->ps_flags_mask |= EF_VI_PS_FLAG_BAD_FCS;
  }

  /* vi->rx_added = 0; */
  /* vi->rx_removed = 0; */
  vi->rx_pkts = sc_thread_calloc(thread,
                                 (ef_vi_receive_capacity(&vi->vi) + 1) *
                                 sizeof(vi->rx_pkts[0]));
  TEST(vi->rx_pkts);

  /* vi->tx_added = 0; */
  /* vi->tx_removed = 0; */
  vi->tx_pkts = sc_thread_calloc(thread,
                                 (ef_vi_transmit_capacity(&vi->vi) + 1) *
                                 sizeof(vi->tx_pkts[0]));
  TEST(vi->tx_pkts);

  TRY(sc_stats_add_block(thread, vi->name, "sc_vi_stats", "v", vi->id,
                         sizeof(*vi->stats), &vi->stats));

  if( attr->vi_burst_interval_ns > 0 &&
      (attr->vi_burst_pkts_threshold > 0 || attr->vi_burst_bytes_threshold > 0) ) {
    TRY(sc_stats_add_block(thread, vi->name, "sc_vi_burst_stats", "v", vi->id,
                           sizeof(*vi->burst_stats), &vi->burst_stats));
    SC_TRY( sc_callback_alloc2(&vi->burst_cb, attr, thread, "vi_burst") );
    vi->burst_interval_ns = attr->vi_burst_interval_ns;
    vi->burst_pkts_threshold = (attr->vi_burst_pkts_threshold > 0) ?
      attr->vi_burst_pkts_threshold : UINT64_MAX;
    vi->burst_bytes_threshold = (attr->vi_burst_bytes_threshold > 0) ?
      attr->vi_burst_bytes_threshold : UINT64_MAX;
    vi->burst_cb->cb_private = vi;
    vi->burst_cb->cb_handler_fn = sc_ef_vi_burst_cb;
  }
  if( attr->group_name != NULL )
    sc_stats_add_info_str(tg, "v", vi->id, "group_name", attr->group_name);
  sc_stats_add_info_str(tg, "v", vi->id, "interface", netif->name);
  sc_stats_add_info_str(tg, "v", vi->id, "real_interface",
                        netif->interface->if_name);
  vi->stats->id                    = vi->id;
  vi->stats->thread_id             = thread->id;
  vi->stats->pool_id               = -1;
  vi->stats->interface_id          = vi->netif_id;
  vi->stats->recv_node_id          = -1;
  vi->stats->rx_refill_batch_low   = vi->rx_refill_batch_low;
  vi->stats->rx_refill_batch_high  = vi->rx_refill_batch_high;
  vi->stats->poll_batch            = vi->poll_batch;
  vi->stats->evq_size              = ef_eventq_capacity(&vi->vi);
  vi->stats->tx_ring_max           = ef_vi_transmit_capacity(&vi->vi);
  vi->stats->rx_ring_max           = vi->rx_ring_max;
  vi->stats->rx_ring_size          = ef_vi_receive_capacity(&vi->vi) + 1;
  vi->stats->rx_ring_low_level     = vi->rx_ring_low_level;
  vi->stats->rx_ring_high_level    = vi->rx_ring_high_level;
  vi->stats->discard_mask          = vi->discard_mask;
  vi->stats->n_bufs_rx_req         = attr->n_bufs_rx;
  vi->stats->n_bufs_rx_min         = get_n_bufs_rx_min(attr);
  vi->stats->vi_group_id           = -1;
  vi->stats->hw_timestamps         = sc_ef_vi_flags & vif_rx_timestamps ? 1 : 0;
  vi->stats->packed_stream_mode    = vi->packed_stream_mode;
  if( vi->packed_stream_mode )
    vi->stats->packed_stream_unpack = vi->packed_stream_vi->unpack;
  vi->stats->packed_stream_pool_id = -1;
  vi->stats->packed_stream_flush_nanos = attr->batch_timeout_nanos;
  if( vi->stats->packed_stream_flush_nanos <= 0 )
    vi->stats->packed_stream_flush_nanos = 1;

  if( ! vi->packed_stream_mode &&
      SC_DMA_PKT_BUF_LEN - vi->rx_prefix_len < attr->linear_header )
    return ef_vi_set_err(vi, ENOTSUP,
                         "ERROR: VI not able to provide linear_header=%"PRId64".  "
                         "Maximum is %d\n", attr->linear_header,
                         (int) (SC_DMA_PKT_BUF_LEN - vi->rx_prefix_len));

  sc_thread_add_vi(thread, vi);

  TEST(vi->id == tg->tg_vis_n);
  tg->tg_vis_n++;
  SC_REALLOC(&tg->tg_vis, tg->tg_vis_n);
  tg->tg_vis[vi->id] = vi;

  SC_TRY( sc_callback_alloc2(&vi->readable_cb, attr, thread, "vi_readable") );
  vi->readable_cb->cb_private = vi;
  vi->readable_cb->cb_handler_fn = sc_ef_vi_readable;
  if( thread->wakeup_cb != NULL )
    sc_ef_vi_set_non_busy_wait(vi);

  return 0;
}


void sc_ef_vi_set_non_busy_wait(struct sc_ef_vi* vi)
{
  /* The ef_vi API requires that we call ef_vi_prime before doing a wait.
   * Once we're in the set we might be waited on, but if the thread is not
   * interested in waiting for a vi wake it won't necessarily call
   * sc_ef_vi_about_to_sleep to prime us, eg if using sc_epoll_timer.
   */
  SC_TRY(ef_vi_prime(&vi->vi, vi->dh, ef_eventq_current(&vi->vi)));
  vi->primed = 1;
  SC_TRY(sc_epoll_ctl(vi->thread, EPOLL_CTL_ADD, vi->dh, EPOLLIN,
                      vi->readable_cb));
}


static int sc_ef_vi_add_monitor(struct sc_ef_vi* vi, struct sc_node** to_node,
                                const char** name_opt)
{
  /* Add a sc_vi_monitor node between the VI and [to_node]. */
  struct sc_node* vim;
  struct sc_attr* attr;
  TRY(sc_attr_alloc(&attr));
  struct sc_object* vi_obj;
  TRY(sc_opaque_alloc(&vi_obj, vi));
  struct sc_arg args[] = { SC_ARG_OBJ("vi", vi_obj) };
  TRY(sc_node_alloc(&vim, attr, vi->thread, &sc_vi_monitor_sc_node_factory,
                    args, sizeof(args) / sizeof(args[0])));
  sc_opaque_free(vi_obj);
  sc_attr_free(attr);
  int rc = sc_node_add_link(vim, "", *to_node, *name_opt);
  if( rc < 0 )
    return sc_node_fwd_error(vim, rc);
  *to_node = vim;
  *name_opt = NULL;
  return 0;
}


static int sc_ef_vi_add_snap(struct sc_ef_vi* vi, struct sc_node** to_node,
                             const char** name_opt)
{
  /* Add a sc_snap node between the VI and [to_node]. */
  struct sc_node* snap;
  struct sc_attr* attr;
  TRY(sc_attr_alloc(&attr));
  struct sc_arg args[] = { SC_ARG_INT("snap", vi->snap) };
  TRY(sc_node_alloc(&snap, attr, vi->thread, &sc_snap_sc_node_factory,
                    args, sizeof(args) / sizeof(args[0])));
  sc_attr_free(attr);
  int rc = sc_node_add_link(snap, "", *to_node, *name_opt);
  if( rc < 0 )
    return sc_node_fwd_error(snap, rc);
  *to_node = snap;
  *name_opt = NULL;
  return 0;
}


int sc_ef_vi_set_recv_node(struct sc_ef_vi* vi, struct sc_node* to_node,
                           const char* name_opt, const struct sc_attr* attr)
{
  struct sc_session* tg = vi->thread->session;
  int rc, first_time = vi->vi_recv_node == NULL;

  sc_trace(tg, "%s: %s => %s/%s\n",
           __func__, vi->name, to_node->nd_name, name_opt);

  if( vi->snap > 0 )
    if( (rc = sc_ef_vi_add_snap(vi, &to_node, &name_opt)) < 0 )
      return rc;
  if( vi->flags & vif_active_discard )
    if( (rc = sc_ef_vi_add_monitor(vi, &to_node, &name_opt)) < 0 )
      return rc;

  struct sc_node_impl* to_ni = SC_NODE_IMPL_FROM_NODE(to_node);
  if( vi->thread != to_ni->ni_thread )
    to_node = sc_node_add_link_cross_thread(vi->thread, to_ni, name_opt);

  char* to_name = name_opt ? strdup(name_opt) : NULL;
  struct sc_node* node = sc_node_get_ingress_node(to_node, &to_name);
  free(to_name);
  if( node == NULL )
    return ef_vi_set_err(vi, EINVAL,
                      "ERROR: Failed to get target node '%s' from node '%s'\n",
                      name_opt, to_node->nd_name);

  vi->vi_recv_node = SC_NODE_IMPL_FROM_NODE(node);
  vi->stats->recv_node_id = vi->vi_recv_node->ni_id;
  ++(vi->vi_recv_node->ni_n_incoming_links);

  if( first_time ) {
    struct sc_attr* my_attr = sc_attr_dup(attr);
    if( vi->packed_stream_mode ) {
      struct sc_packed_stream_vi* ps_vi = vi->packed_stream_vi;
      my_attr->buf_size = ps_vi->ps_params.psp_buffer_size;
      /* TODO: my_attr->buf_align = ps_vi->ps_params.psp_buffer_align; */
      my_attr->buf_inline = 0;
      my_attr->require_huge_pages = 1;
    }
    else {
      my_attr->buf_size = -1; /* use default */
      my_attr->buf_inline = 1;
    }
    my_attr->n_bufs_tx = -1;
    sc_ef_vi_set_attr(my_attr, vi->flags, vi);
    if( my_attr->n_bufs_rx >= 0 ) {
      my_attr->pool_n_bufs = my_attr->n_bufs_rx;
      my_attr->pool_size = -1;
    }
    else {
      SC_TEST( my_attr->pool_size >= 0 );
      my_attr->pool_n_bufs = -1;
    }
    sc_thread_get_pool(vi->thread, my_attr, vi->netif, &vi->pkt_pool);
    if( attr->vi_mmap_fname )
      SC_TRY(sc_pkt_pool_set_mmap_path(vi->pkt_pool, attr->vi_mmap_fname));
    sc_pkt_pool_request_bufs(vi->pkt_pool, my_attr);
    vi->stats->pool_id = vi->pkt_pool->pp_id;
    uint64_t num_bufs = sc_pkt_pool_calc_num_bufs(vi->pkt_pool,
                                                  my_attr->pool_size,
                                                  my_attr->pool_n_bufs);
    sc_attr_free(my_attr);

    if( vi->packed_stream_mode ) {
      struct sc_packed_stream_vi* ps_vi = vi->packed_stream_vi;
      /* Pool for unpacking packed stream (if unpacking) or flushing part filled
       * buffers (if not unpacking).
       */
      struct sc_attr* pool_attr = sc_attr_dup(attr);
      SC_TRY(sc_attr_set_int(pool_attr, "buf_inline", 0));
      /* Packets never split across buffers, so no need to allocate space for
       * linear headers. We can safely set buffer size to 0.
       */
      SC_TRY(sc_attr_set_int(pool_attr, "buf_size", 0));
      pool_attr->private_pool = 1;
      pool_attr->n_bufs_tx = -1;
      pool_attr->pool_size = -1;

      sc_pkt_pool_alloc(&ps_vi->ref_pkt_pool, pool_attr, vi->thread);
      vi->stats->packed_stream_pool_id = ps_vi->ref_pkt_pool->pp_id;
      SC_TEST(ps_vi->ref_pkt_pool->pp_linked_pool == NULL);
      ps_vi->ref_pkt_pool->pp_linked_pool = vi->pkt_pool;

      /* If unpacking we need lots of wrapper buffers.  When not unpacking,
       * we need one wrapper per data buffer.
       */
      if( ps_vi->unpack ) {
        if( attr->n_bufs_unpack_pool >= 0 ) {
          pool_attr->pool_n_bufs = attr->n_bufs_unpack_pool;
        }
        else {
          /* Work out how many packets we think would likely fit into the
           * buffers we have.  Need to take account of the padding that the
           * NIC applies between packets.  For the average packet size we
           * assume something fairly aggressive because if we allocate too
           * many buffers it only wastes memory.
           */
          uint64_t avg_pkt_size = 400;
          uint64_t pool_size = num_bufs * ps_vi->ps_params.psp_buffer_size;
          /* These parameters are hidden away inside of ef_vi.  Would be
           * desirable for these to be exposed via ps_params.
           */
          uint64_t avg_overhead = 64/*padding*/ + 64/2/*avg align*/;
          pool_attr->pool_n_bufs = pool_size / (avg_pkt_size + avg_overhead);
          if( attr->n_bufs_unpack_pool_max > 0 &&
              pool_attr->pool_n_bufs > attr->n_bufs_unpack_pool_max )
            pool_attr->pool_n_bufs = attr->n_bufs_unpack_pool_max;
        }
      }
      else {
        pool_attr->pool_n_bufs = num_bufs;
      }
      sc_pkt_pool_request_bufs(ps_vi->ref_pkt_pool, pool_attr);
      sc_attr_free(pool_attr);

      struct sc_object* vi_pkt_pool_ptr;
      struct sc_object* ref_pkt_pool_ptr;
      SC_TEST( sc_opaque_alloc(&vi_pkt_pool_ptr, vi->pkt_pool) == 0 );
      SC_TEST( sc_opaque_alloc(&ref_pkt_pool_ptr, ps_vi->ref_pkt_pool) == 0 );

      struct sc_arg undo_args[] = {
        SC_ARG_OBJ("referenced_pp_ptr", vi_pkt_pool_ptr),
        SC_ARG_OBJ("referring_pp_ptr", ref_pkt_pool_ptr),
      };
      TRY(sc_node_alloc(&vi->undo_node, attr, vi->thread,
                        &sc_ref_count_undo_sc_node_factory, undo_args,
                        sizeof(undo_args) / sizeof(undo_args[0])));
      sc_opaque_free(vi_pkt_pool_ptr);
      sc_opaque_free(ref_pkt_pool_ptr);

      sc_packet_list_init(&(ps_vi->backlog));
    }
  }

  if( vi->burst_interval_ns > 0 )
    sc_timer_expire_after_ns(vi->burst_cb,
                             vi->burst_interval_ns);
  return 0;
}


static void sc_ef_vi_free_pkt(struct sc_pkt_pool* pp, struct sc_pkt* pkt)
{
  sc_pkt_pool_put(pp, pkt);
  ++(pp->pp_refill_node->ni_stats->pkts_in);
  sc_callback_at_safe_time(pp->pp_cb_backlog);
}


static void sc_ef_vi_ps_put_current_on_backlog(struct sc_ef_vi* vi)
{
  struct sc_packed_stream_vi* ps_vi = vi->packed_stream_vi;
  struct sc_pkt* ps_pkt = ps_vi->current_ps_pkt;

  SC_TEST( sc_packet_list_is_empty(&(ps_vi->backlog)) ||
           sc_callback_is_active(ps_vi->backlog_cb) );

  if( ps_pkt_is_on_backlog(ps_pkt) )
    return;

  ps_pkt_set_on_backlog(ps_pkt, 1);
  sc_packet_list_append(&(ps_vi->backlog), &(ps_pkt->sp_usr));
  ++(ps_pkt->sp_ref_count);
  vi->stats->packed_backlog = ps_vi->backlog.num_pkts;
  if( vi->stats->packed_backlog_max < ps_vi->backlog.num_pkts )
    vi->stats->packed_backlog_max = ps_vi->backlog.num_pkts;
  if( ps_vi->backlog.num_pkts == 1 ) {
    /* Backlog is transitioning from empty to non-empty: Ask for callback
     * when buffers are available.
     */
    sc_pool_on_threshold(&(ps_vi->ref_pkt_pool->pp_public),
                         ps_vi->backlog_cb, ps_vi->backlog_threshold);
    ++(vi->stats->n_packed_backlog_enter);
  }
}


static void sc_ef_vi_ps_packed_emit(struct sc_ef_vi* vi, struct sc_pkt* ps_pkt)
{
  struct sc_packed_stream_vi* ps_vi = vi->packed_stream_vi;

  sc_tracefp(ef_vi_tg(vi), "%s:\n", __func__);
  SC_TEST( ! ps_vi->unpack );
  SC_TEST( ps_pkt != NULL );
  SC_TEST( pkt_iov0_len(ps_pkt) > 0 );
  SC_TEST( ! sc_pkt_pool_is_empty(ps_vi->ref_pkt_pool) );

  struct sc_pkt* out_pkt = sc_pkt_pool_get(ps_vi->ref_pkt_pool);
  out_pkt->sp_usr.iov[0].iov_base = psp_from_ps_pkt(ps_pkt);
  out_pkt->sp_usr.iov[0].iov_len = pkt_iov0_len(ps_pkt);
  out_pkt->sp_usr.iovlen = 1;
  out_pkt->sp_usr.frame_len = pkt_iov0_len(out_pkt);
  out_pkt->sp_usr.frags = &ps_pkt->sp_usr;
  out_pkt->sp_usr.frags_tail = &ps_pkt->sp_usr.next;
  out_pkt->sp_usr.frags_n++;
  out_pkt->sp_usr.flags = SC_PACKED_STREAM;
  out_pkt->sp_ref_count = 1;  /* needed to suppress debug checks */
  /* Use timestamp of the first packet. */
  ef_packed_stream_packet* psp = (void*) pkt_iov0_base(out_pkt);
  out_pkt->sp_usr.ts_sec  = psp->ps_ts_sec;
  out_pkt->sp_usr.ts_nsec = psp->ps_ts_nsec;
  __sc_packet_list_append(&vi->vi_recv_node->ni_pkt_list, &out_pkt->sp_usr);

  ps_pkt->sp_usr.iov[0].iov_base = pkt_iov0_end(ps_pkt);
  ps_pkt->sp_usr.iov[0].iov_len = 0;
  ++(ps_pkt->sp_ref_count);
}


static void sc_ef_vi_ps_packed_emit_current(struct sc_ef_vi* vi)
{
  struct sc_packed_stream_vi* ps_vi = vi->packed_stream_vi;
  if( sc_packet_list_is_empty(&(ps_vi->backlog)) &&
      ! sc_pkt_pool_is_empty(ps_vi->ref_pkt_pool) )
    sc_ef_vi_ps_packed_emit(vi, ps_vi->current_ps_pkt);
  else
    sc_ef_vi_ps_put_current_on_backlog(vi);
}


static void sc_ef_vi_ps_packed_emit_from_backlog(struct sc_ef_vi* vi)
{
  struct sc_packed_stream_vi* ps_vi = vi->packed_stream_vi;

  SC_TEST( ps_vi->ref_pkt_pool->pp_n_bufs > 0 );
  SC_TEST( ! sc_packet_list_is_empty(&(ps_vi->backlog)) );

  do {
    struct sc_pkt* ps_pkt =
      SC_PKT_FROM_PACKET(sc_packet_list_pop_head(&(ps_vi->backlog)));
    sc_ef_vi_ps_packed_emit(vi, ps_pkt);
    ps_pkt_set_on_backlog(ps_pkt, 0);
    --(ps_pkt->sp_ref_count);
    SC_TEST( ps_pkt->sp_ref_count > 0 );
  } while( ps_vi->ref_pkt_pool->pp_n_bufs > 0 &&
           ! sc_packet_list_is_empty(&(ps_vi->backlog)) );
}


static void sc_ef_vi_ps_packed_sw_timestamp(struct sc_ef_vi* vi,
                                            ef_packed_stream_packet* psp,
                                            ef_packed_stream_packet* psp_end)
{
  struct sc_thread* thread = vi->thread;
  do {
    psp->ps_ts_sec = thread->cur_time.tv_sec;
    psp->ps_ts_nsec = thread->cur_time.tv_nsec;
    psp = ef_packed_stream_packet_next(psp);
  } while( psp < psp_end );
}


static void sc_ef_vi_ps_pkt_free(struct sc_ef_vi* vi, struct sc_pkt* ps_pkt)
{
  assert( ps_pkt->sp_ref_count == 0 );
  assert( ps_pkt->sp_pkt_pool_id == vi->pkt_pool->pp_id );
  assert( ps_pkt != vi->packed_stream_vi->current_ps_pkt );
  assert( ! ps_pkt_is_on_backlog(ps_pkt) );
  sc_ef_vi_free_pkt(vi->pkt_pool, ps_pkt);
}


static void sc_ef_vi_ps_current_done(struct sc_ef_vi* vi)
{
  /* Adapter has finished delivering packets into this buffer. */

  struct sc_packed_stream_vi* ps_vi = vi->packed_stream_vi;
  struct sc_pkt* ps_pkt = ps_vi->current_ps_pkt;

  sc_tracefp(ef_vi_tg(vi), "%s:\n", __func__);

  if( ! ps_vi->unpack && pkt_iov0_len(ps_pkt) > 0 ) {
    sc_callback_remove(ps_vi->flush_cb);
    sc_ef_vi_ps_packed_emit_current(vi);
  }
  ps_vi->current_ps_pkt = NULL;
  if( --(ps_pkt->sp_ref_count) == 0 )
    sc_ef_vi_ps_pkt_free(vi, ps_pkt);
}


static void sc_ef_vi_ps_get_next_buffer(struct sc_ef_vi* vi)
{
  struct sc_packed_stream_vi* ps_vi = vi->packed_stream_vi;

  sc_tracefp(ef_vi_tg(vi), "%s:\n", __func__);

  if( ps_vi->current_ps_pkt != NULL )
    /* Emit or free the buffer just filled. */
    sc_ef_vi_ps_current_done(vi);

  /* Setup next buffer. */
  unsigned rx_id = (vi->rx_removed)++ & ef_vi_receive_capacity(&vi->vi);
  struct sc_pkt* ps_pkt = vi->rx_pkts[rx_id];
  ps_pkt->sp_ref_count = 1;
  ps_pkt->sp_usr.iov[0].iov_base =
    ef_packed_stream_packet_first(sc_pkt_get_buf(ps_pkt),
                                  ps_vi->ps_params.psp_start_offset);
  ps_pkt->sp_usr.iov[0].iov_len = 0;
  ps_vi->current_ps_pkt = ps_pkt;
  ps_pkt_set_on_backlog(ps_pkt, 0);
}


void sc_ef_vi_stop(struct sc_ef_vi* vi)
{
  if( ! vi->vi_running )
    return;

  sc_trace(vi->thread->session, "%s: t%d v%d/%s\n",
           __func__, vi->thread->id, vi->id, vi->name);
  vi->vi_running = false;
  if( vi->packed_stream_mode ) {
    struct sc_packed_stream_vi* ps_vi = vi->packed_stream_vi;
    if( ps_vi->current_ps_pkt != NULL )
      sc_ef_vi_ps_current_done(vi);
    if( ! ps_vi->unpack )
      sc_callback_remove(ps_vi->flush_cb);
    sc_callback_remove(ps_vi->backlog_cb);
  }
  if( vi->vi_recv_node != NULL )
    sc_node_end_of_stream(vi->vi_recv_node);
}


/* Prep VI at startup. This is called after the packet pool has been filled. */
void sc_ef_vi_prep(struct sc_ef_vi* vi)
{
  struct sc_session* scs = vi->thread->session;
  sc_trace(scs, "%s: sizeof(packet)=%d sizeof(pkt)=%d dma_off=%d dma_len=%d "
           "buf_size=%zd\n", __func__, (int) sizeof(struct sc_packet),
           (int) sizeof(struct sc_pkt), (int) PKT_DMA_OFF,
           ef_vi_receive_buffer_len(&vi->vi), vi->pkt_pool->pp_buf_size);
  SC_TEST( ef_vi_receive_buffer_len(&vi->vi) <= vi->pkt_pool->pp_buf_size );
  SC_TEST( ef_vi_receive_fill_level(&vi->vi) == 0 );

  while( sc_ef_vi_rx_space(vi) >= vi->rx_refill_batch &&
         vi->pkt_pool->pp_n_bufs >= vi->rx_refill_batch )
    sc_ef_vi_rx_refill_batch(vi);
  /* ?? TODO: error if insufficient pkt bufs? */
  vi->vi_running = true;

  if( vi->packed_stream_mode ) {
    struct sc_packed_stream_vi* ps_vi = vi->packed_stream_vi;
    int backlog_thresh = 1;
    if( ps_vi->unpack ) {
      /* Wait for a couple of bins worth of packets to be returned before
       * servicing backlog, to increase chances that bins will be filled.
       */
      backlog_thresh = 2 * sc_pkt_pool_bufs_per_bin(ps_vi->ref_pkt_pool);
      if( backlog_thresh > ps_vi->ref_pkt_pool->pp_stats->allocated_bufs / 4 )
        backlog_thresh = ps_vi->ref_pkt_pool->pp_stats->allocated_bufs / 4;
    }
    ps_vi->backlog_threshold = backlog_thresh;
  }
}


static void sc_ef_vi_rx_refill(struct sc_ef_vi* vi)
{
  int fill_level = ef_vi_receive_fill_level(&vi->vi);
  if( fill_level < vi->rx_ring_low_level ) {
    if( vi->pkt_pool == NULL )
      /* We're not receiving on this VI. */
      return;
    vi->rx_refill_batch = vi->rx_refill_batch_low;
    ++vi->stats->n_rxq_low;
  }
  else if( fill_level > vi->rx_ring_high_level ) {
    vi->rx_refill_batch = vi->rx_refill_batch_high;
  }

  if( vi->rx_refill_batch <= vi->rx_ring_max - fill_level ) {
    if( vi->rx_refill_batch <= vi->pkt_pool->pp_n_bufs )
      sc_ef_vi_rx_refill_batch(vi);
    else
      ++vi->stats->n_free_pool_empty;
  }
}


static void drop_jumbo(struct sc_ef_vi* vi)
{
  assert(vi->jumbo != NULL);
  if( vi->jumbo != NULL ) {
    *vi->jumbo->sp_usr.frags_tail = NULL;
    sc_ef_vi_free_pkt(vi->pkt_pool, vi->jumbo);
    vi->jumbo = NULL;
    VI_DBG_STATS(++vi->stats->jumbo_drop);
    assert(! vi->jumbo_truncated);
  }
  vi->jumbo_truncated = 1;
}


static inline struct sc_pkt*
initialise_rx_pkt(struct sc_ef_vi* vi, ef_event event)
{
  unsigned rx_id = vi->rx_removed & ef_vi_receive_capacity(&vi->vi);
  struct sc_pkt* pkt = vi->rx_pkts[rx_id];
  TEST(EF_EVENT_RX_RQ_ID(event) == rx_id);
  ++vi->rx_removed;
  pkt->sp_usr.iov[0].iov_len = EF_EVENT_RX_BYTES(event) - vi->rx_prefix_len;
  pkt->sp_usr.flags = 0;
  return pkt;
}


static inline struct sc_pkt*
initialise_rx_multi_pkt(struct sc_ef_vi* vi, ef_request_id rq_id)
{
  unsigned rx_id = vi->rx_removed & ef_vi_receive_capacity(&vi->vi);
  struct sc_pkt* pkt = vi->rx_pkts[rx_id];
  uint16_t pkt_bytes;
  TEST(rq_id == rx_id);
  ++(vi->rx_removed);
  ef_vi_receive_get_bytes(&vi->vi, sc_pkt_get_buf_inline(pkt), &pkt_bytes);
  /* If the frame is a jumbo, ef_vi_receive_get_bytes() returns the entire
   * length of the frame, whereas iov_len should just be the length of the
   * current buffer.  We will fix up the the value of iov[0].iov_len when
   * processing the jumbo in sc_ef_vi_rx_multi_ev().
   */
  pkt->sp_usr.iov[0].iov_len = pkt_bytes;
  pkt->sp_usr.flags = 0;
  return pkt;
}


#if 0

#define CRC       4
#define PREAMBLE  8
#define IPG       8


static inline void advance_time(struct sc_ef_vi* vi, unsigned frame_len)
{
  struct timespec* ts = &(vi->thread->cur_time);
  ts->tv_nsec +=
    ((frame_len + CRC + PREAMBLE + IPG) * vi->rate_multiplier) >> 10u;
  if( ts->tv_nsec >= 1000000000 ) {
    ts->tv_sec += 1;
    ts->tv_nsec -= 1000000000;
  }
}

#endif


static inline void timestamp_pkt(struct sc_ef_vi* vi, struct sc_pkt* pkt)
{
  if( vi->flags & vif_rx_timestamps ) {
    void* dma = (char*)pkt + PKT_DMA_OFF;
#ifdef ef_vi_receive_get_precise_timestamp
    /* Onload 9 new unified mechanism for timestamping - old mechanism is deprecated */
    ef_precisetime ts;
    ef_vi_receive_get_precise_timestamp(&vi->vi, dma, &ts);
#else /* ef_vi_receive_get_precise_timestamp */
    /* Prior versions of Onload timestamping mechanism */
    unsigned ts_flags;
    struct timespec ts;
    ef_vi_receive_get_timestamp_with_sync_flags(&vi->vi, dma, &ts, &ts_flags);
#endif /* ef_vi_receive_get_precise_timestamp */
    /* If the above call fails we get a zero timestamp.  (The only expected
     * reason for this happening is receiving packets via the loopback
     * path).
     *
     * TODO: Expose the ts_flags info either via sc_packet flags or
     * metadata.
     */
    pkt->sp_usr.ts_sec = ts.tv_sec;
    pkt->sp_usr.ts_nsec = ts.tv_nsec;
  }
  else {
    pkt->sp_usr.ts_sec = vi->thread->cur_time.tv_sec;
    pkt->sp_usr.ts_nsec = vi->thread->cur_time.tv_nsec;
  }
}


static inline void sc_ef_vi_ps_unpack_one(struct sc_ef_vi* vi,
                                          struct sc_pkt* ps_pkt,
                                          ef_packed_stream_packet* psp)
{
  struct sc_packed_stream_vi* ps_vi = vi->packed_stream_vi;

   /* Mask out discard bits that we're not interested in.
    * NOTE ps_flags mask may be set so as to include EF_VI_PS_FLAG_BAD_FCS
    * or EF_VI_PS_FLAG_BAD_IP_CSUM as required
    */
  if( ! (psp->ps_flags & ps_vi->ps_flags_mask) ) {
    assert(ps_vi->ref_pkt_pool->pp_n_bufs > 0);
    struct sc_pkt* out_pkt = sc_pkt_pool_get(ps_vi->ref_pkt_pool);
    assert(out_pkt != NULL);
    out_pkt->sp_usr.frags = &ps_pkt->sp_usr;
    out_pkt->sp_usr.frags_tail = &ps_pkt->sp_usr.next;
    out_pkt->sp_usr.frags_n++;
    out_pkt->sp_usr.flags = 0;
    if( psp->ps_flags & EF_VI_PS_FLAG_BAD_FCS )
      out_pkt->sp_usr.flags |= SC_CRC_ERROR;
    if( psp->ps_flags & EF_VI_PS_FLAG_BAD_IP_CSUM )
      out_pkt->sp_usr.flags |= SC_CSUM_ERROR;
    out_pkt->sp_ref_count = 1;  /* needed to suppress debug checks */
    out_pkt->sp_usr.ts_sec = psp->ps_ts_sec;
    out_pkt->sp_usr.ts_nsec = psp->ps_ts_nsec;
    out_pkt->sp_usr.frame_len = psp->ps_orig_len;
    out_pkt->sp_usr.iov[0].iov_len = psp->ps_cap_len;
    out_pkt->sp_usr.iov[0].iov_base = ef_packed_stream_packet_payload(psp);
    out_pkt->sp_usr.iovlen = 1;
    ++(ps_pkt->sp_ref_count);
    __sc_packet_list_append(&vi->vi_recv_node->ni_pkt_list, &out_pkt->sp_usr);
  }
  else {
    vi->stats->n_rx_pkts -= 1;
    vi->stats->n_rx_bytes -= psp->ps_cap_len;
  }
}


static inline void sc_ef_vi_ps_unpack(struct sc_ef_vi* vi, int n_pkts)
{
  struct sc_packed_stream_vi* ps_vi = vi->packed_stream_vi;
  struct sc_pkt* ps_pkt = ps_vi->current_ps_pkt;

  assert(ps_vi->ref_pkt_pool->pp_n_bufs >= n_pkts);
  assert(sc_packet_list_is_empty(&(ps_vi->backlog)));
  assert(pkt_iov0_len(ps_pkt) > 0);

  ef_packed_stream_packet* psp = psp_from_ps_pkt(ps_pkt);
  int i;
  for( i = 0; i < n_pkts; ++i ) {
    if( ! (vi->flags & vif_rx_timestamps) ) {
      psp->ps_ts_sec = vi->thread->cur_time.tv_sec;
      psp->ps_ts_nsec = vi->thread->cur_time.tv_nsec;
    }
    sc_ef_vi_ps_unpack_one(vi, ps_vi->current_ps_pkt, psp);
    psp = ef_packed_stream_packet_next(psp);
  }

  /* Keep track of where we've gotten up to. */
  SC_TEST((uint8_t*) psp == pkt_iov0_end(ps_pkt));  /* todo: assert */
  ps_pkt->sp_usr.iov[0].iov_base = psp;
  ps_pkt->sp_usr.iov[0].iov_len = 0;
}


static void sc_ef_vi_ps_unpack_from_backlog(struct sc_ef_vi* vi)
{
  struct sc_packed_stream_vi* ps_vi = vi->packed_stream_vi;
  SC_TEST( ! sc_packet_list_is_empty(&(ps_vi->backlog)) );

  int max_packets = BACKLOG_BATCH;
  if( ps_vi->ref_pkt_pool->pp_n_bufs < max_packets )
    max_packets = ps_vi->ref_pkt_pool->pp_n_bufs;

  struct sc_pkt* ps_pkt =
    SC_PKT_FROM_PACKET(sc_packet_list_pop_head(&(ps_vi->backlog)));
  SC_TEST(ps_pkt_is_on_backlog(ps_pkt));
  SC_TEST(ps_pkt->sp_usr.iov[0].iov_len > 0);

  do {
    ef_packed_stream_packet* psp = psp_from_ps_pkt(ps_pkt);
    sc_ef_vi_ps_unpack_one(vi, ps_pkt, psp);
    ps_pkt->sp_usr.iov[0].iov_base =
      (uint8_t*) ps_pkt->sp_usr.iov[0].iov_base + psp->ps_next_offset;
    ps_pkt->sp_usr.iov[0].iov_len -= psp->ps_next_offset;
    --max_packets;

    if( ps_pkt->sp_usr.iov[0].iov_len == 0 ) {
      SC_TEST(ps_pkt_is_on_backlog(ps_pkt));
      ps_pkt_set_on_backlog(ps_pkt, 0);
      if( --(ps_pkt->sp_ref_count) == 0 )
        sc_ef_vi_ps_pkt_free(vi, ps_pkt);
      if( max_packets == 0 || sc_packet_list_is_empty(&(ps_vi->backlog)) )
        return;
      ps_pkt = SC_PKT_FROM_PACKET(sc_packet_list_pop_head(&(ps_vi->backlog)));
      SC_TEST(ps_pkt_is_on_backlog(ps_pkt));
      SC_TEST(ps_pkt->sp_usr.iov[0].iov_len > 0);
    }
  } while( max_packets );

  sc_packet_list_push_head(&(ps_vi->backlog), &ps_pkt->sp_usr);
  SC_TEST(ps_pkt_is_on_backlog(ps_pkt));
}


static void sc_ef_vi_rx_ev(struct sc_ef_vi* vi, struct sc_pkt* pkt,
                           ef_event event)
{
  assert(pkt->sp_usr.frags_n == 0);
  assert(pkt->sp_usr.frags == NULL);
  assert(pkt->sp_usr.frags_tail == &pkt->sp_usr.frags);

  if( EF_EVENT_RX_SOP(event) && ! EF_EVENT_RX_CONT(event) ) {
    /* Packet fits in a single buffer. */
    assert(vi->jumbo == NULL);
    pkt->sp_usr.frame_len = pkt->sp_usr.iov[0].iov_len;
    vi->stats->n_rx_bytes += pkt->sp_usr.frame_len;
    vi->stats->n_rx_pkts += 1;
    timestamp_pkt(vi, pkt);
    /* advance_time(vi, pkt->sp_usr.frame_len); */
    __sc_packet_list_append(&vi->vi_recv_node->ni_pkt_list, &pkt->sp_usr);
    sc_tracefp(ef_vi_tg(vi), "%s: v%d:%s normal len=%d flags=%x\n", __func__,
               vi->id, vi->name, (int) pkt->sp_usr.frame_len,
               (unsigned) pkt->sp_usr.flags);
    return;
  }

  if( EF_EVENT_RX_SOP(event) ) {
    /* Start of a jumbo (a packet that spans multiple buffers). */
    assert(vi->jumbo == NULL);
    vi->jumbo_truncated = 0;
    vi->jumbo = pkt;
    timestamp_pkt(vi, pkt);
    VI_DBG_STATS(++vi->stats->jumbo_start);
    sc_tracefp(ef_vi_tg(vi), "%s: v%d:%s jumbo_start len=%d\n", __func__,
               vi->id, vi->name, (int) pkt->sp_usr.iov[0].iov_len);
    return;
  }

  if( vi->jumbo_truncated ) {
    /* We're discarding a truncated jumbo. */
    sc_ef_vi_free_pkt(vi->pkt_pool, pkt);
    sc_tracefp(ef_vi_tg(vi), "%s: v%d:%s jumbo_truncated\n",
               __func__, vi->id, vi->name);
    return;
  }

  /* Middle or end of a jumbo. */
  struct sc_pkt* jumbo_head = vi->jumbo;
  assert(jumbo_head != NULL);
  *(jumbo_head->sp_usr.frags_tail) = &pkt->sp_usr;
  jumbo_head->sp_usr.frags_tail = &pkt->sp_usr.next;
  ++(jumbo_head->sp_usr.frags_n);

  if( EF_EVENT_RX_CONT(event) ) {
    /* Middle of a jumbo. */
    sc_tracefp(ef_vi_tg(vi), "%s: v%d:%s jumbo_cont len=%d\n", __func__,
               vi->id, vi->name, (int) pkt->sp_usr.iov[0].iov_len);
    return;
  }

  /* End of a jumbo. */
  sc_tracefp(ef_vi_tg(vi), "%s: v%d:%s jumbo_end len=%d flags=%x\n",
             __func__, vi->id, vi->name, (int) pkt->sp_usr.iov[0].iov_len,
             (unsigned) pkt->sp_usr.flags);
  VI_DBG_STATS(++vi->stats->jumbo_finish);
  *jumbo_head->sp_usr.frags_tail = NULL;

  struct sc_pkt* jumbo_tail = pkt;
  jumbo_head->sp_usr.frame_len = jumbo_tail->sp_usr.iov[0].iov_len;
  jumbo_head->sp_usr.flags = jumbo_tail->sp_usr.flags;
  int prev_len = jumbo_head->sp_usr.iov[0].iov_len;
  int seg_i = 1;
  pkt = SC_PKT_FROM_PACKET(jumbo_head->sp_usr.frags);
  while( pkt != jumbo_tail ) {
    jumbo_head->sp_usr.iov[seg_i].iov_base =
      sc_pkt_get_buf_inline(pkt);
    jumbo_head->sp_usr.iov[seg_i++].iov_len =
      pkt->sp_usr.iov[0].iov_len - prev_len;
    prev_len = pkt->sp_usr.iov[0].iov_len;
    pkt = SC_PKT_NEXT(pkt);
  }
  assert(pkt == jumbo_tail);
  jumbo_head->sp_usr.iov[seg_i].iov_base =
    sc_pkt_get_buf_inline(pkt);
  jumbo_head->sp_usr.iov[seg_i].iov_len =
    pkt->sp_usr.iov[0].iov_len - prev_len;
  jumbo_head->sp_usr.iovlen = jumbo_head->sp_usr.frags_n + 1;

  vi->stats->n_rx_bytes += jumbo_head->sp_usr.frame_len;
  vi->stats->n_rx_pkts += 1;
  /* advance_time(vi, pkt->sp_usr.frame_len); */
  __sc_packet_list_append(&vi->vi_recv_node->ni_pkt_list, &jumbo_head->sp_usr);
  vi->jumbo = NULL;
}


static void sc_ef_vi_rx_multi_ev(struct sc_ef_vi* vi, struct sc_pkt* pkt,
                                 ef_event event)
{
  bool sop = EF_EVENT_RX_MULTI_SOP(event);
  bool cont = EF_EVENT_RX_MULTI_CONT(event);
  int buf_len = ef_vi_receive_buffer_len(&vi->vi);

  if( sop && ! cont ) {
    /* Packet fits in a single buffer. */
    assert(vi->jumbo == NULL);
    pkt->sp_usr.frame_len = pkt->sp_usr.iov[0].iov_len;
    vi->stats->n_rx_bytes += pkt->sp_usr.frame_len;
    vi->stats->n_rx_pkts += 1;
    timestamp_pkt(vi, pkt);
    __sc_packet_list_append(&vi->vi_recv_node->ni_pkt_list, &pkt->sp_usr);
    sc_tracefp(ef_vi_tg(vi), "%s: v%d:%s normal len=%d flags=%x\n", __func__,
               vi->id, vi->name, (int) pkt->sp_usr.frame_len,
               (unsigned) pkt->sp_usr.flags);
    return;
  }

  if( sop ) {
    /* Start of a jumbo (a packet that spans multiple buffers). */
    assert(vi->jumbo == NULL);
    vi->jumbo_truncated = 0;
    vi->jumbo = pkt;
    pkt->sp_usr.frame_len = pkt->sp_usr.iov[0].iov_len;
    pkt->sp_usr.iov[0].iov_len = buf_len - vi->rx_prefix_len;
    timestamp_pkt(vi, pkt);
    VI_DBG_STATS(++vi->stats->jumbo_start);
    sc_tracefp(ef_vi_tg(vi), "%s: v%d:%s jumbo_start len=%d\n", __func__,
               vi->id, vi->name, (int) pkt->sp_usr.iov[0].iov_len);
    return;
  }

  if( vi->jumbo_truncated ) {
    /* We're discarding a truncated jumbo. */
    sc_ef_vi_free_pkt(vi->pkt_pool, pkt);
    sc_tracefp(ef_vi_tg(vi), "%s: v%d:%s jumbo_truncated\n",
               __func__, vi->id, vi->name);
    return;
  }

  /* Middle or end of a jumbo. */
  struct sc_pkt* jumbo_head = vi->jumbo;
  assert(jumbo_head != NULL);
  int seg_i = jumbo_head->sp_usr.iovlen;
  jumbo_head->sp_usr.iov[seg_i].iov_base = sc_pkt_get_buf_inline(pkt);

  if( cont ) {
    /* Middle of a jumbo.
     * Middle fragments are completely filled, and don't contain a prefix.
     */
    jumbo_head->sp_usr.iov[seg_i].iov_len = buf_len;
    jumbo_head->sp_usr.iovlen++;
    sc_tracefp(ef_vi_tg(vi), "%s: v%d:%s jumbo_cont len=%d\n", __func__,
               vi->id, vi->name, buf_len);
    return;
  }

  /* End of a jumbo. Recalculate length of the last fragment.
   * The first buffer contains a prefix, but all intervening buffers are
   * filled, so this contains whatever's leftover.
   */
  jumbo_head->sp_usr.iov[seg_i].iov_len =
    jumbo_head->sp_usr.frame_len + vi->rx_prefix_len -
    jumbo_head->sp_usr.iovlen * buf_len;
  jumbo_head->sp_usr.iovlen++;
  jumbo_head->sp_usr.flags = pkt->sp_usr.flags;

  sc_tracefp(ef_vi_tg(vi), "%s: v%d:%s jumbo_end len=%d total=%d flags=%x\n",
             __func__, vi->id, vi->name,
             (int) jumbo_head->sp_usr.iov[seg_i].iov_len,
             jumbo_head->sp_usr.frame_len, (unsigned) pkt->sp_usr.flags);
  VI_DBG_STATS(++vi->stats->jumbo_finish);
  vi->stats->n_rx_bytes += jumbo_head->sp_usr.frame_len;
  vi->stats->n_rx_pkts += 1;
  __sc_packet_list_append(&vi->vi_recv_node->ni_pkt_list, &jumbo_head->sp_usr);
  vi->jumbo = NULL;
}


static void sc_ef_vi_complete_tx(struct sc_pkt* pkt)
{
  struct sc_injector_node* inj = pkt->sp_tx.injector;
  sc_forward(inj->node, inj->next_hop, &pkt->sp_usr);
  ++inj->n_pkts_out;
  if( inj->eos && inj->n_pkts_out == inj->n_pkts_in )
    sc_node_link_end_of_stream2(inj->next_hop);
}


static inline void sc_ef_vi_ps_rx_ev(struct sc_ef_vi* vi, ef_event* ev)
{
  struct sc_packed_stream_vi* ps_vi = vi->packed_stream_vi;

  if( EF_EVENT_RX_PS_NEXT_BUFFER(*ev) )
    sc_ef_vi_ps_get_next_buffer(vi);


  struct sc_pkt* ps_pkt = ps_vi->current_ps_pkt;
  ef_packed_stream_packet* psp = (void*) pkt_iov0_end(ps_pkt);
  ef_packed_stream_packet* psp_end = psp;
  int n_pkts, n_bytes;
  ef_vi_packed_stream_unbundle(&vi->vi, ev, &psp_end, &n_pkts, &n_bytes);
  vi->stats->n_rx_pkts += n_pkts;
  vi->stats->n_rx_bytes += n_bytes;

  if( ev->rx_packed_stream.ps_flags & EF_VI_PS_FLAG_BAD_FCS )
    vi->stats->n_rx_crc_bad += n_pkts;
  if( ev->rx_packed_stream.ps_flags & EF_VI_PS_FLAG_BAD_IP_CSUM )
    vi->stats->n_rx_csum_bad += n_pkts;

  ps_pkt->sp_usr.iov[0].iov_len = (uint8_t*) psp_end - pkt_iov0_base(ps_pkt);

  sc_tracefp(ef_vi_tg(vi), "%s: v%d:%s packed pkts=%d bytes=%d ps_buf_len=%d "
             "flags=%x\n", __func__, vi->id, vi->name, n_pkts, n_bytes,
             (int) ps_pkt->sp_usr.iov[0].iov_len,
             (unsigned) ev->rx_packed_stream.ps_flags);

  if( ps_vi->unpack ) {
    if( sc_packet_list_is_empty(&(ps_vi->backlog)) &&
        ps_vi->ref_pkt_pool->pp_n_bufs >= n_pkts ) {
      sc_ef_vi_ps_unpack(vi, n_pkts);
    }
    else {
      if( ! (vi->flags & vif_rx_timestamps) )
        sc_ef_vi_ps_packed_sw_timestamp(vi, psp, psp_end);
      sc_ef_vi_ps_put_current_on_backlog(vi);
    }
  }
  else {
    /* This buffer will be pushed out when it is full, or when the flush
     * timer expires.
     */
    if( ! sc_callback_is_active(ps_vi->flush_cb) )
      /* Note we start the flush timer even if we have stuff on the
       * backlog.  The only reason is to avoid a conditional on this
       * semi-fast path.
       */
      sc_timer_expire_after_ns(ps_vi->flush_cb,
                               vi->stats->packed_stream_flush_nanos);
    if( (vi->flags & vif_rx_timestamps) == 0 )
      sc_ef_vi_ps_packed_sw_timestamp(vi, psp, psp_end);
  }
}


static inline bool sc_ef_vi_check_discard(struct sc_ef_vi* vi,
                                          unsigned discard_type,
                                          unsigned* flags_out,
                                          int n_pkts)
{
  bool discard = false;
  switch( discard_type ) {
  case EF_EVENT_RX_DISCARD_CSUM_BAD:
    vi->stats->n_rx_csum_bad += n_pkts;
    *flags_out = SC_CSUM_ERROR;
    discard = vi->discard_mask & SC_CSUM_ERROR;
    break;
  case EF_EVENT_RX_DISCARD_CRC_BAD:
    vi->stats->n_rx_crc_bad += n_pkts;
    *flags_out = SC_CRC_ERROR;
    discard = vi->discard_mask & SC_CRC_ERROR;
    break;
  case EF_EVENT_RX_DISCARD_TRUNC:
    vi->stats->n_rx_trunc += n_pkts;
    *flags_out = SC_TRUNCATED;
    discard = vi->discard_mask & SC_TRUNCATED;
    break;
  case EF_EVENT_RX_DISCARD_MCAST_MISMATCH:
    vi->stats->n_rx_mcast_mismatch += n_pkts;
    *flags_out = SC_MCAST_MISMATCH;
    discard = vi->discard_mask & SC_MCAST_MISMATCH;
    break;
  default: /* EF_EVENT_RX_DISCARD_OTHER: UNICAST_MISMATCH */
    vi->stats->n_rx_ucast_mismatch += n_pkts;
    *flags_out = SC_UCAST_MISMATCH;
    discard = vi->discard_mask & SC_UCAST_MISMATCH;
    break;
  }
  return discard;
}


static int
sc_ef_vi_alloc_from_pd(struct sc_ef_vi* vi,
                       int evq_capacity, int rxq_capacity,
                       int txq_capacity, enum ef_vi_flags flags,
                       void* data)
{
  struct sc_netif* netif = data;
  return ef_vi_alloc_from_pd(&vi->vi, vi->dh, &netif->pd, netif->dh,
                             evq_capacity, rxq_capacity, txq_capacity,
                             NULL, 0, flags);
}


void sc_ef_vi_poll(struct sc_ef_vi* vi)
{
  ef_request_id tx_ids[EF_VI_TRANSMIT_BATCH];
  ef_request_id rx_ids[EF_VI_RECEIVE_BATCH];
  int i, j, n_ev;

  if( !vi->vi_running )
    return;

  sc_ef_vi_rx_refill(vi);

  n_ev = ef_eventq_poll(&vi->vi, vi->ef_events, vi->poll_batch);
  if( ! n_ev )
    return;

  vi->stats->n_total_ev += n_ev;

  for( i = 0; i < n_ev; ++i ) {
    switch( EF_EVENT_TYPE(vi->ef_events[i]) ) {

    case EF_EVENT_TYPE_RX: {
      assert(!vi->packed_stream_mode);
      struct sc_pkt* pkt = initialise_rx_pkt(vi, vi->ef_events[i]);
      sc_ef_vi_rx_ev(vi, pkt, vi->ef_events[i]);
      break;
    }

    case EF_EVENT_TYPE_RX_PACKED_STREAM: {
      assert(vi->packed_stream_mode);
      sc_ef_vi_ps_rx_ev(vi, &(vi->ef_events[i]));
      break;
    }

    case EF_EVENT_TYPE_RX_MULTI: {
      int n = ef_vi_receive_unbundle(&(vi->vi), &(vi->ef_events[i]), rx_ids);
      for( j = 0; j < n; ++j ) {
        struct sc_pkt* pkt = initialise_rx_multi_pkt(vi, rx_ids[j]);
        sc_ef_vi_rx_multi_ev(vi, pkt, vi->ef_events[i]);
      }
      break;
    }

    case EF_EVENT_TYPE_TX: {
      int n = ef_vi_transmit_unbundle(&vi->vi, &vi->ef_events[i], tx_ids);
      for( j = 0; j < n; ++j ) {
        unsigned tx_id = vi->tx_removed & ef_vi_transmit_capacity(&vi->vi);
        assert((unsigned) tx_ids[j] == tx_id);
        sc_ef_vi_complete_tx(vi->tx_pkts[tx_id]);
        ++vi->tx_removed;
      }
      if( ! vi->vi_tx_filling &&
          ef_vi_transmit_fill_level(&vi->vi) < vi->vi_tx_refill_level )
        sc_ef_vi_tx_refill(vi);
      ++(vi->stats->n_tx_ev);
      break;
    }

    case EF_EVENT_TYPE_RX_NO_DESC_TRUNC: {
      drop_jumbo(vi);
      ++vi->stats->n_rx_no_desc_trunc;
      break;
    }

    case EF_EVENT_TYPE_RX_DISCARD: {
      assert(!vi->packed_stream_mode);
      unsigned flags;
      int discard =
        sc_ef_vi_check_discard(vi,
                               EF_EVENT_RX_DISCARD_TYPE(vi->ef_events[i]),
                               &flags, 1);
      struct sc_pkt* pkt = initialise_rx_pkt(vi, vi->ef_events[i]);
      if( ! discard ) {
        pkt->sp_usr.flags |= flags;
        sc_ef_vi_rx_ev(vi, pkt, vi->ef_events[i]);
      }
      else
        sc_ef_vi_free_pkt(vi->pkt_pool, pkt);
      break;
    }

    case EF_EVENT_TYPE_RX_MULTI_DISCARD: {
      int n = ef_vi_receive_unbundle(&(vi->vi), &(vi->ef_events[i]), rx_ids);
      unsigned flags, subtype = vi->ef_events[i].rx_multi_discard.subtype;
      bool discard = sc_ef_vi_check_discard(vi, subtype, &flags, n);
      for( j = 0; j < n; ++j ) {
        struct sc_pkt* pkt = initialise_rx_multi_pkt(vi, rx_ids[j]);
        if( ! discard ) {
          pkt->sp_usr.flags |= flags;
          sc_ef_vi_rx_multi_ev(vi, pkt, vi->ef_events[i]);
        }
        else {
          sc_ef_vi_free_pkt(vi->pkt_pool, pkt);
        }
      }
      break;
    }

    case EF_EVENT_TYPE_TX_ERROR: {
      sc_err(ef_vi_tg(vi), "%s: ERROR: TX_ERROR event type=%d\n",
              __func__, (int) EF_EVENT_TX_ERROR_TYPE(vi->ef_events[i]));
      break;
    }

    default:
      sc_err(ef_vi_tg(vi), "%s: ERROR: unexpected event type=%d\n",
              __func__, (int) EF_EVENT_TYPE(vi->ef_events[i]));
      break;
    }
  }

  VI_DBG_STATS(vi->stats->recv_space =
           vi->rx_ring_max - ef_vi_receive_fill_level(&vi->vi));
  VI_DBG_STATS(vi->stats->recv_fill_level= ef_vi_receive_fill_level(&vi->vi));
  VI_DBG_STATS(vi->stats->pool = vi->pkt_pool->pp_n_bufs);
}


/* Function allocs vi with or without features support according to attributes.
 *
 * Considered features set:
 * - RX event merging
 * - RX timestamping
 *
 * When attribute rx_batch_nanos (or batch_timeout_nanos) is set to 0,
 * or in packed stream mode the function will only try to allocate
 * vi without RX event merging.
 *
 * When attribute require_hw_timestamps is set the function will fail if
 * allocation of vi with timestamps fails.
 *
 * When attribute force_sw_timestamps is set the function will only try to
 * allocate vi without timestamps.
 *
 * When neither attribute for the feature is set then the function will try
 * to allocate vi with feature and, in case this fails, it will
 * fall back to allocating vi without feature.
 *
 * sc_ef_vi_flags_out parameter is updated accordingly to flags of
 * allocated vi.
 */
int
sc_ef_vi_alloc_feats(struct sc_session* tg, struct sc_ef_vi* vi,
                     struct sc_netif* netif, const struct sc_attr* attr,
                     enum ef_vi_flags viflags,
                     sc_ef_vi_alloc_fn alloc_fn, void* alloc_data,
                     unsigned* sc_ef_vi_flags_out)
{
  int rc = -EDOM; /* Placate compiler. */
  int tx_ring_max;

  struct {
    bool try_with;
    bool try_without;
    const char* description;
    enum ef_vi_flags ef_vi_flags;
    enum sc_ef_vi_flags sc_ef_vi_flags;

  } features [] = {
#define FEAT_RX_EVENT_MERGE 0
    {
      .try_with = true,
      .try_without = true,
      .description = "RX event merging",
      .ef_vi_flags = EF_VI_RX_EVENT_MERGE,
      .sc_ef_vi_flags = vif_rx_event_merge,
    },
#define FEAT_RX_TS 1
    {
      .try_with = true,
      .try_without = true,
      .description = "RX timestamping",
      .ef_vi_flags = EF_VI_RX_TIMESTAMPS,
      .sc_ef_vi_flags = vif_rx_timestamps,
    },
  };
  const int feature_count = sizeof(features) / sizeof(features[0]);
  unsigned requested_feature_mask = 0;
  unsigned required_feature_mask = 0;
  unsigned feature_mask;
  enum ef_vi_flags flags;
  enum sc_ef_vi_flags sc_flags;
  int i;

  int rx_batch_nanos = attr->rx_batch_nanos;
  if( rx_batch_nanos < 0 )
    rx_batch_nanos = attr->batch_timeout_nanos;

  if( netif->is_packed_stream ) {
    tx_ring_max = 0;
    *sc_ef_vi_flags_out |= vif_packed_stream;
    viflags |= EF_VI_RX_PACKED_STREAM | EF_VI_RX_PS_BUF_SIZE_64K;
  }
  else {
    /* Use event merging if possible unless attributes request low latency. */
    features[FEAT_RX_EVENT_MERGE].try_with = rx_batch_nanos != 0;
    tx_ring_max = attr->tx_ring_max;
  }

  if( attr->require_hw_timestamps && attr->force_sw_timestamps )
    return sc_set_err(tg, EINVAL, "ERROR: %s: require_hw_timestamps and "
                      "force_sw_timestamps are mutually exclusive\n",
                      __func__);
  features[FEAT_RX_TS].try_with = ! attr->force_sw_timestamps;
  features[FEAT_RX_TS].try_without = ! attr->require_hw_timestamps;

  /* Build masks of the features that are required or requested. */
  for( i = 0; i < feature_count; ++i )
    if( features[i].try_with ) {
      requested_feature_mask |= 1 << i;
      if( ! features[i].try_without )
        required_feature_mask |= 1 << i;
    }
  assert((required_feature_mask & ~requested_feature_mask) == 0);

  feature_mask = requested_feature_mask;
  do {
    /* Skip any iterations that would attempt to enable a feature that was not
     * requested, or would not attempt a feature that was required.
     */
    if( feature_mask & ~requested_feature_mask ||
        ~feature_mask & required_feature_mask )
      continue;

    /* Build the flag fields from the mask of features. */
    flags = viflags;
    sc_flags = 0;
    for( i = 0; i < feature_count; ++i )
      if( feature_mask & (1 << i) ) {
        flags |= features[i].ef_vi_flags;
        sc_flags |= features[i].sc_ef_vi_flags;
      }

    rc = alloc_fn(vi, -1, attr->rx_ring_max, tx_ring_max, flags, alloc_data);
    if( rc == 0 ) {
      *sc_ef_vi_flags_out |= sc_flags;
      break;
    }
    /* Loop until we've tried the least-featureful permissible allocation,
     * taking care that we don't underflow.
     */
  } while( feature_mask && feature_mask-- >= required_feature_mask );

  /* Log failed attempts for optional features */
  if( rc != 0 )
    feature_mask = required_feature_mask;
  for( i = 0; i < feature_count; ++i )
    if( features[i].try_with && ! (feature_mask & (1 << i)) )
      sc_trace(tg, "VI allocation with %s failed. Trying without.\n",
               features[i].description);

  if( rc == -EINVAL )
    rc = sc_set_err(tg, rc, "ERROR: %s: VI allocation failed"
                    "(invalid rx_ring_max or tx_ring_max)\n", __func__);
  else if( rc != 0 )
    rc = sc_set_err(tg, rc, "ERROR: %s: VI allocation failed (%d)\n",
                    __func__, rc);
  return rc;
}


void sc_ef_vi_set_attr(struct sc_attr* attr, unsigned sc_ef_vi_flags,
                       struct sc_ef_vi* vi)
{
  if( sc_ef_vi_flags & vif_packed_stream ) {
    ef_packed_stream_params  ps_params;
    SC_TRY(ef_vi_packed_stream_get_params(&(vi->vi), &ps_params));
    /* Buffers can be 1MiB or 64 KiB. We need to adjust rx_ring_max
     * accordingly.
     */
    if( ps_params.psp_buffer_size == (1024*1024) ) {
      if( attr->rx_ring_max < 0 )
        attr->rx_ring_max = RX_RING_MAX_DEFAULT_PACKED_STREAM_1M;
    }
    else if( ps_params.psp_buffer_size == (64*1024) ) {
      if( attr->rx_ring_max < 0 )
        attr->rx_ring_max = RX_RING_MAX_DEFAULT_PACKED_STREAM_64K;
    }
    else {
      /* Only 1MiB and 64KiB buffer sizes are supported */
      SC_TEST(0);
    }
    if( attr->pool_size < 0 && attr->n_bufs_rx < 0 )
      attr->pool_size = 128*1024*1024;
    if( attr->rx_refill_batch_high < 0 )
      attr->rx_refill_batch_high = RX_REFILL_BATCH_HIGH_PACKED_STREAM;
    if( attr->rx_refill_batch_low < 0 )
      attr->rx_refill_batch_low = RX_REFILL_BATCH_LOW_PACKED_STREAM;
  }
  else {
    if(  attr->pool_size < 0 && attr->n_bufs_rx < 0 )
      attr->pool_size = 128*1024*1024;
    if( attr->rx_ring_max < 0 )
      attr->rx_ring_max = 504;
    if( attr->rx_refill_batch_high < 0 )
      attr->rx_refill_batch_high = 16;
    if( attr->rx_refill_batch_low < 0 )
      attr->rx_refill_batch_low = 40;
  }
}


int sc_ef_vi_alloc(struct sc_ef_vi** vi_out, const struct sc_attr* attr,
                   struct sc_thread* thread, const char* layer_2_interface,
                   unsigned sc_ef_vi_flags)
{
  int rc;
  struct sc_session* tg = thread->session;

  struct sc_netif* netif;
  rc = sc_netif_get(&netif, attr, tg, layer_2_interface);
  if( rc < 0 )
    return rc;

  enum ef_vi_flags viflags = 0;
  if( ! (sc_ef_vi_flags & vif_tx_csum_ip) )
    viflags |= EF_VI_TX_IP_CSUM_DIS;
  if( ! (sc_ef_vi_flags & vif_tx_csum_tcpudp) )
    viflags |= EF_VI_TX_TCPUDP_CSUM_DIS;

  struct sc_ef_vi* vi = sc_thread_calloc(thread, sizeof(*vi));
  TEST(vi != NULL);
  vi->id = tg->tg_vis_n;
  if( attr->name == NULL )
    TEST(asprintf(&vi->name, "sc_vi(%d,%s/%s)", vi->id,
                  netif->name, netif->interface->if_name) > 0);
  else
    vi->name = strdup(attr->name);

  if( (rc = ef_driver_open(&vi->dh)) < 0 ) {
    rc = sc_set_err(tg, -rc, "ERROR: %s: ef_driver open failed (%d)\n",
                    __func__, rc);
    goto free_sc_ef_vi;
  }

  rc = sc_ef_vi_alloc_feats(tg, vi, netif, attr, viflags,
                            sc_ef_vi_alloc_from_pd, netif, &sc_ef_vi_flags);
  if( rc < 0 )
    goto close_dh;

  struct sc_attr* vi_attr = sc_attr_dup(attr);
  SC_TEST(vi_attr != NULL);
  sc_ef_vi_set_attr(vi_attr, sc_ef_vi_flags, vi);

  if( (rc = __sc_ef_vi_init(thread, vi_attr, vi, netif, sc_ef_vi_flags)) < 0 )
    goto free_ef_vi;


  sc_trace(tg, "%s: name=%s thread=%s intf=%s vi_id=%d\n", __func__, vi->name,
           thread->name, layer_2_interface, ef_vi_instance(&vi->vi));
  *vi_out = vi;
  sc_attr_free(vi_attr);
  return 0;

 free_ef_vi:
  ef_vi_free(&vi->vi, vi->dh);
  sc_attr_free(vi_attr);
 close_dh:
  ef_driver_close(vi->dh);
 free_sc_ef_vi:
  free(vi->name);
  sc_thread_mfree(thread, vi);
  return rc;
}


int sc_ef_vi_free(struct sc_session* tg, struct sc_ef_vi* vi)
{
  int rc;

  /* TODO: What other sc_ef_vi resources should we free here? */

  free(vi->name);
  if( (rc = ef_vi_free(&vi->vi, vi->dh)) != 0 )
    sc_trace(tg, "%s: ef_vi_free() failed: %d\n", __func__, rc);
  if( (rc = ef_driver_close(vi->dh)) != 0 )
    sc_trace(tg, "%s: ef_driver_close() failed: %d\n", __func__, rc);
  sc_thread_mfree(vi->thread, vi);
  return 0;
}


static int add_fn_vi(void* v_vi, ef_filter_spec* spec)
{
  struct sc_ef_vi* vi = v_vi;
  vi->flags |= vif_has_stream;
  return ef_vi_filter_add(&vi->vi, vi->dh, spec, NULL);
}


int sc_ef_vi_add_stream(struct sc_ef_vi* vi, struct sc_stream* s,
                        enum sc_capture_mode capture_mode, int promiscuous,
                        enum sc_capture_point capture_point)
{
  return sc_stream_add(s, vi, capture_mode, promiscuous, capture_point,
                       add_fn_vi);
}


static void sc_ef_vi_readable(struct sc_callback* cb, void* event_info)
{
  struct sc_ef_vi* vi = cb->cb_private;
  vi->thread->is_sleeping = 0;
  vi->primed = 0;
  ++(vi->stats->n_wakes);
}


static void sc_ef_vi_burst_cb(struct sc_callback* cb, void* event_info)
{
  struct sc_ef_vi* vi = cb->cb_private;
  if( vi->stats->n_rx_pkts - vi->n_rx_pkts_prev >= vi->burst_pkts_threshold ||
      vi->stats->n_rx_bytes - vi->n_rx_bytes_prev >= vi->burst_bytes_threshold )
    ++vi->burst_stats->n_bursts;
  vi->n_rx_pkts_prev = vi->stats->n_rx_pkts;
  vi->n_rx_bytes_prev = vi->stats->n_rx_bytes;
  sc_timer_expire_after_ns(cb, vi->burst_interval_ns);
}


void sc_ef_vi_about_to_sleep(struct sc_ef_vi* vi)
{
  if( ! vi->primed ) {
    SC_TRY(ef_vi_prime(&vi->vi, vi->dh, ef_eventq_current(&vi->vi)));
    vi->primed = 1;
  }
}


static void sc_ef_vi_ps_try_flush(struct sc_callback* cb, void* event_info)
{
  struct sc_ef_vi* vi = cb->cb_private;
  struct sc_packed_stream_vi* ps_vi = vi->packed_stream_vi;

  sc_tracefp(ef_vi_tg(vi), "%s: current_len=%d backlog=%d\n", __func__,
             (int) pkt_iov0_len(ps_vi->current_ps_pkt),
             ps_vi->backlog.num_pkts);

  SC_TEST( vi->vi_running );
  SC_TEST( vi->packed_stream_mode );
  SC_TEST( ! ps_vi->unpack );
  SC_TEST( ps_vi->current_ps_pkt );

  if( pkt_iov0_len(ps_vi->current_ps_pkt) > 0 &&
      sc_packet_list_is_empty(&(ps_vi->backlog)) )
    sc_ef_vi_ps_packed_emit_current(vi);
}


static void sc_ef_vi_ps_on_ref_pool_threshold(struct sc_callback* cb,
                                              void* event_info)
{
  struct sc_ef_vi* vi = cb->cb_private;
  struct sc_packed_stream_vi* ps_vi = vi->packed_stream_vi;

  SC_TEST( vi->vi_running );

  if( ps_vi->unpack )
    sc_ef_vi_ps_unpack_from_backlog(vi);
  else
    sc_ef_vi_ps_packed_emit_from_backlog(vi);

  vi->stats->packed_backlog = ps_vi->backlog.num_pkts;
  if( ! sc_packet_list_is_empty(&(ps_vi->backlog)) )
    sc_pool_on_threshold(&(ps_vi->ref_pkt_pool->pp_public),
                         ps_vi->backlog_cb, ps_vi->backlog_threshold);
}
