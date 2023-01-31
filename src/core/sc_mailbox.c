/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#include "internal.h"
#include <limits.h>


#define MBOX_MSG_BIT         0x1
#define MBOX_ACK_BIT         0x2
#define MBOX_MSG_MASK        (~((uintptr_t) 0x3))


#define mb_name(mb)  ((mb)->mb_send_node.ni_node.nd_name)
#define mb_scs(mb)   ((mb)->mb_thread->session)


/* Returns t1 - t2 in ns */
static inline uint64_t ts_diff(struct timespec t1, struct timespec t2)
{
  if( t2.tv_nsec > t1.tv_nsec )
    return (t1.tv_sec - t2.tv_sec - 1) * (uint64_t)1000000000
      + (t1.tv_nsec + (uint64_t)1000000000 - t2.tv_nsec);
  return (t1.tv_sec - t2.tv_sec) * (uint64_t)1000000000
    + (t1.tv_nsec - t2.tv_nsec);
}


static inline int sc_mbox_can_send(const struct sc_mailbox* mb)
{
  return ((mb->mb_n_sent ^ (mb->mb_recv_slot_v >> 1)) & 0x1) == 0;
}


static void sc_mailbox_wake(struct sc_mailbox* mb)
{
  sc_slb();
  if( mb->mb_remote_thread->is_sleeping ) {
    mb->mb_remote_thread->is_sleeping = 0;
    sc_thread_wake(mb->mb_remote_thread);
    ++(mb->mb_stats->wakes);
  }
}


static inline void sc_mbox_send_msg(struct sc_mailbox* mb, uintptr_t msg)
{
  assert((msg & (MBOX_MSG_BIT | MBOX_ACK_BIT)) == 0);
  ++mb->mb_n_sent;
  mb->mb_send_slot_v = msg | (uintptr_t) (mb->mb_n_sent & 0x1) |
    (uintptr_t) ((mb->mb_n_recv & 0x1) << 1);
  sc_write_release();
  mb->mb_send_slot->v = mb->mb_send_slot_v;
  if( mb->mb_remote_thread->wakeup_cb != NULL )
    sc_mailbox_wake(mb);
}


static void sc_mailbox_push_send_q(struct sc_mailbox* mb)
{
  struct sc_pkt* head = SC_PKT_FROM_PACKET(mb->mb_send_list.head);
  head->sp_mbox.tail = mb->mb_send_list.tail;
  head->sp_mbox.num_pkts = mb->mb_send_list.num_pkts;
  head->sp_mbox.num_frags = mb->mb_send_list.num_frags;
  sc_mbox_send_msg(mb, (uintptr_t) head);
  __sc_packet_list_init(&mb->mb_send_list);
  assert(!sc_mbox_can_send(mb));
  sc_callback_remove(mb->mb_timer_cb);
  mb->mb_stats->send_backlog = 0;
}


static void sc_mailbox_send_timeout(struct sc_callback* cb, void* event_info)
{
  struct sc_mailbox* mb = cb->cb_private;
  if( sc_mbox_can_send(mb) ) {
    sc_tracefp(mb_scs(mb), "%s: [%s] push %d pkts\n",
               __func__, mb_name(mb), mb->mb_send_list.num_pkts);
    sc_mailbox_push_send_q(mb);
  }
}


static inline void sc_mbox_try_send(struct sc_mailbox* mb, int was_empty)
{
  assert(!sc_packet_list_is_empty(&mb->mb_send_list));

  if( mb->mb_send_list.num_pkts >= mb->mb_stats->send_min_pkts ) {
    if( sc_mbox_can_send(mb) ) {
      sc_tracefp(mb_scs(mb), "%s: [%s] push %d pkts\n",
                 __func__, mb_name(mb), mb->mb_send_list.num_pkts);
      sc_mailbox_push_send_q(mb);
      return;
    }
  }
  else if( was_empty ) {
    sc_timer_expire_after_ns(mb->mb_timer_cb, mb->mb_stats->send_max_nanos);
  }
  mb->mb_stats->send_backlog = mb->mb_send_list.num_pkts;
}


void sc_mailbox_send(struct sc_mailbox* mb, struct sc_packet* packet)
{
  sc_tracefp(mb_scs(mb), "%s: [%s] send_q=%d\n",
             __func__, mb_name(mb), mb->mb_send_list.num_pkts + 1);
  int was_empty = sc_packet_list_is_empty(&mb->mb_send_list);
  sc_packet_list_append(&mb->mb_send_list, packet);
  sc_mbox_try_send(mb, was_empty);
  ++(mb->mb_send_node.ni_stats->pkts_in);
}


static inline void __sc_mailbox_send_list(struct sc_mailbox* mb,
                                          struct sc_packet_list* pl)
{
  int was_empty = sc_packet_list_is_empty(&mb->mb_send_list);
  sc_packet_list_append_list(&mb->mb_send_list, pl);
  sc_mbox_try_send(mb, was_empty);
}


void sc_mailbox_send_list(struct sc_mailbox* mb, struct sc_packet_list* pl)
{
  sc_tracefp(mb_scs(mb), "%s: [%s] send_q=%d\n",
             __func__, mb_name(mb), mb->mb_send_list.num_pkts + pl->num_pkts);
  __sc_mailbox_send_list(mb, pl);
  mb->mb_send_node.ni_stats->pkts_in += pl->num_pkts;
}


static void sc_mailbox_send_node_pkts(struct sc_node* this_node,
                                      struct sc_packet_list* pl)
{
  struct sc_node_impl* ni = SC_NODE_IMPL_FROM_NODE(this_node);
  struct sc_mailbox* mb = SC_MAILBOX_FROM_NODE_IMPL(ni);
  sc_tracefp(mb_scs(mb), "%s: [%s] send_q=%d\n",
             __func__, mb_name(mb), mb->mb_send_list.num_pkts + pl->num_pkts);
  __sc_mailbox_send_list(mb, pl);
}


static void sc_mailbox_send_node_end_of_stream_again(struct sc_callback* cb,
                                                     void* event_info)
{
  struct sc_mailbox* mb = cb->cb_private;
  struct sc_session* tg = mb->mb_thread->session;
  if( sc_packet_list_is_empty(&mb->mb_send_list) && sc_mbox_can_send(mb) ) {
    sc_trace(tg, "%s: [%s] NOW\n", __func__, mb_name(mb));
    sc_mbox_send_msg(mb, 0);
    sc_callback_free(cb);
    mb->mb_stats->eos_in = 1;
  }
  else {
    sc_trace(tg, "%s: [%s] DEFER\n", __func__, mb_name(mb));
    sc_timer_expire_after_ns(cb, 1000000);
  }
}


static void sc_mailbox_send_node_end_of_stream(struct sc_node* node)
{
  struct sc_node_impl* ni = SC_NODE_IMPL_FROM_NODE(node);
  struct sc_session* tg = ni->ni_thread->session;
  struct sc_mailbox* mb = SC_MAILBOX_FROM_NODE_IMPL(ni);
  if( sc_packet_list_is_empty(&mb->mb_send_list) && sc_mbox_can_send(mb) ) {
    sc_trace(tg, "%s: [%s] NOW\n", __func__, mb_name(mb));
    sc_mbox_send_msg(mb, 0);
    mb->mb_stats->eos_in = 1;
  }
  else {
    sc_trace(tg, "%s: [%s] DEFER\n", __func__, mb_name(mb));
    struct sc_callback* cb;
    SC_TRY( sc_callback_alloc2(&cb, NULL, ni->ni_thread, "mailbox_eos") );
    cb->cb_private = mb;
    cb->cb_handler_fn = sc_mailbox_send_node_end_of_stream_again;
    sc_timer_expire_after_ns(cb, 1000000);
    mb->mb_stats->eos_in = -1;
  }
}


static int sc_mailbox_send_node_prep(struct sc_node* this_node,
                                     const struct sc_node_link*const* links,
                                     int n_links)
{
  struct sc_node_impl* ni = SC_NODE_IMPL_FROM_NODE(this_node);
  struct sc_mailbox* mb = SC_MAILBOX_FROM_NODE_IMPL(ni);
  struct sc_mailbox* rmb = sc_mailbox_get_peer(mb);
  if( rmb != NULL ) {
    if( rmb->mb_recv_node == NULL ) {
      /* This mailbox is reachable, but goes nowhere -- setup as free path.
       * (This is used by apps with unmanaged threads, including libpcap).
       */
      struct sc_session* tg = ni->ni_thread->session;
      sc_trace(tg, "%s: m%d/n%d frees to pools (%s)\n", __func__,
               mb->mb_id, ni->ni_id, sc_bitmask_fmt(&ni->ni_src_pools));
      sc_setup_pkt_free(tg, &rmb->mb_recv_node,
                        rmb->mb_thread, &ni->ni_src_pools);
    }
    sc_node_propagate_pools(rmb->mb_recv_node, &ni->ni_src_pools);
  }
  return 0;
}


const struct sc_node_type sc_mailbox_send_node_type = {
  .nt_name             = "sc_mailbox_node",
  .nt_prep_fn          = sc_mailbox_send_node_prep,
  .nt_pkts_fn          = sc_mailbox_send_node_pkts,
  .nt_end_of_stream_fn = sc_mailbox_send_node_end_of_stream,
};


static inline int sc_mailbox_try_get(struct sc_mailbox* mb)
{
  uintptr_t v = mb->mb_recv_slot_v;
  if( ((v ^ mb->mb_n_recv) & 0x1) != 0 ) {
    struct sc_pkt* pkt = (void*) (v & MBOX_MSG_MASK);
    ++mb->mb_n_recv;
    if( pkt != NULL ) {
      sc_tracefp(mb_scs(mb), "%s: [%s] %d pkts\n",
                 __func__, mb_name(mb), pkt->sp_mbox.num_pkts);
      MBOX_DBG_STATS(++mb->mb_stats->recved_data);
      __sc_packet_list_append_list(&mb->mb_recv_q,
                                   &pkt->sp_usr, pkt->sp_mbox.tail,
                                   pkt->sp_mbox.num_pkts,
                                   pkt->sp_mbox.num_frags);
      return 1;
    }
    else {
      sc_trace(mb_scs(mb), "%s: [%s] end-of-stream [%s]\n",
               __func__, mb_name(mb), mb->mb_recv_node ?
               mb->mb_recv_node->ni_node.nd_name : "[no-recv-node]");
      mb->mb_stats->eos_out = 1;
      if( mb->mb_recv_node != NULL )
        sc_node_end_of_stream(mb->mb_recv_node);
    }
  }
  return 0;
}


int sc_mailbox_poll(struct sc_mailbox* mb, struct sc_packet_list* pl)
{
  /* Do we want to re-read the local slot?  (Because we want to send and
   * can't, or because we would like to receive more data).
   */
  bool want_to_send = ! sc_packet_list_is_empty(&mb->mb_send_list) &&
    (mb->mb_send_list.num_pkts >= mb->mb_stats->send_min_pkts ||
     ! sc_callback_is_active(mb->mb_timer_cb));

  if( mb->mb_recv_q.num_pkts < mb->mb_stats->recv_max_pkts ) {
    uintptr_t v = mb->mb_recv_slot.v;
    if( mb->mb_recv_slot_v != v ) {
      mb->mb_recv_slot_v = v;
      sc_read_acquire();
    }
    sc_mailbox_try_get(mb);
  }
  else if( want_to_send && ! sc_mbox_can_send(mb) ) {
    uintptr_t v = mb->mb_recv_slot.v;
    if( mb->mb_recv_slot_v != v ) {
      mb->mb_recv_slot_v = v;
      sc_read_acquire();
    }
  }

  if( want_to_send && sc_mbox_can_send(mb) ) {
    sc_tracefp(mb_scs(mb), "%s: [%s] push %d pkts\n",
               __func__, mb_name(mb), mb->mb_send_list.num_pkts);
    sc_mailbox_push_send_q(mb);
  }
  else if( (mb->mb_send_slot_v ^ (mb->mb_n_recv << 1)) & MBOX_ACK_BIT ) {
    /* We've received a message that we've not yet acknowledged. */
    sc_tracefp(mb_scs(mb), "%s: [%s] ack last recv\n", __func__, mb_name(mb));
    MBOX_DBG_STATS(++mb->mb_stats->sent_ack);
    uintptr_t v = mb->mb_send_slot_v & ~MBOX_ACK_BIT;
    v |= (mb->mb_n_recv & 0x1) << 1;
    mb->mb_send_slot->v = v;
    mb->mb_send_slot_v = v;
    if( mb->mb_remote_thread->wakeup_cb != NULL )
      sc_mailbox_wake(mb);
  }

  if( mb->mb_recv_q.num_pkts ) {
    if( mb->mb_recv_q.num_pkts <= mb->mb_stats->recv_max_pkts ) {
      sc_packet_list_append_list(pl, &mb->mb_recv_q);
      assert(*(pl->tail) == NULL);
      __sc_packet_list_init(&mb->mb_recv_q);
      mb->mb_stats->recv_backlog = 0;
      return 1;
    }
    else {
      int i = 0;
      while( 1 ) {
        __sc_packet_list_append(pl, __sc_packet_list_pop_head(&mb->mb_recv_q));
        if( ++i < mb->mb_stats->recv_max_pkts )
          sc_packet_prefetch_r(mb->mb_recv_q.head->next);
        else
          break;
      }
      assert( ! sc_packet_list_is_empty(&mb->mb_recv_q) );
      sc_packet_list_finalise(pl);
      mb->mb_stats->recv_backlog = mb->mb_recv_q.num_pkts;
      return 1;
    }
  }

  return 0;
}


int sc_mailbox_alloc(struct sc_mailbox** mbox_out,
                       const struct sc_attr* attr, struct sc_thread* thread)
{
  struct sc_session* tg = thread->session;

  TRY(sc_thread_affinity_save_and_set(thread));

  struct sc_mailbox* m;
  m = sc_thread_calloc_aligned(thread, sizeof(*m), SC_CACHE_LINE_SIZE);
  SC_TEST(((uintptr_t) &m->mb_recv_slot.v & (SC_CACHE_LINE_SIZE-1)) == 0);
  m->mb_id = tg->tg_mailboxes_n++;

  char* name;
  TEST(asprintf(&name, "sc_mailbox_node(n%d,m%d)",
                tg->tg_nodes_n, m->mb_id) > 0);
  sc_node_init(&m->mb_send_node, &sc_mailbox_send_node_type, thread,
               name, attr->group_name);
  sc_node_add_info_int(&m->mb_send_node.ni_node, "mailbox_id", m->mb_id);

  if( attr->name == NULL )
    TEST(asprintf(&name, "sc_mailbox(%d)", m->mb_id) > 0);
  else
    name = strdup(attr->name);
  TRY(sc_stats_add_block(thread, name, "sc_mailbox_stats",
                         "m", m->mb_id, sizeof(*m->mb_stats), &m->mb_stats));
  if( attr->group_name != NULL )
    sc_stats_add_info_str(tg, "m", m->mb_id, "group_name", attr->group_name);
  free(name);
  m->mb_stats->id = m->mb_id;
  m->mb_stats->managed = attr->managed;
  m->mb_stats->thread_id = thread->id;
  m->mb_stats->peer_id = -1;
  m->mb_stats->send_node_id = m->mb_send_node.ni_id;

  __sc_packet_list_init(&m->mb_recv_q);
  __sc_packet_list_init(&m->mb_send_list);
  sc_thread_add_mailbox(thread, m);

  m->mb_thread = thread;
  sc_mailbox_set_batching_send(m, attr);
  sc_mailbox_set_batching_recv(m, attr);
  SC_TRY( sc_callback_alloc2(&m->mb_timer_cb, NULL, thread, "mailbox_send") );
  m->mb_timer_cb->cb_private = m;
  m->mb_timer_cb->cb_handler_fn = sc_mailbox_send_timeout;

  TRY(sc_thread_affinity_restore(thread));
  *mbox_out = m;
  sc_trace(tg, "%s: name=%s thread=%s\n",
           __func__, m->mb_send_node.ni_node.nd_name, thread->name);
  return 0;
}


int sc_mailbox_connect(struct sc_mailbox* mn1, struct sc_mailbox* mn2)
{
  TEST(mn1->mb_thread->session == mn2->mb_thread->session);
  struct sc_session* tg = mn1->mb_thread->session;

  if( mn1->mb_remote_thread != NULL )
    return sc_set_err(tg, EINVAL, "%s: ERROR: mailbox(%s) already connected\n",
                      __func__, mn1->mb_send_node.ni_node.nd_name);
  if( mn2->mb_remote_thread != NULL )
    return sc_set_err(tg, EINVAL, "%s: ERROR: mailbox(%s) already connected\n",
                      __func__, mn2->mb_send_node.ni_node.nd_name);

  sc_trace(tg, "%s: m%d<=>m%d n%d<=>n%d\n", __func__,
           mn1->mb_id, mn2->mb_id,
           mn1->mb_send_node.ni_id, mn2->mb_send_node.ni_id);

  mn1->mb_send_slot = &mn2->mb_recv_slot;
  mn1->mb_remote_thread = mn2->mb_thread;
  mn1->mb_stats->peer_id = mn2->mb_id;

  mn2->mb_send_slot = &mn1->mb_recv_slot;
  mn2->mb_remote_thread = mn1->mb_thread;
  mn2->mb_stats->peer_id = mn1->mb_id;

  sc_stats_add_info_int(tg, "m", mn1->mb_id, "peer_mailbox_id", mn2->mb_id);
  sc_stats_add_info_int(tg, "m", mn2->mb_id, "peer_mailbox_id", mn1->mb_id);
  return 0;
}


int sc_mailbox_set_recv(struct sc_mailbox* mn, struct sc_node* node_in,
                        const char* name_opt)
{
  struct sc_session* tg = mn->mb_thread->session;
  if( mn->mb_recv_node != NULL )
    return sc_set_err(tg, EINVAL, "%s: ERROR: mailbox(%s) already has recv "
                      "node (%s)\n", __func__, mn->mb_send_node.ni_node.nd_name,
                      mn->mb_recv_node->ni_node.nd_name);
  if( sc_node_get_thread(node_in) != mn->mb_thread )
    return sc_set_err(tg, EINVAL, "%s: ERROR: mailbox(%s) in different thread "
                      "from node (%s)\n", __func__,
                      mn->mb_send_node.ni_node.nd_name, node_in->nd_name);

  char* to_name = name_opt ? strdup(name_opt) : NULL;
  struct sc_node* node = sc_node_get_ingress_node(node_in, &to_name);
  free(to_name);
  if( node == NULL )
    return sc_fwd_err(tg, NULL);

  sc_trace(tg, "%s: %s => n%d/%s[%s]\n",
           __func__, mn->mb_send_node.ni_node.nd_name,
           SC_NODE_IMPL_FROM_NODE(node)->ni_id, node->nd_type->nt_name,
           node->nd_name);
  mn->mb_recv_node = SC_NODE_IMPL_FROM_NODE(node);
  ++(mn->mb_recv_node->ni_n_incoming_links);
  mn->mb_stats->recv_node_id = mn->mb_recv_node->ni_id;
  return 0;
}


struct sc_node* sc_mailbox_get_send_node(struct sc_mailbox* mn)
{
  return &mn->mb_send_node.ni_node;
}


struct sc_mailbox* sc_mailbox_get_peer(struct sc_mailbox* mb)
{
  if( mb->mb_send_slot == NULL )
    return NULL;
  return SC_CONTAINER(struct sc_mailbox, mb_recv_slot,
                      mb->mb_send_slot);
}


struct sc_thread* sc_mailbox_get_thread(struct sc_mailbox* mb)
{
  return mb->mb_send_node.ni_thread;
}


struct sc_thread* sc_mailbox_get_remote_thread(struct sc_mailbox* mb)
{
  mb = sc_mailbox_get_peer(mb);
  return mb != NULL ? sc_mailbox_get_thread(mb) : NULL;
}


void sc_mailbox_set_batching_send(struct sc_mailbox* mb,
                                  const struct sc_attr* attr)
{
  struct sc_mailbox_stats* stats = mb->mb_stats;
  stats->send_min_pkts =
    SC_ATTR_GET_INT_ALT(attr, mailbox_min_pkts, batch_num_pkts);
  stats->send_max_nanos =
    SC_ATTR_GET_INT_ALT(attr, mailbox_max_nanos, batch_timeout_nanos);
}


void sc_mailbox_set_batching_recv(struct sc_mailbox* mb,
                                  const struct sc_attr* attr)
{
  struct sc_mailbox_stats* stats = mb->mb_stats;
  stats->recv_max_pkts =
    SC_ATTR_GET_INT_ALT(attr, mailbox_recv_max_pkts, batch_max_pkts);
  if( stats->recv_max_pkts <= 0 )
    stats->recv_max_pkts = INT_MAX;
}
