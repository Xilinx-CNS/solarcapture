/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#include "internal.h"
#include <sc_internal/ef_vi.h>

#include <limits.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/timerfd.h>
#include <sys/eventfd.h>

#include "compiled_ef_vi_version.h"

__thread struct sc_thread* sc_thread_current;

static pthread_mutex_t global_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct sc_dlist all_sessions;


int sc_session_alloc(struct sc_session** tg_out, const struct sc_attr* attr)
{
  struct sc_session* tg = calloc(1, sizeof(*tg));
  TEST(tg);
  sc_dlist_init(&tg->tg_threads);
  sc_dlist_init(&tg->tg_affinity_stack);
  tg->tg_log_level = attr->log_level;
  sc_dlist_init(&tg->tg_unpreped_nodes);
  SC_TEST(pthread_mutex_init(&tg->tg_mutex, NULL) == 0);
  SC_TEST(pthread_cond_init(&tg->tg_cond, NULL) == 0);
  tg->tg_run_invoked = false;

  SC_TEST(pthread_mutex_lock(&global_mutex) == 0);

  static int session_ids;
  tg->tg_id = session_ids++;
  if( all_sessions.next == NULL )
    sc_dlist_init(&all_sessions);
  sc_dlist_push_tail(&all_sessions, &(tg->tg_all_sessions_link));

  if( tg->tg_id == 0 ) {
    sc_info(tg, "SolarCapture %s.  (ef_vi %s)\n"
            "\tCopyright (c) 2012-2025 Advanced Micro Devices, Inc.\n",
            SC_VER, COMPILED_EF_VI_VERSION );
    const char* src_id = "%{SC_SRC_ID}"; /* replaced by packaging script */
    sc_trace(tg, "%s: src_id=%s\n", __func__, src_id);
#ifndef NDEBUG
    sc_info(tg, "%s: DEBUG build\n", __func__);
#endif
  }
  int rc = sc_stats_new_session(tg, attr);
  SC_TEST(pthread_mutex_unlock(&global_mutex) == 0);
  if( rc == 0 ) {
    *tg_out = tg;
  }
  else {
    free(tg);
  }
  return rc;
}


int sc_thread_add_mailbox(struct sc_thread* t, struct sc_mailbox* mb)
{
  if( mb->mb_stats->managed ) {
    SC_REALLOC(&t->mailboxes, t->n_mailboxes + 1);
    t->mailboxes[t->n_mailboxes] = mb;
    ++t->n_mailboxes;
  }
  return 0;
}


static inline void __sc_thread_poll_timers(struct sc_thread* thread,
                                           int* did_something)
{
  struct sc_callback_impl* cbi;
  while( (cbi = sc_thread_timer_head(thread), 1) &&
         sc_timespec_le(cbi->cbi_timer_expiry, thread->cur_time) ) {
    assert(cbi != &(thread->timers));
    sc_dlist_remove(&cbi->cbi_public.cb_link);
    sc_dlist_init(&cbi->cbi_public.cb_link);
    switch( cbi->cbi_type ) {
    case evt_timer:
      sc_callback_call(&(cbi->cbi_public), thread, "timeout");
      *did_something = 1;
      break;
    case evt_pool_threshold:
      if( sc_pkt_pool_callback_check(cbi) )
        *did_something = 1;
      break;
    default:
      SC_TEST(0);
      break;
    }
  }
}


int sc_thread_poll_timers(struct sc_thread* thread)
{
  SC_TRY( clock_gettime(CLOCK_REALTIME, &thread->cur_time) );
  int did_something = 0;
  __sc_thread_poll_timers(thread, &did_something);
  return did_something;
}


int sc_thread_poll(struct sc_thread* thread)
{
  /* Do work.
   *
   * It is important that we push packets through the node graph
   * immediately before polling timers.  This is necessary to ensure that
   * packets are handled ahead of end-of-stream indications (which are
   * propagated via a timer callback that is scheduled 1ns after the
   * end-of-stream indication hits a node).
   */
  struct sc_node_impl* ni;
  int i, did_something = 0;

  TRY(clock_gettime(CLOCK_REALTIME, &thread->cur_time));

  /* Poll VIs for network events. */
  for( i = 0; i < thread->n_vis; ++i ) {
    struct sc_ef_vi* vi = thread->vis[i];
    sc_ef_vi_poll(vi);
    ni = vi->vi_recv_node;
    if( ni != NULL && ! sc_packet_list_is_empty(&ni->ni_pkt_list) ) {
      sc_node_dispatch(ni);
      sc_dlist_remove(&ni->ni_dispatch_link);
      sc_dlist_init(&ni->ni_dispatch_link);
      did_something = 1;
    }
  }

  /* Poll mailboxes for messages from other threads. */
  for( i = 0; i < thread->n_mailboxes; ++i ) {
    struct sc_mailbox* mb = thread->mailboxes[i];
    if( sc_mailbox_poll(mb, &(mb->mb_recv_node->ni_pkt_list)) ) {
      ni = thread->mailboxes[i]->mb_recv_node;
      assert(ni != NULL);
      assert(!sc_packet_list_is_empty(&ni->ni_pkt_list));
      sc_dlist_remove(&ni->ni_dispatch_link);
      sc_dlist_init(&ni->ni_dispatch_link);
      sc_node_dispatch(ni);
      did_something = 1;
    }
  }

  /* Push packets through the node graph. */
  while( ! sc_dlist_is_empty(&thread->dispatch_list) ) {
    ni = SC_CONTAINER(typeof(*ni), ni_dispatch_link,
                      sc_dlist_pop_head(&thread->dispatch_list));
    sc_dlist_init(&ni->ni_dispatch_link);
    sc_node_dispatch(ni);
    did_something = 1;
  }

  /* Poll timers. */
  __sc_thread_poll_timers(thread, &did_something);

  if( ! did_something && ! sc_dlist_is_empty(&thread->idle_callbacks) ) {
    /* Fire a single idle event per poll iteration. */
    struct sc_callback_impl* cbi =
      SC_CALLBACK_IMPL_FROM_LINK(sc_dlist_pop_head(&thread->idle_callbacks));
    sc_dlist_init(&cbi->cbi_public.cb_link);
    sc_callback_call(&(cbi->cbi_public), thread, "idle");
  }

  thread->last_poll_did_something = did_something;
  return did_something;
}


static void sc_thread_state_set(struct sc_thread* t,
                                enum sc_thread_state new_state)
{
  struct sc_session* scs = t->session;
  SC_TEST(sc_thread_current == t);
  SC_TEST(pthread_mutex_lock(&scs->tg_mutex) == 0);
  pthread_cond_t* cond;
  cond = (new_state == SC_THRD_STATE_STOP) ? &scs->tg_cond : &t->cond;
  t->cfg->state = new_state;
  /* We must not dereference [t] after this point if stopping. */
  SC_TEST(pthread_mutex_unlock(&scs->tg_mutex) == 0);
  SC_TEST(pthread_cond_broadcast(cond) == 0);
}


static void* sc_thread_fn(void* arg)
{
  struct sc_thread* t = arg;
  struct sc_session* scs = t->session;
  SC_TEST(sc_thread_current == NULL);
  sc_thread_current = t;
  sc_thread_state_set(t, SC_THRD_STATE_INITIALISING);
  sc_trace(scs, "%s: [%d:%s]\n", __func__, t->id, t->name);
  if( t->affinity >= 0 )
    TRY(sc_affinity_set(t->affinity));

  while( t->cfg->state_requested != SC_THRD_STATE_STOP ) {
    switch( t->cfg->state_requested ) {
    case SC_THRD_STATE_RUN:
      sc_thread_state_set(t, SC_THRD_STATE_RUN);
      /* Poll timers first so that nodes can set a callback that is invoked
       * after prep but before packets arrive.
       */
      sc_thread_poll_timers(t);
      while( t->cfg->state_requested == SC_THRD_STATE_RUN )
        sc_thread_poll(t);
      break;
    case SC_THRD_STATE_PAUSE:
      sc_thread_state_set(t, SC_THRD_STATE_PAUSE);
      SC_TEST(pthread_mutex_lock(&scs->tg_mutex) == 0);
      while( t->cfg->state_requested == SC_THRD_STATE_PAUSE )
        SC_TEST(pthread_cond_wait(&t->cond, &scs->tg_mutex) == 0);
      SC_TEST(pthread_mutex_unlock(&scs->tg_mutex) == 0);
      break;
    case SC_THRD_STATE_STOP:
      break;
    }
  }
  sc_thread_state_set(t, SC_THRD_STATE_STOP);
  return NULL;
}


static void __sc_thread_state_wait(struct sc_thread* t)
{
  /* Wait for thread [t] to reach its target state. */
  struct sc_session* scs = t->session;
  SC_TEST(sc_thread_current != t);
  SC_TEST(pthread_mutex_trylock(&scs->tg_mutex) == EBUSY);
  pthread_cond_t* cond;
  cond = (t->cfg->state_requested == SC_THRD_STATE_STOP) ?
    &scs->tg_cond : &t->cond;
  while( t->cfg->state != t->cfg->state_requested )
    SC_TEST(pthread_cond_wait(cond, &scs->tg_mutex) == 0);
}


static void sc_thread_state_request(struct sc_thread* t,
                                    enum sc_thread_state new_state,
                                    bool wait)
{
  struct sc_session* scs = t->session;
  SC_TEST(pthread_mutex_lock(&scs->tg_mutex) == 0);
  t->cfg->state_requested = new_state;
  switch( t->cfg->state ) {
  case SC_THRD_STATE_STOP:
    if( new_state != SC_THRD_STATE_STOP ) {
      if( t->wakeup_cb != NULL ) {
        uint64_t v;
        /* Explicilty discarding result - we're just attempting to notify
         * and if they've stopped waiting, that's ok. */
        (void) read(t->wakeup_eventfd, &v, 8);
      }
      SC_TEST(pthread_create(&t->pthread_id, NULL, sc_thread_fn, t) == 0);
      SC_TEST(pthread_detach(t->pthread_id) == 0);
    }
    break;
  case SC_THRD_STATE_RUN:
    if( t->wakeup_cb != NULL )
      /* Thread may be blocked in epoll_wait(). */
      sc_thread_wake(t);
    break;
  default:
    /* Thread probably blocked waiting for state change. */
    SC_TEST(pthread_cond_broadcast(&t->cond) == 0);
    break;
  }
  if( wait )
    __sc_thread_state_wait(t);
  SC_TEST(pthread_mutex_unlock(&scs->tg_mutex) == 0);
}


static void sc_thread_free(struct sc_thread* t)
{
  /* WARNING: Currently only suitable to be called from
   * sc_session_destroy().  Assumes thread is stopped and removed from
   * tg_threads.
   */

  sc_trace(t->session, "%s:\n", __func__);
  SC_TEST(t->cfg->state == SC_THRD_STATE_STOP);

  struct sc_session* scs = t->session;
  int rc = munmap(t->stats_header, scs->tg_stats_file_size);
  if( rc < 0 )
    sc_err(scs, "%s: ERROR: munmap failed (errno=%d)", __func__, errno);

  /* ?? TODO: Many more resources to free here! */
  free(t->name);
  sc_attr_free(t->attr);

  /* WARNING: This also frees [t] since it is allocated from [t->ma]. */
  sc_allocator_free(t->ma);
  /* Don't put anything here!! */
}


static void sc_thread_on_idle(struct sc_callback* cb, void* event_info)
{
  struct sc_thread* t = event_info;
  ++(t->idle_stats->idle_loops);
  sc_callback_on_idle(cb);
}


static void sc_thread_wakeup_cb(struct sc_callback* cb, void* event_info)
{
  struct sc_thread* t = cb->cb_private;
  uint64_t v;
  SC_TEST( read(t->wakeup_eventfd, &v, 8) == 8 );
  t->cfg->wakes += v;
  ++(t->cfg->woken);
}


static void sc_thread_wakeup_cb_level_triggered(struct sc_callback* cb,
                                                void* event_info)
{
  /* Used when sc_thread_waitable_fd_get has been called in level-triggered
   * mode.  We do not want to read() the eventfd because that would allow
   * the epollfd to become unready.
   */
}


static int sc_thread_set_non_busy_wait(struct sc_thread* thread)
{
  int rc;
  SC_TEST(thread->wakeup_cb == NULL);
  SC_TEST(thread->epoll_idle_cb == NULL);
  /* NB. EFD_NONBLOCK only since Linux 2.6.27, so don't use it. */
  thread->wakeup_eventfd = eventfd(0, 0);
  if( thread->wakeup_eventfd < 0 )
    return sc_set_err(sc_thread_get_session(thread),
                      errno, "%s: eventfd() failed", __func__);
  SC_TRY( fcntl(thread->wakeup_eventfd, F_SETFL, O_NONBLOCK) );
  SC_TRY( sc_callback_alloc2(&thread->wakeup_cb, NULL,
                             thread, "thread_wakeup") );
  thread->wakeup_cb->cb_private = thread;
  thread->wakeup_cb->cb_handler_fn = sc_thread_wakeup_cb;
  if( (rc = sc_epoll_ctl(thread, EPOLL_CTL_ADD, thread->wakeup_eventfd,
                         EPOLLIN, thread->wakeup_cb)) < 0 )
    return rc;
  if( thread->idle_cb != NULL )
    sc_callback_remove(thread->idle_cb);
  if( ! thread->cfg->managed && thread->epoll_timer_cb != NULL )
      sc_callback_remove(thread->epoll_timer_cb);
  return 0;
}


bool sc_thread_has_ready_mailbox(struct sc_thread* t)
{
  /* NB. It is not necessary to look at other aspects of mailbox state
   * here, such as the send queue or recv backlog.  All we want to know is
   * whether we have new information from the peer.
   */
  int i;
  for( i = 0; i < t->n_mailboxes; ++i ) {
    struct sc_mailbox* mb = t->mailboxes[i];
    if( mb->mb_recv_slot_v != mb->mb_recv_slot.v )
      return true;
  }
  return false;
}


int sc_thread_alloc(struct sc_thread** sc_t, const struct sc_attr* attr,
                    struct sc_session* tg)
{
  int rc = sc_affinity_save_and_set(tg, attr->affinity_core);
  if( rc < 0 )
    return rc;

  struct sc_allocator* ma;
  sc_allocator_alloc(&ma);
  struct sc_thread* t = sc_allocator_calloc(ma, sizeof(struct sc_thread));
  TEST(t);
  t->ma = ma;
  /* t->last_poll_did_something = 0; */
  t->id = tg->tg_threads_n++;
  t->affinity = attr->affinity_core;
  t->session = tg;
  sc_dlist_init(&t->dispatch_list);
  sc_dlist_init(&t->idle_callbacks);
  TRY(clock_gettime(CLOCK_REALTIME, &t->cur_time));
  t->epoll_fd = -1;
  t->timerfd = -1;
  /* t->timerfd_cb = NULL; */
  /* t->wakeup_cb = NULL; */
  t->wakeup_eventfd = -1;
  /* t->is_sleeping = 0; */
  SC_TEST(pthread_cond_init(&t->cond, NULL) == 0);
  SC_TEST( t->attr = sc_attr_dup(attr) );

  /* The head of the list has a time far in the future. */
  t->timers.cbi_timer_expiry.tv_sec = LONG_MAX;
  TEST(sizeof(t->timers.cbi_timer_expiry.tv_sec) == sizeof(long));
  TEST(t->timers.cbi_timer_expiry.tv_sec == LONG_MAX);
  sc_dlist_init(&t->timers.cbi_public.cb_link);

  if( attr->name == NULL )
    TEST(asprintf(&t->name, "sc_thread(%d)", t->id) > 0);
  else
    t->name = strdup(attr->name);

  struct sc_thread_stats* cfg;
  TRY(sc_stats_add_block(t, t->name, "sc_thread_stats", "t", t->id,
                         sizeof(*cfg), &cfg));
  if( attr->group_name != NULL )
    sc_stats_add_info_str(tg, "t", t->id, "group_name", attr->group_name);
  cfg->id = t->id;
  cfg->affinity = attr->affinity_core;
  cfg->managed = attr->managed;
  cfg->fd_poll_max_events = attr->fd_poll_max_events;
  cfg->fd_poll_nanos =
    SC_ATTR_GET_INT_ALT(attr, fd_poll_nanos, batch_timeout_nanos);
  if( cfg->fd_poll_nanos <= 0 )
    cfg->fd_poll_nanos = 1;
  cfg->state_requested = SC_THRD_STATE_STOP;
  cfg->state = SC_THRD_STATE_STOP;
  t->cfg = cfg;

  if( ! attr->busy_wait ) {
    if( ! cfg->managed )
      return sc_set_err(tg, EINVAL, "ERROR: %s: busy_wait=0 is not supported "
                        "for unmanaged threads\n", __func__);
    if( (rc = sc_thread_set_non_busy_wait(t)) < 0 ) {
      sc_allocator_mfree(ma, t);
      sc_allocator_free(ma);
      return rc;
    }
  }

  sc_dlist_push_tail(&tg->tg_threads, &t->session_link);
  *sc_t = t;
  TRY(sc_affinity_restore(tg));
  sc_trace(tg, "%s: name=%s\n", __func__, t->name);

  if( attr->idle_monitor && attr->busy_wait ) {
    SC_TRY( sc_callback_alloc2(&t->idle_cb, attr, t, NULL) );
    t->idle_cb->cb_private = t;
    t->idle_cb->cb_handler_fn = sc_thread_on_idle;
    sc_callback_on_idle(t->idle_cb);
    TRY(sc_stats_add_block(t, t->name, "sc_idle_monitor_stats", "t", t->id,
                           sizeof(*t->idle_stats), &t->idle_stats));
  }

  return 0;
}


static void sc_thread_timerfd_arm(struct sc_thread* thread)
{
  struct itimerspec timeout;
  assert( thread->timerfd >= 0 );
  timeout.it_interval.tv_sec = 0;
  timeout.it_interval.tv_nsec = 0;
  struct sc_callback_impl* cbi = sc_thread_timer_head(thread);
  timeout.it_value.tv_sec = cbi->cbi_timer_expiry.tv_sec;
  timeout.it_value.tv_nsec = cbi->cbi_timer_expiry.tv_nsec;
  SC_TRY( timerfd_settime(thread->timerfd, TFD_TIMER_ABSTIME, &timeout, NULL) );
}


static void sc_thread_timerfd_cb(struct sc_callback* cb, void* event_info)
{
}


int sc_thread_waitable_fd_get(struct sc_thread* thread, bool edge_triggered)
{
  if( thread->cfg->managed )
    return sc_set_err(sc_thread_get_session(thread), EINVAL,
                      "%s: Requires an unmanaged thread", __func__);
  if( thread->wakeup_cb == NULL ) {
    /* First get_waitable_fd call for this thread */
    int rc, i;
    if( (rc = sc_thread_set_non_busy_wait(thread)) < 0 )
      return rc;
    for( i = 0; i < thread->n_vis; ++i )
      sc_ef_vi_set_non_busy_wait(thread->vis[i]);
    thread->timerfd = timerfd_create(CLOCK_REALTIME, 0);
    if( thread->timerfd < 0 )
      return sc_set_err(thread->session, errno,
                        "ERROR: %s: timerfd_create failed (errno=%d)\n",
                        __func__, errno);
    SC_TRY( sc_callback_alloc2(&thread->timerfd_cb, NULL,
                               thread, "waitable_timer") );
    thread->timerfd_cb->cb_private = thread;
    thread->timerfd_cb->cb_handler_fn = sc_thread_timerfd_cb;
    sc_epoll_ctl(thread, EPOLL_CTL_ADD, thread->timerfd, EPOLLIN,
                 thread->timerfd_cb);
    /* We need to ensure that any timers we have already scheduled get handled.
     */
    sc_thread_timerfd_arm(thread);
    if( ! edge_triggered ) {
      thread->wakeup_cb->cb_handler_fn = sc_thread_wakeup_cb_level_triggered;
      sc_thread_wake(thread);
    }
  }
  SC_TEST(thread->epoll_fd >= 0);
  return thread->epoll_fd;
}


void sc_thread_waitable_fd_prime(struct sc_thread* thread)
{
  assert( ! thread->cfg->managed );
  assert( thread->wakeup_cb != NULL );
  assert( thread->epoll_fd >= 0 );

  if( thread->wakeup_cb->cb_handler_fn
      == sc_thread_wakeup_cb_level_triggered ) {
    if( thread->last_poll_did_something ) {
      /* The last sc_thread_poll() call did something, so we can't be sure
       * there isn't more work outstanding within the node graph.  Return
       * without doing anything, so the fd will remain readable.
       */
      assert( sc_fd_is_readable(thread->wakeup_eventfd) );
      return;
    }
    /* Allow the epollfd to become unready.  (In edge-triggered mode
     * sc_epoll_wait() will have invoked sc_thread_wakeup_cb() already via
     * sc_thread_poll(), which resets the eventfd).
     */
    uint64_t v;
    if( read(thread->wakeup_eventfd, &v, 8) == 8 ) {
      thread->cfg->wakes += v;
      ++(thread->cfg->woken);
    }
  }

  thread->is_sleeping = 1;
  sc_slb();
  if( sc_thread_has_ready_mailbox(thread) )
    /* There is outstanding work to do, so we *must* ensure the waitable fd
     * is readable.
     */
    sc_thread_wake(thread);

  int i;
  for( i = 0; i < thread->n_vis; ++i )
    sc_ef_vi_about_to_sleep(thread->vis[i]);

  /* Remove our epoll timer else it is likely to determine the timerfd
   * timeout!
   */
  sc_callback_remove(thread->epoll_timer_cb);
  sc_thread_timerfd_arm(thread);

  /* Ensures that once our epollfd becomes readable and app calls
   * sc_thread_poll(), this callback will reinstate periodic polling of
   * sc_epoll_wait().
   */
  if( thread->wakeup_cb->cb_handler_fn == sc_thread_wakeup_cb_level_triggered )
    thread->epoll_timer_cb->cb_handler_fn = sc_epoll_restart_after_lt_prime;
  sc_callback_at_safe_time(thread->epoll_timer_cb);
}


struct sc_session* sc_thread_get_session(const struct sc_thread* t)
{
  return t->session;
}


void sc_thread_get_time(const struct sc_thread* t,
                        struct timespec* time_out)
{
  /* ?? todo: assert unmanaged or running */
  *time_out = t->cur_time;
}


void sc_thread_add_vi(struct sc_thread* t, struct sc_ef_vi* vi)
{
  SC_REALLOC(&t->vis, t->n_vis + 1);
  t->vis[t->n_vis] = vi;
  ++t->n_vis;
}


static int can_share_pool(const struct sc_pkt_pool* pp,
                          const struct sc_thread* thread,
                          const struct sc_attr* attr)
{
  if( pp->pp_thread != thread )
    return 0;
  if( pp->pp_private )
    return 0;
  if( attr->buf_size > 0 &&
      (pp->pp_buf_size < attr->buf_size ||
       pp->pp_buf_size > attr->buf_size * 2) )
    return 0;
  if( attr->buf_inline >= 0 && pp->pp_is_inline != !!attr->buf_inline )
    return 0;
#if 0
  if( attr->buf_align > 0 && pp->pp_align < attr->buf_align )
    return 0;
#endif
  return 1;
}


static struct sc_pkt_pool* sc_thread_find_pool(struct sc_thread* t,
                                               const struct sc_netif* netif,
                                               const struct sc_attr* attr)
{
  struct sc_session* tg = t->session;
  int pp_id;
  for( pp_id = 0; pp_id < tg->tg_pkt_pools_n; ++pp_id ) {
    struct sc_pkt_pool* pp = tg->tg_pkt_pools[pp_id];
    if( can_share_pool(pp, t, attr) &&
        ( netif == NULL || (pp->pp_netifs & (1llu << netif->netif_id)) ) )
      return pp;
  }
  return NULL;
}


static struct sc_pkt_pool* sc_thread_alloc_pool(struct sc_thread* t,
                                                const struct sc_attr* attr,
                                                struct sc_netif* netif)
{
  struct sc_pkt_pool* pp;
  sc_pkt_pool_alloc(&pp, attr, t);
  if( netif != NULL )
    sc_pkt_pool_add_netif(pp, netif);

  /* We allocate a refill node for each packet pool. */

  struct sc_object* ppo;
  SC_TEST( sc_opaque_alloc(&ppo, pp) == 0 );
  struct sc_arg args[] = { SC_ARG_OBJ("pool", ppo) };

  struct sc_node* refill;
  TRY(sc_node_alloc(&refill, attr, pp->pp_thread,
                    &sc_refill_node_factory, args, 1));
  sc_opaque_free(ppo);
  return pp;
}


void sc_thread_get_pool(struct sc_thread* t, const struct sc_attr* attr_opt,
                        struct sc_netif* netif, struct sc_pkt_pool** pool_out)
{
  struct sc_attr* attr = (void*) attr_opt;  /* cast away const */
  struct sc_pkt_pool* pp;

  if( attr_opt == NULL )
    TRY(sc_attr_alloc(&attr));

  if( attr->private_pool ) {
    pp = sc_thread_alloc_pool(t, attr, netif);
    assert(pp->pp_private == 1);
  }
  else {
    pp = sc_thread_find_pool(t, netif, attr);
    if( pp == NULL )
      pp = sc_thread_alloc_pool(t, attr, netif);
  }
  *pool_out = pp;

  if( attr_opt == NULL )
    sc_attr_free(attr);
}


static struct sc_node_impl* sc_find_node_to_prep(struct sc_session* tg,
                                                 int free_path)
{
  struct sc_node_impl* ni_with_unpreped_subnode = NULL;
  struct sc_node_impl* ni;
  SC_DLIST_FOR_EACH_OBJ(&tg->tg_unpreped_nodes, ni, ni_link) {
    sc_trace(tg, "%s: node(%d,%s) state=%d n_in=%d n_preped=%d\n",
             __func__, ni->ni_id, ni->ni_node.nd_type->nt_name, ni->ni_state,
             ni->ni_n_incoming_links, ni->ni_n_incoming_links_preped);
    TEST(ni->ni_state == SC_NODE_INITED);
    if( (ni->ni_n_incoming_links || ! ni->ni_node.nd_type->nt_pkts_fn) &&
        ni->ni_n_incoming_links_preped == ni->ni_n_incoming_links &&
        ni->ni_stats->is_free_path == free_path ) {
      if( sc_node_subnodes_are_preped(ni) ) {
        sc_dlist_remove(&ni->ni_link);
        return ni;
      }
      else if( ni_with_unpreped_subnode == NULL ) {
        ni_with_unpreped_subnode = ni;
      }
    }
  }
  if( ni_with_unpreped_subnode != NULL )
    sc_dlist_remove(&ni_with_unpreped_subnode->ni_link);
  return ni_with_unpreped_subnode;
}


static struct sc_mailbox*
  sc_thread_find_unused_mailbox(struct sc_thread* t, struct sc_thread* remote,
                                int pp_id)
{
  /* Find a mailbox connecting [t] to [remote] that is unused.  ie. No
   * nodes connect in on the local send side, and not connected on the
   * remove receive side.
   *
   * If [pp_id >= 0] that indicates that we're only interested in a mailbox
   * that is handling packets from the given pool (in the opposite
   * direction of course).
   */
  struct sc_mailbox *lmb, *rmb;
  int mb_i;

  for( mb_i = 0; mb_i < t->n_mailboxes; ++mb_i ) {
    lmb = t->mailboxes[mb_i];
    if( sc_bitmask_ffs(&lmb->mb_send_node.ni_src_pools) != 0 )
      continue;
    if( sc_mailbox_get_remote_thread(lmb) == remote ) {
      rmb = sc_mailbox_get_peer(lmb);
      if( rmb->mb_recv_node == NULL )
        if( (pp_id < 0) ||
            sc_bitmask_is_set(&rmb->mb_send_node.ni_src_pools, pp_id) )
          return lmb;
    }
  }
  return NULL;
}


static struct sc_node_impl*
  sc_thread_find_remote_freer(struct sc_thread* t, struct sc_pkt_pool* pp)
{
  /* Find the mailbox sender node that returns packets to the given packet
   * pool (which must be in another thread).
   *
   * Return NULL if none found.
   */
  struct sc_mailbox *lmb, *rmb;
  int mb_i;

  TEST( pp->pp_thread != t );

  for( mb_i = 0; mb_i < t->n_mailboxes; ++mb_i ) {
    lmb = t->mailboxes[mb_i];
    if( sc_mailbox_get_remote_thread(lmb) != pp->pp_thread )
      continue;
    rmb = sc_mailbox_get_peer(lmb);
    if( rmb->mb_recv_node == pp->pp_refill_node )
      return &(lmb->mb_send_node);
  }
  return NULL;
}


static struct sc_node_impl*
  sc_thread_get_remote_freer(struct sc_thread* t, struct sc_pkt_pool* pp)
{
  struct sc_node_impl* ni;
  struct sc_mailbox* lmb;
  struct sc_mailbox* rmb;

  if( (ni = sc_thread_find_remote_freer(t, pp)) != NULL ) {
    sc_trace(t->session, "%s: pool=%d via n%d/%s[%s] (existing)\n", __func__,
             pp->pp_id, ni->ni_id, ni->ni_node.nd_type->nt_name,
             ni->ni_node.nd_name);
    return ni;
  }

  /* No existing path, so create one.  Try to find an unused mailbox
   * handling packets (in the other direction) for the same pool.  This is
   * better than an unrelated mailbox because it increases the chances of
   * acks being carried by messages.
   *
   * Otherwise pick any unused mailbox.  (NB. This is not ideal, because we
   * may pick a mailbox that would have been better used for a different
   * node to free via.  That can be improved, but is a little fiddly).
   */
  lmb = sc_thread_find_unused_mailbox(t, pp->pp_thread, pp->pp_id);
  if( lmb == NULL )
    lmb = sc_thread_find_unused_mailbox(t, pp->pp_thread, -1);
  const char* mbox_is = "existing";
  if( lmb == NULL ) {
    TRY(sc_mailbox_alloc(&lmb, t->attr, t));
    TRY(sc_mailbox_alloc(&rmb, pp->pp_thread->attr, pp->pp_thread));
    TRY(sc_mailbox_connect(lmb, rmb));
    sc_trace(t->session, "%s: [%s] pool %d via new mailbox %d\n", __func__,
             t->name, pp->pp_id, lmb->mb_id);
    mbox_is = "new";
  }
  sc_trace(t->session, "%s: t%d => t%d/p%d via %s mailbox m%d\n", __func__,
           t->id, pp->pp_thread->id, pp->pp_id, mbox_is, lmb->mb_id);

  lmb->mb_send_node.ni_stats->is_free_path = 1;

  rmb = sc_mailbox_get_peer(lmb);
  TRY( sc_mailbox_set_recv(rmb, &pp->pp_refill_node->ni_node, NULL) );
  /* Limiting recv_max_pkts can cause the free path to back-up (see
   * bug61507), so override here.  I don't think it is ever helpful to
   * batch here.
   */
  rmb->mb_stats->recv_max_pkts = INT_MAX;
  /* If re-using an existing mailbox, set send-side batching from the
   * thread's attributes.  (We want consistent behaviour whether the
   * mailbox is allocated here or scavenged).
   */
  sc_mailbox_set_batching_send(lmb, t->attr);

  ni = &lmb->mb_send_node;
  TEST(sc_thread_find_remote_freer(t, pp) == ni);
  sc_trace(t->session, "%s: pool=%d via n%d/%s[%s]\n", __func__,
           pp->pp_id, ni->ni_id, ni->ni_node.nd_type->nt_name,
           ni->ni_node.nd_name);
  return ni;
}


static struct sc_node_impl*
  sc_thread_setup_free_demux(struct sc_thread* t,
                             const struct sc_bitmask* pools)
{
  struct sc_session* tg = t->session;

  if( t->free_demux_node == NULL ) {
    struct sc_node* node;
    TRY(sc_node_alloc(&node, t->attr, t, &sc_free_demux_node_factory, NULL, 0));
    t->free_demux_node = SC_NODE_IMPL_FROM_NODE(node);
  }

  struct sc_node* fdm_node = &t->free_demux_node->ni_node;
  struct sc_free_demux* fdm = fdm_node->nd_private;

  int pp_id;
  for( pp_id = 0; pp_id < tg->tg_pkt_pools_n; ++pp_id ) {
    if( ! sc_bitmask_is_set(pools, pp_id) )
      continue;
    if( pp_id < fdm->len && fdm->pp_id_to_link[pp_id] != NULL )
      continue;
    struct sc_pkt_pool* pp = tg->tg_pkt_pools[pp_id];
    struct sc_node_impl* ni;
    if( pp->pp_thread == t )
      ni = pp->pp_refill_node;
    else
      /* This is the easiest solution, but it could lead to lots of
       * mailboxes in some scenarios.  Solution would be to create a single
       * mailbox to an sc_free_demux_node in the target thread.
       */
      ni = sc_thread_get_remote_freer(t, pp);
    char lname[11];
    sprintf(lname, "%d", pp_id);
    __sc_node_add_link(SC_NODE_IMPL_FROM_NODE(fdm_node), lname, ni, NULL);
    struct sc_node_link_impl* nl = sc_node_find_link(fdm_node, lname);
    if( pp_id >= fdm->len ) {
      SC_REALLOC(&(fdm->pp_id_to_link), pp_id + 1);
      memset(fdm->pp_id_to_link + fdm->len, 0,
             (pp_id + 1 - fdm->len) * sizeof(fdm->pp_id_to_link[0]));
      fdm->len = pp_id + 1;
    }
    fdm->pp_id_to_link[pp_id] = &nl->nl_public;
    sc_bitmask_clear_all(&nl->nl_pools);
    sc_bitmask_set(&nl->nl_pools, pp_id);
  }

  struct sc_node_impl* ni = t->free_demux_node;
  sc_trace(tg, "%s: pools=(%s) via n%d/%s[%s]\n", __func__,
           sc_bitmask_fmt(pools), ni->ni_id, ni->ni_node.nd_type->nt_name,
           ni->ni_node.nd_name);
  return ni;
}


void sc_setup_pkt_free(struct sc_session* tg, struct sc_node_impl** p_ni,
                       struct sc_thread* thread,
                       const struct sc_bitmask* pools)
{
  int pp_id = sc_bitmask_ffs(pools) - 1;
  TEST(pp_id >= 0);
  TEST(pp_id < tg->tg_pkt_pools_n);
  if( sc_bitmask_is_single_bit(pools, pp_id) ) {
    /* This link frees packets to a single pool. */
    struct sc_pkt_pool* pp = tg->tg_pkt_pools[pp_id];
    if( pp->pp_thread == thread ) {
      *p_ni = pp->pp_refill_node;
      sc_trace(tg, "%s: pool=%d via n%d/%s[%s] (direct)\n", __func__,
               pp->pp_id, (*p_ni)->ni_id, (*p_ni)->ni_node.nd_type->nt_name,
               (*p_ni)->ni_node.nd_name);
    }
    else {
      *p_ni = sc_thread_get_remote_freer(thread, pp);
    }
  }
  else {
    /* This link frees packets to multiple pools. */
    struct sc_bitmask threads_bm;
    sc_pools_to_threads(tg, pools, &threads_bm);
    int t_id = sc_bitmask_ffs(&threads_bm) - 1;
    TEST(t_id >= 0);
    TEST(t_id < tg->tg_threads_n);
    *p_ni = sc_thread_setup_free_demux(thread, pools);
    sc_bitmask_free(&threads_bm);

    /* TODO: This is not always ideal.  In some scenarios we'll create more
     * mailboxes than are needed, which has a cost.  eg. If multiple pools
     * this link frees to are in a single remote thread, we could pass them
     * all through a single mailbox to a demuxer in the remote thread.  We
     * could test for that case with:
     *
     * if( threads == (1llu << t_id) && t_id != thread->id )
     *
     * (But this is not necessarily an improvement -- it depends on where
     * you'd prefer to do the demux work).
     */
  }
  ++((*p_ni)->ni_n_incoming_links);
}


void sc_node_link_setup_pkt_free(struct sc_node_link_impl* nl)
{
  struct sc_node_impl* ni = nl->nl_from_node;
  struct sc_session* tg = ni->ni_thread->session;

  sc_trace(tg, "%s: %s/%s frees to pools (%s)\n", __func__,
           ni->ni_node.nd_name, nl->nl_public.name,
           sc_bitmask_fmt(&nl->nl_pools));

  assert( nl->nl_to_node == NULL );
  TEST( sc_bitmask_ffs(&nl->nl_pools) > 0 );

  sc_setup_pkt_free(tg, &nl->nl_to_node, ni->ni_thread, &nl->nl_pools);
}


static void sc_session_propagate_paths(struct sc_session* tg)
{
  /* < n_incoming_links: Node is not ready to be processed
   * = n_incoming_links: Node is ready to be processed
   * > n_incoming_links: Node has already been processed */
  int n_in_links_processed[tg->tg_nodes_n];
  unsigned i, j, n_processed_nodes = 0;
  memset(n_in_links_processed, 0, sizeof(n_in_links_processed));
  sc_trace(tg, "%s\n", __func__);

  /* VIs are counted in ni_n_incoming_links, but we do not care about
   * them here so we increment n_in_links_processed for nodes which
   * are fed by them. */
  for( i = 0; i < tg->tg_vis_n; ++i )
    if( tg->tg_vis[i]->vi_recv_node != NULL )
      ++n_in_links_processed[tg->tg_vis[i]->vi_recv_node->ni_id];

  /* For each node, this block sets ni_src_nodes to the set of nodes from
   * which there is a path to this node. */
  while( n_processed_nodes < tg->tg_nodes_n ) {
    unsigned old_processed = n_processed_nodes;
    for( i = 0; i < tg->tg_nodes_n; ++i ) {
      struct sc_node_impl* src = tg->tg_nodes[i];
      SC_TEST( src->ni_id == i );
      if( n_in_links_processed[i] == src->ni_n_incoming_links ) {
        ++n_processed_nodes;
        ++n_in_links_processed[i]; /* Marks this node as processed */
        for( j = 0; j < src->ni_n_links; ++j ) {
          struct sc_node_impl* dst = src->ni_links[j]->nl_to_node;
          ++n_in_links_processed[dst->ni_id];
          sc_bitmask_or(&dst->ni_src_nodes, &src->ni_src_nodes);
          sc_bitmask_set(&dst->ni_src_nodes, src->ni_id);
        }
        if( src->ni_node.nd_type == &sc_mailbox_send_node_type ) {
          struct sc_mailbox* mb = SC_MAILBOX_FROM_NODE_IMPL(src);
          struct sc_mailbox* rmb = sc_mailbox_get_peer(mb);
          if( rmb != NULL && rmb->mb_recv_node != NULL ) {
            ++n_in_links_processed[rmb->mb_recv_node->ni_id];
            sc_bitmask_or(&rmb->mb_recv_node->ni_src_nodes, &src->ni_src_nodes);
            sc_bitmask_set(&rmb->mb_recv_node->ni_src_nodes, src->ni_id);
          }
        }
      }
    }
    if( n_processed_nodes == old_processed ) {
      sc_err(tg, "%s: ERROR: node graph contains a loop\n", __func__);
      SC_TEST( n_processed_nodes > old_processed );
    }
  }

  /* For each node, this block determines whether it is reachable from
   * its parent node, or any node which is a parent of its parent. */
  for( i = 0; i < tg->tg_nodes_n; ++i ) {
    struct sc_node_impl* ni = tg->tg_nodes[i];
    struct sc_node_impl* parent;
    struct sc_bitmask ancestors;

    sc_bitmask_init(&ancestors);
    for( parent = ni->ni_parent_node; parent ; parent = parent->ni_parent_node )
      sc_bitmask_set(&ancestors, parent->ni_id);

    sc_bitmask_and(&ancestors, &ni->ni_src_nodes);
    ni->ni_reachable_from_ancestor = sc_bitmask_ffs(&ancestors) > 0;
    sc_bitmask_free(&ancestors);
    sc_trace(tg, "  %s: ni_id=%d src_nodes=%s reachable=%d\n",
             ni->ni_node.nd_name, i, sc_bitmask_fmt(&ni->ni_src_nodes),
             ni->ni_reachable_from_ancestor);
  }
}


static int sc_session_prep_nodes(struct sc_session* tg)
{
  struct sc_node_impl* ni;
  int rc, vi_id;

  /* For each node, determine which other nodes have a path to it */
  sc_session_propagate_paths(tg);

  sc_trace(tg, "%s: propagate from VIs\n", __func__);

  struct sc_bitmask pools;
  sc_bitmask_init(&pools);
  /* Propagate packet pools from VIs to nodes. */
  for( vi_id = 0; vi_id < tg->tg_vis_n; ++vi_id ) {
    struct sc_ef_vi* vi = tg->tg_vis[vi_id];
    if( vi->vi_recv_node != NULL ) {
      sc_bitmask_clear_all(&pools);
      if( vi->packed_stream_mode )
        sc_bitmask_set(&pools, vi->packed_stream_vi->ref_pkt_pool->pp_id);
      else
        sc_bitmask_set(&pools, vi->pkt_pool->pp_id);
      sc_node_propagate_pools(vi->vi_recv_node, &pools);
    }
  }
  sc_bitmask_free(&pools);

  /* We prep nodes that are on the free path after all other nodes.  Reason
   * is that new links can be added along the free path as we prep nodes,
   * so doing them last ensures that the dispatch_order doesn't go wrong.
   */
  sc_trace(tg, "%s: prep nodes\n", __func__);
  while( (ni = sc_find_node_to_prep(tg, 0)) != NULL )
    if( (rc = sc_node_prep(ni)) < 0 )
      return rc;
  sc_trace(tg, "%s: prep free-path nodes\n", __func__);
  while( (ni = sc_find_node_to_prep(tg, 1)) != NULL )
    if( (rc = sc_node_prep(ni)) < 0 )
      return rc;
  sc_trace(tg, "%s: prep nodes DONE\n", __func__);

  SC_DLIST_FOR_EACH_OBJ(&tg->tg_unpreped_nodes, ni, ni_link)
    sc_trace(tg, "%s: node(%d,%s) not preped\n",
             __func__, ni->ni_id, ni->ni_node.nd_type->nt_name);

  return 0;
}


static int __sc_session_prepare(struct sc_session* tg)
{
  struct sc_thread* t;
  int rc;
  int i;

  /* If we fail part way through, we are broken. */
  SC_TEST(tg->tg_state == SCS_STATE_NEW);
  tg->tg_state = SCS_STATE_BROKEN;

  sc_trace(tg, "%s:\n", __func__);

  if( tg->tg_log_level >= SC_LL_TRACE )
    sc_topology_dump(tg);

  /* Threads need to have correct time when nt_prep_fn() is invoked. */
  SC_DLIST_FOR_EACH_OBJ(&tg->tg_threads, t, session_link)
    TRY(clock_gettime(CLOCK_REALTIME, &t->cur_time));
  if( (rc = sc_session_prep_nodes(tg)) < 0 )
    return rc;

  /* For any threads that have a waitable fd, we need to make sure that any
   * timers scheduled at prep time get handled.
   */
  SC_DLIST_FOR_EACH_OBJ(&tg->tg_threads, t, session_link)
    if( t->timerfd >=0 )
      sc_thread_timerfd_arm(t);

  if( tg->tg_log_level >= SC_LL_TRACE )
    sc_topology_dump(tg);

  if( (rc = sc_topology_check(tg)) < 0 )
    return rc;

  /* Allocating buffers for packet pools */
  for( i = 0; i < tg->tg_pkt_pools_n; ++i ) {
    rc = sc_pkt_pool_alloc_bufs(tg->tg_pkt_pools[i]);
    if( rc < 0 )
      return rc;
  }

  /* Prep all VIs used for RX. This fills their RX ring.
   *
   * TODO: We should do this incrementally so all VIs get a share if we
   * only have limited buffers available.
   */
  for( i = 0; i < tg->tg_vis_n; ++i ) {
    struct sc_ef_vi* vi = tg->tg_vis[i];
    if( vi->vi_recv_node != NULL )
      sc_ef_vi_prep(vi);
  }

  tg->tg_state = SCS_STATE_READY;
  return 0;
}


int sc_session_prepare(struct sc_session* scs)
{
  struct sc_thread* t;
  int rc;

  SC_TEST( sc_thread_current == NULL );

  switch( scs->tg_state ) {
  case SCS_STATE_NEW:
    if( (rc = __sc_session_prepare(scs)) < 0 )
      return rc;
    break;
  case SCS_STATE_READY:
  case SCS_STATE_STOPPED:
    break;
  case SCS_STATE_BROKEN:
    return sc_set_err(scs, ENONET, "ERROR: session in broken state\n");
  }

  sc_trace(scs, "%s: start managed threads in paused state\n", __func__);
  SC_DLIST_FOR_EACH_OBJ(&scs->tg_threads, t, session_link)
    if( t->cfg->managed )
      sc_thread_state_request(t, SC_THRD_STATE_PAUSE, true);

  sc_trace(scs, "%s: done\n", __func__);
  return 0;
}


int sc_session_go(struct sc_session* scs)
{
  struct sc_thread* t;
  int rc;

  SC_TEST( sc_thread_current == NULL );

  switch( scs->tg_state ) {
  case SCS_STATE_NEW:
    if( (rc = __sc_session_prepare(scs)) < 0 )
      return rc;
    break;
  case SCS_STATE_READY:
  case SCS_STATE_STOPPED:
    break;
  case SCS_STATE_BROKEN:
    return sc_set_err(scs, ENONET, "ERROR: session in broken state\n");
  }

  sc_trace(scs, "%s: start managed threads\n", __func__);
  SC_DLIST_FOR_EACH_OBJ(&scs->tg_threads, t, session_link)
    if( t->cfg->managed )
      sc_thread_state_request(t, SC_THRD_STATE_RUN, true);

  sc_trace(scs, "%s: done\n", __func__);
  return 0;
}


int sc_session_pause(struct sc_session* scs)
{
  struct sc_thread* t;

  SC_TEST( sc_thread_current == NULL );

  switch( scs->tg_state ) {
  case SCS_STATE_NEW:
    return sc_set_err(scs, ENONET, "ERROR: session not yet prepared\n");
  case SCS_STATE_READY:
  case SCS_STATE_STOPPED:
    break;
  case SCS_STATE_BROKEN:
    return sc_set_err(scs, ENONET, "ERROR: session in broken state\n");
  }

  sc_trace(scs, "%s: pause managed threads\n", __func__);
  SC_DLIST_FOR_EACH_OBJ(&scs->tg_threads, t, session_link)
    if( t->cfg->managed )
      sc_thread_state_request(t, SC_THRD_STATE_PAUSE, true);
  return 0;
}


int sc_session_run(struct sc_session* scs, int* exit_code_out)
{
  /* This changes the default behaviour of the sc_exit node. */
  scs->tg_run_invoked = true;

  int rc = sc_session_go(scs);
  if( rc < 0 )
    return rc;

  SC_TEST( pthread_mutex_lock(&(scs->tg_mutex)) == 0 );
  while( scs->tg_state != SCS_STATE_STOPPED )
    SC_TEST( pthread_cond_wait(&(scs->tg_cond), &(scs->tg_mutex)) == 0 );
  if( exit_code_out != NULL )
    *exit_code_out = scs->tg_exit_code;
  scs->tg_state = SCS_STATE_READY;
  SC_TEST( pthread_mutex_unlock(&(scs->tg_mutex)) == 0 );
  return 0;
}


static int __sc_session_stop(struct sc_session* scs, int exit_code,
                             bool do_set_exit_code)
{
  int rc = sc_session_pause(scs);
  if( rc < 0 )
    return rc;

  SC_TEST( pthread_mutex_lock(&(scs->tg_mutex)) == 0 );
  if( do_set_exit_code )
    scs->tg_exit_code = exit_code;
  scs->tg_state = SCS_STATE_STOPPED;
  SC_TEST( pthread_mutex_unlock(&(scs->tg_mutex)) == 0 );
  SC_TEST( pthread_cond_broadcast(&(scs->tg_cond)) == 0 );
  return 0;
}


void* sc_session_stop_bg(void* arg)
{
  struct sc_session* scs = arg;
  __sc_session_stop(scs, 0/*don't care*/, false);
  return NULL;
}


int sc_session_stop(struct sc_session* scs, int exit_code)
{
  if( sc_thread_current == NULL ) {
    sc_trace(scs, "%s: exit_code=%d\n", __func__, exit_code);
    return __sc_session_stop(scs, exit_code, true);
  }
  else {
    sc_trace(scs, "%s: exit_code=%d from t%d\n", __func__, exit_code,
             sc_thread_current->id);
    scs->tg_exit_code = exit_code;
    pthread_t tid;
    SC_TEST( pthread_create(&tid, NULL, sc_session_stop_bg, scs) == 0 );
    SC_TEST( pthread_detach(tid) == 0 );
    return 0;
  }
}


struct sc_session_error* sc_session_error_get(struct sc_session* tg)
{
  if( tg->tg_err_msg == NULL )
    return NULL;
  assert(tg->tg_err_func != NULL);
  assert(tg->tg_err_file != NULL);
  struct sc_session_error* err = malloc(sizeof(struct sc_session_error));
  err->err_msg = strdup(tg->tg_err_msg);
  err->err_func = strdup(tg->tg_err_func);
  err->err_file = strdup(tg->tg_err_file);
  err->err_line = tg->tg_err_line;
  err->err_errno = tg->tg_err_errno;
  return err;
}


void sc_session_error_free(struct sc_session* tg, struct sc_session_error* err)
{
  free(err->err_msg);
  free(err->err_file);
  free(err->err_func);
  free(err);
}


int sc_session_destroy(struct sc_session* tg)
{
  int i, rc;

  sc_trace(tg, "%s: stop managed threads\n", __func__);
  struct sc_thread* t;
  SC_DLIST_FOR_EACH_OBJ(&tg->tg_threads, t, session_link)
    if( t->cfg->managed )
      sc_thread_state_request(t, SC_THRD_STATE_STOP, true);

  /* TODO: What else should we free here?  Nodes? */

  for( i = 0; i < tg->tg_pkt_pools_n; ++i ) {
    sc_trace(tg, "%s: Calling sc_pkt_pool_free(%d)\n", __func__, i);
    if( (rc = sc_pkt_pool_free(tg, tg->tg_pkt_pools[i])) != 0 )
      sc_trace(tg, "%s: sc_pkt_pool_free(%d) failed: rc=%d\n", __func__, i, rc);
  }

  /* TODO: We have just freed sc_ef_vi if required, but not sc_vi  */
  for( i = 0; i < tg->tg_vis_n; ++i ) {
    sc_trace(tg, "%s: Calling sc_ef_vi_free(%d)\n", __func__, i);
    if( (rc = sc_ef_vi_free(tg, tg->tg_vis[i])) != 0 )
      sc_trace(tg, "%s: sc_ef_vi_free(%d) failed: rc=%d\n", __func__, i, rc);
  }

  while( ! sc_dlist_is_empty(&(tg->tg_threads)) ) {
    struct sc_dlist* lnk = sc_dlist_pop_head(&(tg->tg_threads));
    sc_thread_free(SC_CONTAINER(struct sc_thread, session_link, lnk));
  }

  for( i = 0; i < tg->tg_netifs_n; ++i ) {
    sc_trace(tg, "%s: Calling sc_netif_free(%d)\n", __func__, i);
    if( (rc = sc_netif_free(tg, tg->tg_netifs[i])) != 0 )
      sc_trace(tg, "%s: sc_netif_free(%d) failed: rc=%d\n", __func__, i, rc);
  }
  for( i = 0; i < tg->tg_interfaces_n; ++i )
    sc_interface_free(tg->tg_interfaces[i]);

  SC_TEST(pthread_mutex_lock(&global_mutex) == 0);
  sc_dlist_remove(&tg->tg_all_sessions_link);
  SC_TEST(pthread_mutex_unlock(&global_mutex) == 0);
  fclose(tg->tg_info_file);
  fclose(tg->tg_type_file);
  free(tg->tg_stats_dir_name);
  for( i = 0; i < tg->tg_stats_types_n; ++i )
    free(tg->tg_stats_types[i]);
  free(tg->tg_stats_types);
  free(tg);
  return 0;
}


static void sc_thread_stop_vis_doit(struct sc_callback* cb, void* event_info)
{
  struct sc_thread* t = cb->cb_private;
  sc_trace(t->session, "%s: t%d\n", __func__, t->id);
  sc_callback_free(cb);
  int i;
  for( i = 0; i < t->n_vis; ++i )
    sc_ef_vi_stop(t->vis[i]);
}


void sc_thread_stop_vis(struct sc_thread* t)
{
  sc_trace(t->session, "%s: t%d\n", __func__, t->id);
  struct sc_callback* cb;
  SC_TRY( sc_callback_alloc(&cb, NULL, t) );
  cb->cb_handler_fn = sc_thread_stop_vis_doit;
  cb->cb_private = t;
  sc_callback_at_safe_time(cb);
}


void sc_enumerate(void)
{
  struct sc_session* scs;
  SC_DLIST_FOR_EACH_OBJ(&all_sessions, scs, tg_all_sessions_link)
    sc_session_enumerate(scs);
}
