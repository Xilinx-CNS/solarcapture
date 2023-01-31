/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#include "internal.h"
#include "sc_internal/ef_vi.h"

#include <sys/epoll.h>


static void sc_epoll_wait(struct sc_thread* thread, int timeout_ms)
{
  int max_evs = thread->cfg->fd_poll_max_events;
  struct epoll_event evs[max_evs];
  int n_evs = epoll_wait(thread->epoll_fd, evs, max_evs, timeout_ms);
  thread->is_sleeping = 0;
  if( timeout_ms != 0 )
    TRY(clock_gettime(CLOCK_REALTIME, &thread->cur_time));
  int i;
  for( i = 0; i < n_evs; ++i ) {
    struct sc_callback* cb = evs[i].data.ptr;
    assert(SC_CALLBACK_IMPL_FROM_CALLBACK(cb)->cbi_thread == thread);
    sc_tracefp(thread->session, "%s: t%d ev%d events=0x%x\n", __func__,
               thread->id, i, evs[i].events);
    sc_callback_call(cb, (void*)(uintptr_t) evs[i].events, "epoll");
  }
}


static void sc_epoll_timer(struct sc_callback* cb, void* event_info)
{
  struct sc_thread* thread = cb->cb_private;
  sc_epoll_wait(thread, 0);
  sc_timer_expire_after_ns(thread->epoll_timer_cb, thread->cfg->fd_poll_nanos);
}


void sc_epoll_restart_after_lt_prime(struct sc_callback* cb, void* event_info)
{
  /* App is using sc_thread_waitable_fd_prime() in level-triggered mode.
   * This gets invoked when the app invokes sc_thread_poll() after prime(),
   * presumably after epoll_fd has become ready.  We need to ensure that
   * epoll_fd remains ready until sc_thread_waitable_fd_prime() is invoked.
   *
   * (The point is that the thing that woke us up may stop being ready once
   * we call epoll_wait(), so we have to explicitly force the epoll_fd to
   * remain ready).
   */
  struct sc_thread* thread = cb->cb_private;
  sc_tracefp(thread->session, "%s:\n", __func__);
  sc_thread_wake(thread);
  cb->cb_handler_fn = sc_epoll_timer;
  sc_epoll_timer(cb, event_info);
}


static void sc_epoll_thread_is_idle(struct sc_callback* cb, void* event_info)
{
  /* Thread is idle.  Perhaps we can go to sleep? */

  struct sc_thread* thread = event_info;
  int i;

  assert( thread->wakeup_cb != NULL );
  assert( thread->cfg->managed );

  if( thread->is_sleeping == 0 ) {
    /* Set [is_sleeping] then check no messages managed to sneak in... */
    thread->is_sleeping = 1;
    sc_slb();
    if( sc_thread_has_ready_mailbox(thread) ) {
      sc_callback_on_idle(thread->epoll_idle_cb);
      return;
    }
  }

  /* Remove our epoll timer else we're not going to get a sensible answer
   * for how long we should block for!
   */
  assert(sc_callback_is_active(thread->epoll_timer_cb));
  sc_callback_remove(thread->epoll_timer_cb);

  int timeout_ms;
  if( ! sc_dlist_is_empty(&(thread->timers.cbi_public.cb_link)) ) {
    struct sc_callback_impl* cbi = sc_thread_timer_head(thread);
    int64_t ns = sc_timespec_diff_ns(cbi->cbi_timer_expiry, thread->cur_time);
    if( ns > 0 ) {
      int64_t ms = ns / 1000000;
      if( ms <= 1000000000 )  /* avoid overflow of timeout_ms */
        timeout_ms = (int) ms;
      else
        timeout_ms = 1000000000;
    }
    else {
      timeout_ms = 0;
    }
  }
  else {
    timeout_ms = -1;
  }

  for( i = 0; i < thread->n_vis; ++i )
    sc_ef_vi_about_to_sleep(thread->vis[i]);

  sc_epoll_wait(thread, timeout_ms);
  sc_callback_on_idle(thread->epoll_idle_cb);
  sc_timer_expire_after_ns(thread->epoll_timer_cb, thread->cfg->fd_poll_nanos);
}


int sc_epoll_ctl(struct sc_thread* thread, int op, int fd,
                 unsigned events, struct sc_callback* callback)
{
  assert(op == EPOLL_CTL_DEL ||
         SC_CALLBACK_IMPL_FROM_CALLBACK(callback)->cbi_thread == thread);

  if( thread->epoll_fd < 0 ) {
    thread->epoll_fd = epoll_create(1);
    if( thread->epoll_fd < 0 )
      return sc_set_err(thread->session, errno,
                        "ERROR: epoll_create failed\n");
    assert(thread->epoll_idle_cb == NULL);
    if( thread->wakeup_cb != NULL && thread->cfg->managed ) {
      /* Allocate idle callback for non-busy-wait managed threads only */
      SC_TRY( sc_callback_alloc2(&thread->epoll_idle_cb, NULL,
                                 thread, "epoll_idle") );
      thread->epoll_idle_cb->cb_private = NULL;
      thread->epoll_idle_cb->cb_handler_fn = sc_epoll_thread_is_idle;
      sc_callback_on_idle(thread->epoll_idle_cb);
    }
    /* This timer is used to ensure epoll is polled periodically while
     * busy.
     */
    SC_TRY( sc_callback_alloc2(&thread->epoll_timer_cb, NULL, thread, NULL) );
    thread->epoll_timer_cb->cb_private = thread;
    thread->epoll_timer_cb->cb_handler_fn = sc_epoll_timer;
    sc_timer_expire_after_ns(thread->epoll_timer_cb,
                             thread->cfg->fd_poll_nanos);
  }

  struct epoll_event epev;
  epev.events = events;
  epev.data.ptr = callback;

  int rc = epoll_ctl(thread->epoll_fd, op, fd, &epev);
  if( rc < 0 )
    rc = sc_set_err(thread->session, errno, "epoll_ctl failed\n");
  return rc;
}
