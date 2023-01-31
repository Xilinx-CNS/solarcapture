/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#ifndef __SC_THREAD_H__
#define __SC_THREAD_H__

#include <stdio.h>
#include <unistd.h>
#include <sched.h>
#include <pthread.h>


enum sc_log_level {
  SC_LL_NONE,
  SC_LL_ERR,
  SC_LL_WARN,
  SC_LL_INFO,
  SC_LL_TRACE,
  /* Log levels below here are only included in debug builds. */
  SC_LL_TRACEFP,
};


enum sc_session_state {
  SCS_STATE_NEW,
  SCS_STATE_READY,
  SCS_STATE_BROKEN,
  SCS_STATE_STOPPED,
};


struct sc_session {
  struct sc_dlist                  tg_threads;
  int                              tg_threads_n;

  struct sc_netif**                tg_netifs;
  int                              tg_netifs_n;

  struct sc_interface**            tg_interfaces;
  int                              tg_interfaces_n;

  struct sc_ef_vi**                tg_vis;
  int                              tg_vis_n;

  struct sc_pkt_pool**             tg_pkt_pools;
  int                              tg_pkt_pools_n;

  struct sc_node_impl**            tg_nodes;
  int                              tg_nodes_n;

  char**                           tg_stats_types;
  int                              tg_stats_types_n;
  bool                             tg_write_stats_types;

  int                              tg_mailboxes_n;
  int                              tg_vi_groups_n;

  int                              tg_id;
  char*                            tg_stats_dir_name;
  int                              tg_stats_file_size;
  FILE*                            tg_info_file;
  FILE*                            tg_type_file;

  int                              tg_dispatch_order;

  enum sc_log_level                tg_log_level;
  enum sc_session_state            tg_state;
  char*                            tg_err_msg;
  const char*                      tg_err_func;
  const char*                      tg_err_file;
  int                              tg_err_line;
  int                              tg_err_errno;
  struct sc_dlist                  tg_unpreped_nodes;
  struct sc_dlist                  tg_affinity_stack;
  struct sc_dlist                  tg_all_sessions_link;
  pthread_mutex_t                  tg_mutex;
  pthread_cond_t                   tg_cond;
  int                              tg_exit_code;
  bool                             tg_run_invoked;
};


enum sc_thread_state {
  SC_THRD_STATE_STOP,
  SC_THRD_STATE_INITIALISING,
  SC_THRD_STATE_RUN,
  SC_THRD_STATE_PAUSE,
};


struct sc_thread {
  /*
   * Modified by this thread on fast paths.
   */

  struct timespec                  cur_time;

  /* Records return value from last sc_thread_poll() call. */
  int                              last_poll_did_something;

  /* List of nodes that have packets queued. */
  struct sc_dlist                  dispatch_list;

  /* This object contains two things we care about: It is the head of the
   * timer list, and its 'expiry time' is set far in the future.  This
   * makes adding timers and checking for expiry rather elegant...
   */
  struct sc_callback_impl          timers;

  /* List of idle event handlers. */
  struct sc_dlist                  idle_callbacks;

  /* Set to true if thread goes to sleep. */
  volatile int                     is_sleeping;

  /*
   * Constant once running.
   */

  struct sc_allocator*             ma;
  struct sc_ef_vi**                vis;
  struct sc_mailbox**              mailboxes;
  struct sc_stats_file_header*     stats_header;
  char*                            name;
  int                              n_vis;
  int                              n_mailboxes;
  int                              id;
  int                              affinity;
  struct sc_session*               session;
  struct sc_dlist                  session_link;
  struct sc_node_impl*             free_demux_node;
  struct sc_thread_stats*          cfg;
  struct sc_callback*              idle_cb;
  struct sc_idle_monitor_stats*    idle_stats;
  int                              epoll_fd;
  int                              timerfd;
  struct sc_callback*              timerfd_cb;
  struct sc_callback*              epoll_idle_cb;
  struct sc_callback*              epoll_timer_cb;
  struct sc_callback*              wakeup_cb;
  int                              wakeup_eventfd;
  pthread_t                        pthread_id;
  pthread_cond_t                   cond;
  struct sc_attr*                  attr;
};


struct sc_saved_affinity {
  struct sc_dlist ssa_session_link;
  cpu_set_t       ssa_affinity;
};


static inline void sc_thread_wake(struct sc_thread* thread)
{
  uint64_t v = 1;
  SC_TEST( write(thread->wakeup_eventfd, &v, 8) == 8 );
}


#endif  /* __SC_THREAD_H__ */
