/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#ifndef __SC_EVENT_H__
#define __SC_EVENT_H__


enum sc_callback_type {
  evt_timer,
  evt_pool_threshold,
  evt_idle,
};


struct sc_callback_impl {
  struct sc_callback    cbi_public;
  struct sc_thread*     cbi_thread;
#ifndef NDEBUG
  char*                 cbi_desc;
#endif
  enum sc_callback_type cbi_type;

  /* Any callback type can be pushed into the timer subsystem -- this is
   * used as a way to defer the callback to a 'safe' time.  So therefore
   * cbi_timer_expiry cannot go in the union.
   */
  struct timespec       cbi_timer_expiry;

  union {
    struct {
      struct sc_pkt_pool* pool;
      int                 threshold;
    } cbi_pool_non_empty;
  };
};


#define SC_CALLBACK_DESCRIPTION_SILENT  ((char*)(uintptr_t) 1)


#define SC_CALLBACK_IMPL_FROM_CALLBACK(ev)                      \
  SC_CONTAINER(struct sc_callback_impl, cbi_public, (ev))

#define SC_CALLBACK_IMPL_FROM_LINK(l)                                   \
  SC_CONTAINER(struct sc_callback_impl, cbi_public.cb_link, (l))


/* Invoke callback at safe time.  ie. During timer processing.  This
 * function sets cbi_type=evt_timer.
 */
extern void sc_callback_at_safe_time(struct sc_callback*);

/* Invoke callback at safe time.  Used where callback condition needs to be
 * re-checked before invoking callback.  Caller must set cbi_type.
 */
extern void __sc_callback_at_safe_time(struct sc_callback*);


/* Scales the provided value, initially in the specified unit,
 * to seconds. unit should be one of "s", "ms", "us", "ns".
 * Returns 0 on success, -1 on failure.
 */
extern int sc_scale_to_seconds(const char* unit, double* value);


extern void sc_epoll_restart_after_lt_prime(struct sc_callback* cb,
                                            void* event_info);


#ifdef NDEBUG
static inline void sc_callback_call(struct sc_callback* cb, void* event_info,
                                    const char* caller)
{
  cb->cb_handler_fn(cb, event_info);
}
#else
extern void sc_callback_call(struct sc_callback* cb, void* event_info,
                             const char* caller);
#endif




#endif  /* __SC_EVENT_H__ */
