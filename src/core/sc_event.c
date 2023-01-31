/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#include "internal.h"

#include <stdarg.h>


/* sc_callback_alloc is defined as a macro in solar_capture/event.h. */
#undef sc_callback_alloc


int sc_callback_alloc2(struct sc_callback** cb_out, const struct sc_attr* attr,
                       struct sc_thread* thread, const char* description)
{
  struct sc_callback_impl* cbi = sc_thread_calloc(thread, sizeof(*cbi));
  struct sc_callback* cb = &cbi->cbi_public;
  sc_dlist_init(&cb->cb_link);
#ifndef NDEBUG
  cbi->cbi_desc = description ? strdup(description) : NULL;
#endif
  cbi->cbi_thread = thread;
  *cb_out = cb;
  return 0;
}


int sc_callback_alloc(struct sc_callback** cb_out, const struct sc_attr* attr,
                      struct sc_thread* thread)
{
  return sc_callback_alloc2(cb_out, attr, thread, "");
}


void sc_callback_free(struct sc_callback* cb)
{
  struct sc_callback_impl* cbi = SC_CALLBACK_IMPL_FROM_CALLBACK(cb);
  sc_callback_remove(cb);
  sc_thread_mfree(cbi->cbi_thread, cbi);
}


void sc_callback_set_description(struct sc_callback* cb,
                                 const char* fmt, ...)
{
#ifndef NDEBUG
  struct sc_callback_impl* cbi = SC_CALLBACK_IMPL_FROM_CALLBACK(cb);
  free(cbi->cbi_desc);
  cbi->cbi_desc = NULL;

  if( fmt != NULL ) {
    va_list va;
    va_start(va, fmt);
    int rc = vasprintf(&(cbi->cbi_desc), fmt, va);
    assert( rc > 0 );  (void) rc;
    va_end(va);
  }
#endif
}


#ifndef NDEBUG
void sc_callback_call(struct sc_callback* cb, void* event_info,
                      const char* caller)
{
  struct sc_callback_impl* cbi = SC_CALLBACK_IMPL_FROM_CALLBACK(cb);
  if( cbi->cbi_desc != NULL )
    sc_tracefp(cbi->cbi_thread->session, "%s: t%d %s %s\n", __func__,
               cbi->cbi_thread->id, caller, cbi->cbi_desc);
  cb->cb_handler_fn(cb, event_info);
}
#endif


static void sc_timer_schedule(struct sc_callback_impl* cbi)
{
  struct sc_callback_impl* e = sc_thread_timer_head(cbi->cbi_thread);
  while( sc_timespec_le(e->cbi_timer_expiry, cbi->cbi_timer_expiry) )
    e = SC_CALLBACK_IMPL_FROM_LINK(e->cbi_public.cb_link.next);

  /* This inserts [ev] in the list before [e]. */
  sc_dlist_remove(&cbi->cbi_public.cb_link);
  sc_dlist_push_tail(&e->cbi_public.cb_link, &cbi->cbi_public.cb_link);
}


static void __sc_timer_expire_now(struct sc_callback_impl* cbi)
{
  struct sc_thread* t = cbi->cbi_thread;
  /* NB. Caller sets cbi_type.  (Not always evt_timer). */
  cbi->cbi_timer_expiry = t->cur_time;
  sc_timer_schedule(cbi);
}


#if 0  /* Not yet in public API. */
void sc_timer_expire_now(struct sc_callback* cb)
{
  struct sc_callback_impl* cbi = SC_CALLBACK_IMPL_FROM_CALLBACK(cb);
  cbi->cbi_type = evt_timer;
  __sc_timer_expire_now(cbi);
}
#endif


void sc_timer_expire_at(struct sc_callback* cb, const struct timespec* time)
{
  /* ?? todo: assert thread is running? */
  assert(cb->cb_handler_fn != NULL);

  struct sc_callback_impl* cbi = SC_CALLBACK_IMPL_FROM_CALLBACK(cb);
  cbi->cbi_type = evt_timer;
  cbi->cbi_timer_expiry = *time;
  sc_timer_schedule(cbi);
}


void sc_timer_expire_after_ns(struct sc_callback* cb, int64_t delta_ns)
{
  /* ?? todo: assert thread is running? */
  assert(cb->cb_handler_fn != NULL);

  struct sc_thread* t = SC_CALLBACK_IMPL_FROM_CALLBACK(cb)->cbi_thread;
  struct timespec ts;
  if( delta_ns > 0 ) {
    if( delta_ns <= 1000000000 ) {
      ts.tv_sec = t->cur_time.tv_sec;
      ts.tv_nsec = t->cur_time.tv_nsec + delta_ns;
    }
    else {
      ts.tv_sec = t->cur_time.tv_sec + delta_ns / 1000000000;
      ts.tv_nsec = t->cur_time.tv_nsec + delta_ns % 1000000000;
    }
    if( ts.tv_nsec >= 1000000000 ) {
      ts.tv_sec += 1;
      ts.tv_nsec -= 1000000000;
    }
  }
  else {
    ts = t->cur_time;
  }
  sc_timer_expire_at(cb, &ts);
}


void sc_timer_push_back_ns(struct sc_callback* cb, int64_t delta_ns)
{
  struct sc_callback_impl* cbi = SC_CALLBACK_IMPL_FROM_CALLBACK(cb);

  /* ?? todo: assert thread is running? */
  assert(cb->cb_handler_fn != NULL);
  assert(delta_ns >= 0);
  assert(cbi->cbi_type == evt_timer);

  if( delta_ns <= 1000000000 ) {
    cbi->cbi_timer_expiry.tv_nsec += delta_ns;
  }
  else {
    cbi->cbi_timer_expiry.tv_sec += delta_ns / 1000000000;
    cbi->cbi_timer_expiry.tv_nsec += delta_ns % 1000000000;
  }
  if( cbi->cbi_timer_expiry.tv_nsec >= 1000000000 ) {
    cbi->cbi_timer_expiry.tv_sec += 1;
    cbi->cbi_timer_expiry.tv_nsec -= 1000000000;
  }
  sc_timer_schedule(cbi);
}


int sc_timer_get_expiry_time(const struct sc_callback* cb,
                             struct timespec* ts_out)
{
  struct sc_callback_impl* cbi = SC_CALLBACK_IMPL_FROM_CALLBACK(cb);
  if( cbi->cbi_type == evt_timer ) {
    *ts_out = cbi->cbi_timer_expiry;
    return 0;
  }
  /* NB. We do not set an error. */
  return -1;
}


void sc_callback_on_idle(struct sc_callback* cb)
{
  assert(cb->cb_handler_fn != NULL);

  struct sc_callback_impl* cbi = SC_CALLBACK_IMPL_FROM_CALLBACK(cb);
  struct sc_thread* t = cbi->cbi_thread;
  cbi->cbi_type = evt_idle;
  sc_dlist_remove(&cb->cb_link);
  sc_dlist_push_tail(&t->idle_callbacks, &cb->cb_link);
}


void sc_callback_at_safe_time(struct sc_callback* cb)
{
  struct sc_callback_impl* cbi = SC_CALLBACK_IMPL_FROM_CALLBACK(cb);
  cbi->cbi_type = evt_timer;
  __sc_timer_expire_now(cbi);
}


void __sc_callback_at_safe_time(struct sc_callback* cb)
{
  struct sc_callback_impl* cbi = SC_CALLBACK_IMPL_FROM_CALLBACK(cb);
  __sc_timer_expire_now(cbi);
}


int sc_scale_to_seconds(const char* unit, double* value)
{
  if( !strcmp(unit, "s") );
  else if( !strcmp(unit, "ms") )
    *value /= 1e3;
  else if( !strcmp(unit, "us") )
    *value /= 1e6;
  else if( !strcmp(unit, "ns") )
    *value /= 1e9;
  else
    return -1;
  return 0;
}
