/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \file
 * \brief Functions for managing time.
 */

#ifndef __SOLAR_CAPTURE_TIME_H__
#define __SOLAR_CAPTURE_TIME_H__


struct sc_attr;
struct sc_thread;


/**
 * \brief Request a callback at a given time
 *
 * \param cb              A callback object
 * \param time            Time at which callback is requested
 *
 * The callback @p cb will be invoked at or after the specified time.  If the
 * time is in the past, then the handler function will be invoked as soon
 * as possible.
 *
 * The time is relative to the system realtime clock (CLOCK_REALTIME),
 * which is the same clock returned by ::sc_thread_get_time().
 */
extern void sc_timer_expire_at(struct sc_callback* cb,
                               const struct timespec* time);

/**
 * \brief Request a callback in the future
 *
 * \param cb              A callback object
 * \param delta_ns        How far in the future in nanoseconds.
 *
 * The callback will be invoked at or after the specified time delta in
 * nanoseconds.  If @p delta_ns is zero or negative then the handler function
 * will be invoked as soon as possible.
 */
extern void sc_timer_expire_after_ns(struct sc_callback* cb, int64_t delta_ns);

/**
 * \brief Push the expiry time further into the future
 *
 * \param cb              A callback object
 * \param delta_ns        How far in the future in nanoseconds.
 *
 * This function pushes the expiry time of a timer callback further into
 * the future.
 *
 * The callback @p cb must either be a currently active timer registered with
 * ::sc_timer_expire_at() or ::sc_timer_expire_after_ns(), or it must be an
 * inactive timer.  ie. The most recent use of @p cb must have been as a
 * timer callback.
 *
 * If @p cb is active, then it is rescheduled at its current expiry time plus
 * @p delta_ns.  If it is not active then it is scheduled at its previous
 * expiry time plus @p delta_ns.
 */
extern void sc_timer_push_back_ns(struct sc_callback* cb, int64_t delta_ns);

/**
 * \brief Return the expiry time of a timer callback.
 *
 * \param cb              A callback object
 * \param ts_out          The expiry time is returned here
 * \return                Zero if @p cb is a timer else -1
 */
extern int sc_timer_get_expiry_time(const struct sc_callback* cb,
                                    struct timespec* ts_out);

/**
 * \brief Convert a timespec struct to nanoseconds
 * \param ts              The timespec struct to convert
 * \return                Time in nanoseconds
 */
static inline uint64_t sc_ns_from_ts(const struct timespec* ts)
{
  return (uint64_t) ts->tv_sec * 1000000000 + ts->tv_nsec;
}

/**
 * \brief Convert a timeval struct to nanoseconds
 * \param tv              The timeval struct to convert
 * \return                Time in nanoseconds
 */
static inline uint64_t sc_ns_from_tv(const struct timeval* tv)
{
  return (uint64_t) tv->tv_sec * 1000000000 + (uint64_t) tv->tv_usec * 1000;
}


/**
 * \brief Convert milliseconds to nanoseconds
 * \param ms              The time in milliseconds to convert
 * \return                Time in nanoseconds
 */
static inline uint64_t sc_ns_from_ms(uint64_t ms)
{
  return ms * 1000000;
}


/**
 * \brief Convert microseconds to nanoseconds
 * \param us              The time in microseconds to convert
 * \return                Time in nanoseconds
 */
static inline uint64_t sc_ns_from_us(uint64_t us)
{
  return us * 1000;
}


#endif  /* __SOLAR_CAPTURE_TIME_H__ */
/** @} */
