/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \file
 * \brief sc_thread: Representation of a thread in SolarCapture.
 */

#ifndef __SOLAR_CAPTURE_THREAD_H__
#define __SOLAR_CAPTURE_THREAD_H__

#include <stdbool.h>


struct sc_thread;
struct sc_session;


/**
 * \brief Allocate a SolarCapture thread.
 *
 * \param thread_out      The allocated thread object is returned here
 * \param attr            Attributes
 * \param scs             The session
 *
 * \return 0 on success, or a negative error code.
 *
 * This function allocates a SolarCapture thread.
 *
 * Normally SolarCapture creates an OS thread for the sc_thread object, and
 * starts the thread when ::sc_session_go() is called.  If the 'managed'
 * attribute is set to false, then it is up to the application to create an
 * underlying thread.
 */
extern int sc_thread_alloc(struct sc_thread** thread_out,
                           const struct sc_attr* attr,
                           struct sc_session* scs);

/**
 * \brief Return the session associated with a thread.
 */
extern struct sc_session*
  sc_thread_get_session(const struct sc_thread* thread);

#if SC_API_VER >= 1
/**
 * \brief Return a thread's "current time".
 *
 * \param thread          The thread
 * \param time_out        The current time is returned here
 *
 * Each thread's current time is updated by the polling loop, so may or may
 * not be up-to-date when you call this function.  The clock used as the
 * time base is CLOCK_REALTIME.
 */
extern void sc_thread_get_time(const struct sc_thread* thread,
                               struct timespec* time_out);
#endif

#if SC_API_VER >= 1
/**
 * \brief Allocate memory to be used by a thread.
 *
 * \param thread          The thread
 * \param bytes           Size of memory area to allocate
 *
 * This function is intended to be used for allocating small amounts of
 * memory that are used on performance critical paths, such as the private
 * state used by the implementation of a node.
 *
 * The memory region may overlap cache lines used by other allocations from
 * this API for the same @p thread.
 */
extern void* sc_thread_calloc(struct sc_thread* thread, size_t bytes);
#endif

#if SC_API_VER >= 1
/**
 * \brief Allocate memory to be used by a thread.
 *
 * \param thread          The thread
 * \param bytes           Size of memory area wanted
 * \param align           Alignment of memory area wanted
 *
 * This function is intended to be used for allocating small amounts of
 * memory that are used on performance critical paths, such as the private
 * state used by the implementation of a node.
 *
 * The memory region may overlap cache lines used by other allocations from
 * this API for the same @p thread.
 */
extern void* sc_thread_calloc_aligned(struct sc_thread* thread,
                                      size_t bytes, int align);
#endif

#if SC_API_VER >= 1
/**
 * \brief Free memory.
 *
 * \param thread          The thread
 * \param mem             The memory area
 *
 * Use this function to free memory allocated with ::sc_thread_calloc or
 * ::sc_thread_calloc_aligned.
 */
extern void  sc_thread_mfree(struct sc_thread* thread, void* mem);
#endif

#if SC_API_VER >= 2
/**
 * \brief Poll a thread.
 *
 * \param thread          The thread.
 *
 * \return 0 if no work was available to do, or non-zero if work was done
 * (see description).
 *
 * Use this function to poll an unmanaged SolarCapture thread, causing it
 * to do I/O, push packets through the node graph and perform other work.
 *
 * The return value indicates whether any work was done.  If the return is
 * non-zero, then one of the following has happened: Packets have been
 * received by an sc_vi; Packets have been received by an sc_mailbox;
 * Packets or messages have been forwarded between nodes; A timer has
 * expired; Other work has been done (such as handling I/O on a managed
 * file descriptor).
 *
 * This call returns after doing a batch of work.  The application should
 * invoke sc_thread_poll() repeatedly until it returns 0 to do all work
 * presently available.
 *
 * Note: For managed threads this functionality is provided internally by
 * solar_capture.  It is illegal to invoke sc_thread_poll() on a managed
 * thread.
 */
extern int sc_thread_poll(struct sc_thread* thread);
#endif

#if SC_API_VER >= 5
/**
 * \brief Poll a thread's timers.
 *
 * \param thread          The thread.
 *
 * \return Returns non-zero if any timers expired.
 *
 * This function polls an unmanaged thread's timers.  It should always be
 * invoked once after sc_session_prepare() or sc_session_go(), and before
 * calling sc_thread_poll() for the first time.
 *
 * It is also good practice to call this function if the thread has not
 * been polled for a long period of time.
 */
extern int sc_thread_poll_timers(struct sc_thread* thread);
#endif


#if SC_API_VER >= 5
/**
 * \brief Return a file descriptor which an application can wait on until
 * the SolarCapture thread is ready to be polled.
 *
 * The FD returned by this call is typically used with I/O multiplexors
 * such as select(), poll() and epoll_wait().  See also
 * sc_thread_waitable_fd_prime().
 *
 * In level triggered mode: The FD returned by this call is not yet
 * "primed" and is in the readable state.
 *
 * In edge triggered mode: The FD returned is not yet "primed" and may or
 * may not be readable.  The caller should invoke sc_thread_poll() until it
 * returns 0 and call sc_thread_waitable_fd_prime() before waiting on the
 * FD.
 *
 * This call is only supported on unmanaged threads.
 *
 * Returns an FD on success or -1 on error.
 */
extern int sc_thread_waitable_fd_get(struct sc_thread* thread,
                                     bool edge_triggered);
#endif


#if SC_API_VER >= 5
/**
 * \brief Primes the thread's waitable FD.
 *
 * The application should invoke sc_thread_waitable_fd_prime() before
 * waiting on the waitable FD.  If there is no outstanding work to do in
 * the associated thread, then this call makes the waitable FD become
 * unready, and it will become ready again once there is work to do.
 *
 * This call should only be invoked after sc_thread_poll() has returned
 * false, indicating that there is no further work for the thread to do.
 * If this rule is not observed then it is possible for there to be further
 * work for the thread to do even while the waitable FD is not ready.
 *
 * In level triggered mode, once the waitable FD becomes ready it remains
 * ready until sc_thread_waitable_fd_prime() is invoked.
 *
 * In edge triggered mode, the waitable FD may become unready as a side
 * effect of sc_thread_poll().
 *
 * Once the thread's FD becomes readable, it will remain readable
 * until this function is called. After this call returns, it will
 * be readable only if the thread still has work to do.
 *
 * NOTE: To be sure the thread has no more work to do,
 *       call sc_thread_poll in a loop until it returns 0.
 *
 * Before calling this function the application must have called
 * sc_thread_waitable_fd_get().
 */
extern void sc_thread_waitable_fd_prime(struct sc_thread* thread);
#endif


#endif  /* __SOLAR_CAPTURE_THREAD_H__ */
/** @} */
