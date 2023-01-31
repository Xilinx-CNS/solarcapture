/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \file
 * \brief sc_session: A set of threads and other objects.
 */

#ifndef __SOLAR_CAPTURE_SESSION_H__
#define __SOLAR_CAPTURE_SESSION_H__


struct sc_session;

/**
 * \brief A SolarCapture session error object returned by ::sc_session_error_get
 */
struct sc_session_error {
  char* err_msg;         /**< The error message. */
  char* err_func;        /**< The function the error occurred in. */
  char* err_file;        /**< The source file the error occurred in. */
  int   err_line;        /**< The line number the error was issued from. */
  int   err_errno;       /**< The errno for the error. */
};


/**
 * \brief Allocate a SolarCapture session.
 *
 * \param scs_out         The allocated session object is returned here
 * \param attr            Attributes for the new session
 *
 * \return 0 on success, or a negative error code.
 *
 * This function allocates a SolarCapture session.
 *
 * A session comprises a set of threads, VIs, nodes and/or other
 * SolarCapture objects.
 */
extern int sc_session_alloc(struct sc_session** scs_out,
                            const struct sc_attr* attr);


/* sc_session_destroy() is really in SC_API_VER >= 6, but has been
 * back-ported to the 1.6 release branch which supports SC_API_VER 5.
 */
#if SC_API_VER >= 5
/**
 * \brief Destroy a SolarCapture session.
 *
 * \param scs             The session
 *
 * This call stops the session and frees all of the associated resources,
 * including threads, nodes etc.
 */
extern int sc_session_destroy(struct sc_session* scs);
#endif


#if SC_API_VER >= 3
/**
 * \brief Prepare a SolarCapture session.
 *
 * \param scs             The session
 *
 * \return 0 on success, or a negative error code.
 *
 * Prepare the session @p scs.  This step includes finalising resource
 * allocations, preparing nodes, and starting packet capture.  Managed
 * threads are started in the "paused" state.
 *
 * Note that although packet capture is started, you may get packet loss if
 * the threads managing 'sc_vi's are not started soon afterwards.
 *
 * Call ::sc_session_go() to start the managed threads and begin packet
 * processing.
 */
extern int sc_session_prepare(struct sc_session* scs);
#endif


/**
 * \brief Start a SolarCapture session.
 *
 * \param scs             The session
 *
 * \return 0 on success, or a negative error code.
 *
 * Prepare the session @p scs (if necessary) and start the managed threads.
 * This is usually called just once, after allocating resources.  It can
 * also be called after ::sc_session_pause() to restart a paused session.
 */
extern int sc_session_go(struct sc_session* scs);


/* sc_session_run() is really in SC_API_VER >= 6, but has been
 * back-ported to the 1.6 release branch which supports SC_API_VER 5.
 */
#if SC_API_VER >= 5
/**
 * \brief Start a SolarCapture session and wait until it stops.
 *
 * \param scs             The session
 * \param exit_code_out   Exit code from sc_session_stop() returned here
 *
 * \return 0 on success, or a negative error code.
 *
 * This function calls sc_session_go(), and then waits until
 * sc_session_stop() is called.  The exit code passed to sc_session_stop()
 * is returned via @p p_exit_code (which can be NULL if the exit code is
 * not wanted).
 *
 * Calling sc_session_run() changes the default action of the
 * \noderef{sc_exit} node so that it calls sc_session_stop() when the exit
 * condition is met.
 */
extern int sc_session_run(struct sc_session* scs, int* exit_code_out);
#endif


#if SC_API_VER >= 3
/**
 * \brief Pause a SolarCapture session.
 *
 * \param scs             The session
 *
 * \return 0 on success, or a negative error code.
 *
 * Pause the threads managed by session @p scs.
 *
 * This function must not be invoked by a SolarCapture managed thread.
 */
extern int sc_session_pause(struct sc_session* scs);
#endif


/* sc_session_stop() is really in SC_API_VER >= 6, but has been
 * back-ported to the 1.6 release branch which supports SC_API_VER 5.
 */
#if SC_API_VER >= 5
/**
 * \brief Stop a SolarCapture session, causing sc_session_run() to return.
 *
 * \param scs             The session
 * \param exit_code       Exit code passed to sc_session_run()
 *
 * \return >= 0 on success, or a negative error code.
 *
 * This function calls sc_session_pause(), and also causes sc_session_run()
 * to stop waiting and return @p exit_code.
 *
 * This function can be invoked in an application thread or a SolarCapture
 * managed thread.  In the latter case it will return immediately and the
 * work will be deferred to a background thread.
 */
extern int sc_session_stop(struct sc_session* scs, int exit_code);
#endif


#if SC_API_VER >= 3
/**
 * \brief Returns an error from a SolarCapture session.
 *
 * \param scs             The session
 *
 * \return A pointer to a ::sc_session_error struct representing the error
 * encountered by session @p scs. The caller should pass the pointer to
 * ::sc_session_error_free once once done with it.\n
 * If no error has occurred, this function returns NULL.
 */
extern struct sc_session_error* sc_session_error_get(struct sc_session* scs);
#endif


#if SC_API_VER >= 3
/**
 * \brief Frees an error object
 *
 * \param scs             The session
 * \param err             The error
 *
 * Frees a ::sc_session_error pointer returned by ::sc_session_error_get.
 */
extern void sc_session_error_free(struct sc_session* scs, struct sc_session_error* err);
#endif

#endif  /* __SOLAR_CAPTURE_SESSION_H__ */
/** @} */
