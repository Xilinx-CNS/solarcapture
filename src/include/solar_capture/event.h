/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \file
 * \brief sc_callback: Interface for event notification.
 */

#ifndef __SOLAR_CAPTURE_EVENT_H__
#define __SOLAR_CAPTURE_EVENT_H__

#include <sys/epoll.h>

struct sc_attr;
struct sc_thread;
struct sc_callback;

/**
 * \brief A callback handler function
 * \param callback           The callback struct registered with this callback.
 * \param event_info         If callback was registered using ::sc_epoll_ctl this
 *                           will contain the uint32_t epoll_events bitmask (see man 2 epoll_ctl)
 *                           In all other cases this is not used.
 */
typedef void (sc_callback_handler_fn)(struct sc_callback*, void* event_info);


/**
 * \brief A callback object.
 *
 * Callback objects provide a way to be notified when an event of interest
 * occurs.
 */
struct sc_callback {
  void*                    cb_private;    /**< Private state for the implementation. */
  sc_callback_handler_fn*  cb_handler_fn; /**< Callback function to be invoked when the event of interest occurs. */
  struct sc_dlist          cb_link;       /**< Internal use only. */
};


/**
 * \brief Allocate a callback object instance.
 *
 * \param cb_out          The allocated callback object is returned here
 * \param attr            Attributes
 * \param thread          The thread the callback will be used with
 *
 * \return 0 on success, or a negative error code.
 *
 * This function allocates a callback object instance.
 *
 * Before using the callback object the sc_callback::cb_handler_fn field must be
 * initialised.  The sc_callback::cb_private field may be used to store or point to
 * caller-specific state.
 *
 * A callback object can only be registered with a single event source at a
 * time.  If a callback object is registered with an event source it is
 * "active".  If an active callback is registered with an event source, it
 * is automatically removed from the previous event source.
 */
extern int sc_callback_alloc(struct sc_callback** cb_out,
                             const struct sc_attr* attr,
                             struct sc_thread* thread);


#if SC_API_VER >= 5
/**
 * \brief Allocate a callback object and set description.
 *
 * \param cb_out          The allocated callback object is returned here
 * \param attr            Attributes
 * \param thread          The thread the callback will be used with
 * \param description     Description of callback (used for log traces)
 *
 * \return 0 on success, or a negative error code.
 *
 * This function behaves as ::sc_callback_alloc() except that you can also
 * set a custom description.
 */
extern int sc_callback_alloc2(struct sc_callback** cb_out,
                              const struct sc_attr* attr,
                              struct sc_thread* thread,
                              const char* description);

/*
 * \cond NODOC
 * Already documented above, as a function
 */
# define sc_callback_alloc(cb_out, attr, thread)                        \
         sc_callback_alloc2((cb_out), (attr), (thread), __func__)
/** \endcond */
#endif


/**
 * \brief Free a callback object instance.
 *
 * \param cb              The callback object to free
 *
 * This function frees a callback object instance.
 */
extern void sc_callback_free(struct sc_callback* cb);


#if SC_API_VER >= 5
/**
 * \brief Set description of a callback.
 *
 * \param cb              The callback object
 * \param fmt             Printf-style format string
 *
 * This function sets the description for a callback object.  The
 * description is currently only used in log traces.
 *
 * If @p fmt is NULL, then log tracing is suppressed for callback @p cb.
 */
extern void sc_callback_set_description(struct sc_callback* cb,
                                        const char* fmt, ...)
  __attribute__((format(printf,2,3)));
#endif


/**
 * \brief Returns true if a callback object is active.
 *
 * \param cb              The callback object
 */
static inline int sc_callback_is_active(const struct sc_callback* cb)
{
  return cb->cb_link.next != &cb->cb_link;
}


/**
 * \brief Unregister a callback object from its event source
 *
 * \param cb              The callback object
 *
 * This function has no effect if the callback object is not active.
 */
static inline void sc_callback_remove(struct sc_callback* cb)
{
  sc_dlist_remove(&cb->cb_link);
  sc_dlist_init(&cb->cb_link);
}


/**
 * \brief Request a callback when the thread is idle.
 *
 * \param cb              The callback object
 *
 * The callback will be invoked from the associated thread's polling loop
 * if there is no work done in that loop iteration.  ie. The when thread is
 * idle.
 *
 * The callback is only invoked once.  If further callbacks are wanted the
 * callback must be reregistered explicitly.
 */
extern void sc_callback_on_idle(struct sc_callback* cb);


/**
 * \brief Request a callback when the thread is idle.
 *
 * \param thread          The thread managing @p fd
 * \param op              EPOLL_CTL_ADD, EPOLL_CTL_MOD or EPOLL_CTL_DEL
 * \param fd              The file descriptor
 * \param events          Event flags (EPOLLIN, EPOLLOUT etc.)
 * \param cb              The callback object
 *
 * \return 0 on success, or a negative error code.
 *
 * Request a callback when a file descriptor is readable or writable, or if
 * op is EPOLL_CTL_DEL then cancel a callback.
 *
 * This function uses epoll as the underlying mechanism to manage file
 * descriptors, so please refer to the documentation of epoll for detailed
 * semantics.
 *
 * @p events and @p cb are ignored when @p op is EPOLL_CTL_DEL.
 *
 * A callback registered via this interface cannot be removed with
 * ::sc_callback_remove, and must not be re-registered with another event
 * source without first calling ::sc_epoll_ctl with @p op set to EPOLL_CTL_DEL.
 */
extern int sc_epoll_ctl(struct sc_thread* thread, int op, int fd,
                        unsigned events, struct sc_callback* cb);


#endif  /* __SOLAR_CAPTURE_EVENT_H__ */
/** @} */
