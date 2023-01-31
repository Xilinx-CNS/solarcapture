/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \file
 * \brief sc_pool: A pool of packet buffers.
 */

#ifndef __SOLAR_CAPTURE_PKT_POOL_H__
#define __SOLAR_CAPTURE_PKT_POOL_H__


struct sc_pool;
struct sc_callback;
struct sc_packet_list;
struct sc_iovec_ptr;


/**
 * \brief Get packet buffers from a pool.
 *
 * \param list         List where retrieved packets are placed
 * \param pool         The packet pool
 * \param min_packets  Minimum number of buffers to be returned
 * \param max_packets  Maximum number of buffers to be returned
 *
 * \return The number of buffers added to @p list, or -1 if the minimum could
 * not be satisfied.
 *
 * @p list must be initialised on entry (and may already contain some
 * packets), but need not be finalised.  The list is finalised on return
 * unless an error is returned (in which case the list is not modified).
 *
 * Each packet returned is initialised as follows:
 *   pkt->flags = 0;
 *   pkt->frame_len = 0;
 *   pkt->iovlen = 1;
 *   pkt->iov[0] gives the base and extent of the DMA area
 *   The fragment list is empty
 *
 * The following packet fields have undefined values: ts_sec, ts_nsec.
 */
extern int sc_pool_get_packets(struct sc_packet_list* list, struct sc_pool* pool,
                               int min_packets, int max_packets);

#if SC_API_VER >= 2
/**
 * \brief Return packets to a pool.
 *
 * \param pool         The packet pool
 * \param list         List of packets to return
 *
 *  @p list must be initialised on entry, but can be empty.  The packets on
 *  the list can have frags.
 */
extern void sc_pool_return_packets(struct sc_pool* pool,
                                   struct sc_packet_list* list);
#endif


/**
 * \brief Request a callback when the pool is refilled.
 *
 * \param pool         The packet pool
 * \param event        The event object
 * \param threshold    Event fires when pool has >= threshold buffers
 *
 * Registers an event handler that is invoked when the pool fill level
 * reaches the specified threshold.  If the pool fill level is already at
 * or above the threshold, the handler will be invoked as soon as possible.
 */
extern void sc_pool_on_threshold(struct sc_pool* pool, struct sc_callback* event,
                                 int threshold);


/**
 * \brief Duplicate a packet.
 *
 * \param pool         The pool to allocate buffers from
 * \param packet       The packet to duplicate
 * \param snap         The maximum number of bytes to copy
 *
 * \return The duplicated packet or NULL if insufficient buffers.
 */
extern struct sc_packet* sc_pool_duplicate_packet(struct sc_pool* pool,
                                                  struct sc_packet* packet,
                                                  int snap);


#if SC_API_VER >= 5
/**
 * \brief Duplicate a packed-stream packet.
 *
 * \param pool         The pool to allocate buffers from
 * \param psp          The packed-stream packet to duplicate
 * \param snap         The maximum number of bytes to copy
 *
 * \return The duplicated packet or NULL if insufficient buffers.
 */
extern struct sc_packet*
  sc_pool_duplicate_packed_packet(struct sc_pool* pool,
                                  const struct sc_packed_packet* psp, int snap);
#endif


/**
 * \brief Append data to a packet.
 *
 * \param packet       The packet to append data to
 * \param pool         Packet pool to allocate frag buffers from (optional)
 * \param iovp         Identifies the data to copy in
 * \param snap         The maximum number of bytes to copy in
 *
 * \return 0 if all the requested data could be appended.\n
 *         -1 if more space was needed and it was not possible to allocate
 *            fragment buffers\n
 *         -2 if the packet runs out of space (ie. the fragments chain would
 *            exceed the maximum chain length).
 *
 * If you need to know the number of bytes appended, compare the packet
 * frame_len before and after the call.
 */
extern int sc_packet_append_iovec_ptr(struct sc_packet* packet,
                                      struct sc_pool* pool,
                                      struct sc_iovec_ptr* iovp,
                                      int snap);


#if SC_API_VER >= 4
/**
 * \brief Set the refill node for a pool.
 *
 * \param pool         A packet pool
 * \param node         A refill node
 *
 * \return The refill node
 * This function sets @p node to be the refill node for @p pool.
 * SolarCapture sets up the necessary links so that when packet buffers
 * from @p pool are freed, they will be forwarded to @p node.
 *
 * It is expected that @p node will normally return packets to the pool by
 * calling ::sc_pool_return_packets.
 *
 * This call is only needed if some action needs to be taken before
 * returning freed buffers to the pool.  The builtin nodes sc_wrap_undo and
 * sc_ref_count_undo can be used as pool refill nodes.
 */
extern struct sc_node* sc_pool_set_refill_node(struct sc_pool* pool,
                                               struct sc_node* node);
#endif


#if SC_API_VER >= 4
/**
 * \brief Indicate that a pool is used to wrap packets from a node.
 *
 * \param pool         A packet pool
 * \param node         A node
 *
 * \return 0 on success, or a negative error code.
 *
 * This function is used to indicate that packets from @p pool are used to
 * wrap packets that are delivered to @p node.
 *
 * This allows SolarCapture to ensure that the packet pools sending packets
 * to @p node can be configured appropriately.  For example, if these
 * wrapped packets reach an sc_injector, it may be necessary to DMA map the
 * underlying packet buffers.
 */
extern int sc_pool_wraps_node(struct sc_pool* pool, struct sc_node* node);
#endif


#if SC_API_VER >= 4
/**
 * \brief Convert an sc_pool to an ::sc_object.
 *
 * \param pool            An sc_pool instance or NULL
 * \return                NULL if @p pool is NULL otherwise the ::sc_object.
 */
extern struct sc_object* sc_pool_to_object(struct sc_pool* pool);
#endif


#if SC_API_VER >= 4
/**
 * \brief Convert an ::sc_object to an sc_pool.
 *
 * \param obj             An ::sc_object instance or NULL
 * \return                NULL if @p obj is NULL otherwise the sc_pool.
 *
 * Also returns NULL if @p obj is not of type SC_OBJ_POOL.
 */
extern struct sc_pool* sc_pool_from_object(struct sc_object* obj);
#endif


#if SC_API_VER >= 5
/**
 * \brief Get the minimum buffer size provided by this pool
 *
 * \param pool            An sc_pool instance
 * \return                The minimum buffer size provided by this pool.
 *
 * If called at prep time, the size returned returned may be less than the size
 * of buffers provided by this pool.
 */
extern uint64_t sc_pool_get_buffer_size(struct sc_pool* pool);
#endif


#endif  /* __SOLAR_CAPTURE_PKT_POOL_H__ */
/** @} */
