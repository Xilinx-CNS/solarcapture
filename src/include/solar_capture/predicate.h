/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \file
 * \brief sc_pkt_predicate: Interface for testing properties of packets.
 */

#ifndef __SOLAR_CAPTURE_PREDICATE_H__
#define __SOLAR_CAPTURE_PREDICATE_H__


struct sc_pkt_predicate;
struct sc_packet;


/**
 * \brief A packet predicate test function. It should return 1 (true), or 0 (false).
 */
typedef int (sc_pkt_predicate_test_fn)(struct sc_pkt_predicate*,
                                       struct sc_packet*);

/**
 * \brief A packet predicate object
 *
 * This can be used with an \noderef{sc_filter} node to match packets for
 * filtering. 
 */
struct sc_pkt_predicate {
  sc_pkt_predicate_test_fn* pred_test_fn; /**< The predicate test function. It should return 1 (true) or 0 (false) */
  void*                     pred_private; /**< Field to hold state for the predicate function */
};
/*
 * Doxygen might output an error that references the line above, saying
 * "Member __attribute__ (variable) of file predicate.h is not documented".
 * This error can be ignored.
 */

/**
 * \brief Allocate a packet predicate object.
 *
 * \param pred_out        On success the allocated ::sc_pkt_predicate object.
 * \param private_bytes   Size of private memory area wanted.
 * \return                0 on success.
 *
 * Packet predicates are used to test packets against some criteria.  The
 * test function should return true (1) or false (0).
 *
 * If @p private_bytes is non-zero then @p pred_private is initialised with a
 * pointer to a region of memory of size @p private_bytes.  The @p pred_private
 * field may be used by the implementation to hold state.
 */
extern int sc_pkt_predicate_alloc(struct sc_pkt_predicate** pred_out,
                                  int private_bytes);

/**
 * \brief Convert a ::sc_pkt_predicate into a ::sc_object.
 *
 * \param pred            An ::sc_pkt_predicate instance or NULL
 * \return                NULL if @p pred is NULL otherwise the converted ::sc_object.
 */
extern struct sc_object*
  sc_pkt_predicate_to_object(struct sc_pkt_predicate* pred);

/**
 * \brief Convert a ::sc_object into a ::sc_pkt_predicate.
 *
 * \param obj             An ::sc_object instance or NULL
 * \return                NULL if @p obj is NULL otherwise the converted ::sc_pkt_predicate.
 */
extern struct sc_pkt_predicate*
  sc_pkt_predicate_from_object(struct sc_object* obj);


#endif  /* __SOLAR_CAPTURE_PREDICATE_H__ */
/** @} */
