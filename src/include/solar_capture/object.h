/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \file
 * \brief sc_object: Opaque object interface. Use this to pass all types of data
 * that are not ints, doubles or char arrays (see ::SC_PARAM_INT, ::SC_PARAM_DBL
 * and ::SC_PARAM_STR respectively for these).
 */

#ifndef __SOLAR_CAPTURE_OBJECT_H__
#define __SOLAR_CAPTURE_OBJECT_H__

/**
 * \brief The type of data the sc_object contains
 */
enum sc_object_type {
  SC_OBJ_ANY,
  SC_OBJ_OPAQUE,        /**< An opaque pointer */
  SC_OBJ_PKT_PREDICATE, /**< A packet predicate (see ::sc_pkt_predicate) */
  SC_OBJ_C_ATTR,        /**< Const attributes (see ::sc_attr) */
  SC_OBJ_NODE,          /**< A node (see ::sc_node) */
  SC_OBJ_POOL,          /**< A packet pool */
};

/**
 * \struct sc_object
 * \brief An opaque object. Use this to pass all types of data
 * that are not ints, doubles or char arrays (see ::SC_PARAM_INT, ::SC_PARAM_DBL
 * and ::SC_PARAM_STR respectively for these) to nodes.
 */
struct sc_object;

/**
 * \brief Return the type of data contained within the ::sc_object.
 * \param obj       The object to check the data type of.
 * \return          The type of data contained within the ::sc_object.
 */
extern enum sc_object_type sc_object_type(struct sc_object* obj);


#if SC_API_VER >= 2
/**
 * \brief Allocate memory for an opaque ::sc_object.
 *
 * \param obj_out   On success the allocated object.
 * \param opaque    A pointer to the data to be wrapped by the object.
 * \return          0 on success.
 */
extern int sc_opaque_alloc(struct sc_object** obj_out, void* opaque);

/**
 * \brief Free an ::sc_object previously allocated using ::sc_opaque_alloc. Only
 * use this to free an opaque ::sc_object. The underlying data wrapped by this
 * object will not be freed.
 * \param obj       The object to free
 */
extern void sc_opaque_free(struct sc_object* obj);

/**
 * \brief Set the opaque pointer in an ::sc_object
 * \param obj       The object to set the pointer on
 * \param opaque    The new opaque pointer to use
 */
extern void sc_opaque_set_ptr(struct sc_object* obj, void* opaque);

/**
 * \brief Get the opaque pointer stored in an ::sc_object
 * \param obj       The object to fetch the opaque pointer from.
 * \return          The opaque pointer.
 */
extern void* sc_opaque_get_ptr(const struct sc_object* obj);
#endif


#endif  /* __SOLAR_CAPTURE_OBJECT_H__ */
/** @} */
