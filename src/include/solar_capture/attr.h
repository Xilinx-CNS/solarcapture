/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \file
 * \brief sc_attr: Control optional behaviours and tunables.
 */

#ifndef __SOLAR_CAPTURE_ATTR_H__
#define __SOLAR_CAPTURE_ATTR_H__


/**
 * \struct sc_attr
 * \brief Attribute object.
 *
 * Attributes are used to specify optional behaviours and parameters,
 * usually when allocating other SolarCapture objects.  Each attribute
 * object defines a complete set of the attributes that SolarCapture
 * understands.
 *
 * For example, the "affinity_core" attribute controls which CPU core an
 * sc_thread runs on.
 *
 * Functions to create and manage attributes are in the file attr.h.
 *
 * The default values for attributes may be overridden by setting the
 * environment variable SC_ATTR.  For example:
 *
 *   SC_ATTR="log_level=3;snap=2"
 *
 * Each function that takes an attribute argument will only be interested
 * in a subset of the attributes specified by an sc_attr instance.  Other
 * attributes are ignored.
 *
 * The set of attributes supported by SolarCapture may change between
 * releases, so applications should where possible tolerate failures when
 * setting attributes.
 *
 * Attribute objects are not associated with sc_session objects, so the
 * SolarCapture error status is not set when functions that operate on
 * attributes report an error.  Instead, functions that operate on
 * attributes return 0 on success and a negative error code otherwise.
 */
struct sc_attr;


/**
 * \brief Allocate an attribute object.
 *
 * \param attr_out   The attribute object is returned here.
 *
 * \return 0 on success, or a negative error code:\n
 *         -ENOMEM if memory could not be allocated\n
 *         -EINVAL if the SC_ATTR environment variable is malformed.
 */
extern int  sc_attr_alloc(struct sc_attr** attr_out);

/**
 * \brief Free an attribute object.
 *
 * \param attr       The attribute object.
 */
extern void sc_attr_free(struct sc_attr* attr);

/**
 * \brief Return attributes to their default values.
 *
 * \param attr       The attribute object.
 */
extern void sc_attr_reset(struct sc_attr* attr);

/**
 * \brief Set an attribute to an integer value.
 *
 * \param attr       The attribute object.
 * \param name       Name of the attribute.
 * \param val        New value for the attribute.
 *
 * \return 0 on success, or a negative error code:\n
 *         -ENOENT if @p name is not a valid attribute name\n
 *         -EOVERFLOW if @p val is not within the range of values this
 *          attribute can take.
 */
extern int sc_attr_set_int(struct sc_attr* attr,
                           const char* name, int64_t val);

/**
 * \brief Set an attribute to a string value.
 *
 * \param attr       The attribute object.
 * \param name       Name of the attribute.
 * \param val        New value for the attribute (may be NULL).
 *
 * \return 0 on success, or a negative error code:\n
 *         -ENOENT if @p name is not a valid attribute name\n
 *         -ENOMSG if the attribute is not a string attribute.
 */
extern int sc_attr_set_str(struct sc_attr* attr,
                           const char* name, const char* val);

/**
 * \brief Set an attribute from a string value.
 *
 * \param attr       The attribute object.
 * \param name       Name of the attribute.
 * \param val        New value for the attribute.
 *
 * \return 0 on success, or a negative error code:\n
 *         -ENOENT if @p name is not a valid attribute name\n
 *         -EINVAL if it is not possible to convert @p val to a valid value
 *          for the attribute
 *         -EOVERFLOW if @p val is not within the range of values this
 *          attribute can take.
 */
extern int sc_attr_set_from_str(struct sc_attr* attr,
                                const char* name, const char* val);

#if SC_API_VER >= 4
/**
 * \brief Set an attribute to a string value (with formatting).
 *
 * \param attr       The attribute object.
 * \param name       Name of the attribute.
 * \param fmt        Format string for the new attribute value.
 *
 * \return 0 on success, or a negative error code:\n
 *         -ENOENT if @p name is not a valid attribute name\n
 *         -EINVAL if it is not possible to convert @p val to a valid value
 *          for the attribute
 *         -EOVERFLOW if @p val is not within the range of values this
 *          attribute can take.
 *
 * This function behaves exactly as sc_attr_set_from_str(), except that the
 * string value is generated from a printf()-style format string.
 */
extern int sc_attr_set_from_fmt(struct sc_attr* attr,
                                const char* name, const char* fmt, ...)
  __attribute__((format(printf,3,4)));
#endif

/**
 * \brief Duplicate an attribute object.
 *
 * \param attr       The attribute object.
 * \return           A new attribute object.
 *
 * This function is useful when you want to make non-destructive changes to
 * an existing attribute object.
 */
extern struct sc_attr* sc_attr_dup(const struct sc_attr* attr);


#if SC_API_VER >= 3
/**
 * \brief Returns documentation for attributes.  Used by solar_capture_doc.
 * \param attr_name_opt     The attribute name.
 * \param docs_out          On success, the resulting doc string output.
 * \param docs_len_out      On success, the length of the doc string output.
 *
 * \return 0 on success, or a negative error code.
 */
extern int sc_attr_doc(const char* attr_name_opt,
                       const char*** docs_out, int* docs_len_out);
#endif


#if SC_API_VER >= 4
/**
 * \brief Convert an ::sc_attr to an ::sc_object.
 *
 * \param attr            An ::sc_attr instance or NULL
 * \return                NULL if @p attr is NULL otherwise the ::sc_object.
 */
extern struct sc_object* sc_attr_to_object(const struct sc_attr* attr);
#endif


#if SC_API_VER >= 4
/**
 * \brief Convert an ::sc_object to an ::sc_attr.
 *
 * \param obj             An ::sc_object instance or NULL
 * \return                NULL if @p obj is NULL otherwise the ::sc_attr.
 *
 * Also returns NULL if @p obj is not of type SC_OBJ_C_ATTR.
 */
extern const struct sc_attr* sc_attr_from_object(struct sc_object* obj);
#endif


#endif  /* __SOLAR_CAPTURE_ATTR_H__ */

/** @} */
