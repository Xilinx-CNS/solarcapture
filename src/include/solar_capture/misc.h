/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \file
 * \brief Miscellaneous utility functions.
 */

#ifndef __SOLAR_CAPTURE_MISC_H__
#define __SOLAR_CAPTURE_MISC_H__


struct sc_session;


/**
 * \brief Join a multicast group.
 *
 * \param scs        A session
 * \param interface  The network interface to join on
 * \param group      The multicast group to join
 *
 * \return 0 on success, or a negative error code.
 *
 * This function joins multicast group @p group on interface @p interface.
 * This is needed when you need to use the IGMP protocol to arrange that
 * multicast packets are delivered to the adapter.
 */
extern int  sc_join_mcast_group(struct sc_session* scs, const char* interface,
                                const char* group);


#if SC_API_VER >= 1
/** \cond NODOC */
/* Do not call these functions directly.  They are used indirectly via
 * <solar_capture/declare_types.h>.
 */
extern void sc_montype_constant(struct sc_session*, const char*, int);
extern void sc_montype_struct(struct sc_session*, const char*);
extern void sc_montype_field(struct sc_session*, const char*, const char*,
                             const char*, const char*);
extern void sc_montype_struct_end(struct sc_session*);
extern void sc_montype_flush(struct sc_session*);
/** \endcond */
#endif


#endif  /* __SOLAR_CAPTURE_MISC_H__ */
/** @} */
