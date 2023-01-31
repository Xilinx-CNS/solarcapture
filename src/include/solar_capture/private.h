/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \cond NODOC
 * \file
 * \brief private: Functions for internal use only
 *
 * The functions in this header should not be used in applications; they
 * are intended for internal use only and may not be stable across releases.
 */

#ifndef __SOLAR_CAPTURE_PRIVATE_H__
#define __SOLAR_CAPTURE_PRIVATE_H__

extern int __sc_stream_extract_mcast_group(struct sc_stream* stream,
                                           uint32_t* mcast_group);
extern int __sc_stream_extract_vlan_id(struct sc_stream* stream,
                                       uint16_t* vlan_id);

#endif  /* __SOLAR_CAPTURE_PRIVATE_H__ */
/** @}
 * \endcond
 */
