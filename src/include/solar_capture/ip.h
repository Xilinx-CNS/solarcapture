/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \file
 * \brief IP protocol definitions.
 */

#ifndef __SOLAR_CAPTURE_IP_H__
#define __SOLAR_CAPTURE_IP_H__


#define SC_IP4_OFFSET_MASK       0x1fff /**< Mask for Fragment Offset field in IP header */
#define SC_IP4_FRAG_MORE         0x2000 /**< Mask for More Fragments flag in IP header */
#define SC_IP4_FRAG_DONT         0x4000 /**< Mask for Don't Fragment flag in IP header */


#define SC_TCP_FIN        0x01  /**< Mask for FIN flag in TCP header */
#define SC_TCP_SYN        0x02  /**< Mask for SYN flag in TCP header */
#define SC_TCP_RST        0x04  /**< Mask for RST flag in TCP header */
#define SC_TCP_PSH        0x08  /**< Mask for PSH flag in TCP header */
#define SC_TCP_ACK        0x10  /**< Mask for ACK flag in TCP header */
#define SC_TCP_URG        0x20  /**< Mask for URG flag in TCP header */


#endif  /* __SOLAR_CAPTURE_IP_H__ */
/** @} */
