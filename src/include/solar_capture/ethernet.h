/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \file
 * \brief Ethernet protocol definitions.
 */

#ifndef __SOLAR_CAPTURE_ETHERNET_H__
#define __SOLAR_CAPTURE_ETHERNET_H__


#define SC_ETHERTYPE_8021Q        0x8100    /**< EtherType for IEEE 802.1Q */
#define SC_ETHERTYPE_8021QinQ     0x88a8    /**< EtherType for IEEE 802.1QinQ */


#define SC_8021Q_VID_MASK         0xfff	    /**< Mask for VLAN identifier (VID) */


#endif  /* __SOLAR_CAPTURE_ETHERNET_H__ */
/** @} */
