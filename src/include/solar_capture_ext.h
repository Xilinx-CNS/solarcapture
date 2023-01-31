/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#ifndef __SOLAR_CAPTURE_EXT_H__
#define __SOLAR_CAPTURE_EXT_H__

#include <assert.h>

/* Applications can define SC_API_VER to request a particular level of
 * functionality.  If SC_API_VER is not defined, only the baseline features
 * are exposed.
 *
 * SC_API_VER corresponds to the library minor version.
 */
#ifndef SC_API_VER
# define SC_API_VER  0
#endif

/* The API version supported by this release. */
/* Remember: update src/core/libsolarcapture.ldscript too */
#define SC_API_VER_MAX   5

#if SC_API_VER > SC_API_VER_MAX
# error "SC_API_VER not supported by this version of SolarCapture"
#endif


#ifdef __cplusplus
extern "C" {
#endif

#if SC_API_VER >= 1
#include <solar_capture/object.h>
#endif
#include <solar_capture/ext_packet.h>
#include <solar_capture/ext_packet_list.h>
#include <solar_capture/ext_node.h>

#ifdef __cplusplus
}
#endif


#endif  /* __SOLAR_CAPTURE_EXT_H__ */
