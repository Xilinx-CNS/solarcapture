/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#ifndef __SC_INTERNAL_H__
#define __SC_INTERNAL_H__


/* TODO: move to a config header */
#define SC_NODE_STATS       1
#define SC_VI_DEBUG_STATS   0
#define SC_MBOX_DEBUG_STATS 0

/* Internally used flags */
#define SC_PACKED_STREAM (1 << 13)  /* Alias for SC_RESERVED_3. */
#define SC_FILE_ROTATE (1 << 14)  /* Alias for SC_RESERVED_2. */
#define SC_RHD_HEADER  (1 << 15)  /* Alias for SC_RESERVED_1. */

#define SC_API_VER SC_API_VER_MAX
#include <solar_capture.h>

#include <assert.h>

#include <sc_internal/compat.h>
#include <sc_internal/utils.h>
#include <sc_internal/memory.h>
#include <sc_internal/object.h>
#include <sc_internal/event.h>
#include <sc_internal/pkt.h>
#include <sc_internal/thread.h>
#include <sc_internal/node_impl.h>
#include <sc_internal/mailbox.h>
#include <sc_internal/attr.h>
#include <sc_internal/stats.h>
#include <sc_internal/pkt_pool.h>
#include <sc_internal/topology.h>
#include <sc_internal/vi.h>
#include <sc_internal/shm_endpoint.h>
#include <sc_internal/arg_helpers.h>



#endif  /* __SC_INTERNAL_H__ */
