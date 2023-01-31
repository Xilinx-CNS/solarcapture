/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \nodestats{sc_batch_limiter}
 *
 * \brief Statistics exposed by the \noderef{sc_batch_limiter} node.
 *
 * Name        | Type | Data Type  | Description
 * ----------- | ---- | ---------- | ----------------------------------------------------
 * max_packets | int  | config     | The maximum number of packets sent per batch.
 * fwd_on_idle | int  | config     | Set to 1 if mode is on_idle else 0.
 * backlog     | int  | pkt_count  | The current number of packets waiting to be forwarded.
 */

/** \cond NODOC */

ST_STRUCT(sc_batch_limiter_stats)
  ST_FIELD(int,      max_packets,              config)
  ST_FIELD(int,      fwd_on_idle,              config)
  ST_FIELD(int,      backlog,                  pkt_count)
ST_STRUCT_END

/** \endcond NODOC */
