/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \nodestats{sc_rate_monitor}
 *
 * \brief Statistics exposed by the \noderef{sc_rate_monitor} node.
 *
 * Name        | Type     | Data Type  | Description
 * ------------| -------- | -----------| ----------------------------------------------------
 * pkt_rate    | int      | pkt_rate   | Packet rate (packets/second).
 * cap_bytes   | uint64_t | byte_count | Sum of payload bytes.
 * link_bytes  | uint64_t | byte_count | Sum of frame_len (bytes on wire before snapping).
 * cap_bw      | uint64_t | bandwidth  | Payload bandwidth (bits/second).
 * link_bw     | uint64_t | bandwidth  | Bandwidth before snap (bits/second) (from frame_len field).
 */
 
/** \cond NODOC */
ST_STRUCT(sc_rate_monitor_stats)
  ST_FIELD(int,      pkt_rate,                 pkt_rate)
  ST_FIELD(uint64_t, cap_bytes,                byte_count)
  ST_FIELD(uint64_t, link_bytes,               byte_count)
  ST_FIELD(uint64_t, cap_bw,                   bandwidth)
  ST_FIELD(uint64_t, link_bw,                  bandwidth)
ST_STRUCT_END
/** \endcond NODOC */
