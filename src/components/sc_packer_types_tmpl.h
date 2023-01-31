/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \cond NODOC
 * \nodestats{sc_ps_to_ps_packer}
 *
 * \brief Statistics exposed by the \noderef{sc_ps_to_ps_packer} node.
 *
 * Name          | Type     | Data Type       | Description
 * --------------| -------- | --------------- | ----------------------------------------------------
 * packed_bytes  | uint64_t | byte_count      | TBD Packed size in bytes.
 * buffer_low    | uint64_t | ev_count        | TBD Number of times the pool of buffers has run low.
 * backlog_len   | uint64_t | pkt_count       | TBD Number of packets in backlog.
 * cap_bytes     | uint64_t | cap_bytes_count | TBD Sum of payload bytes.
 * cap_pkts      | uint64_t | cap_pkts_count  | TBD Count of packets.
 */
 
/** \cond NODOC */

ST_STRUCT(sc_packer_stats)
  ST_FIELD(uint64_t, packed_bytes, byte_count)
  ST_FIELD(uint64_t, buffer_low,   ev_count)
  ST_FIELD(uint64_t, backlog_len,  pkt_count)
  ST_FIELD(uint64_t, cap_bytes,    cap_bytes_count)
  ST_FIELD(uint64_t, cap_pkts,     cap_pkts_count)
ST_STRUCT_END

/** \endcond NODOC */
