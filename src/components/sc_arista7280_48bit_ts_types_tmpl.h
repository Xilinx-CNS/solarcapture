/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \page sc_arista7280_48bit_ts_stats sc_arista_ts, switch_model=7280, ts_format=48bit
 *
 * \brief Arista timestamp statistics that are exposed by the \noderef{sc_arista_ts} node when switch_model=7280, ts_format=48bit.
 *
 * Name                  | Type      | Data Type  | Description
 * --------------------- | --------- | ---------- |-------------------------------------------------------------------
 * strip_ticks           | int       | config     | 1 if the node is stripping ticks 0 otherwise.
 * replace_src_mac       | int       | config     | 1 if the node is replacing source mac 0 otherwise.
 * n_filtered_oui        | uint64_t  | pkt_count  | Number of packets filtered out by OUI.
 * n_filtered_arista     | uint64_t  | pkt_count  | Number of packets filtered out because of invalid Arista field.
 * n_filtered_other      | uint64_t  | pkt_count  | Number of packets filtered out for some other reasons.
 * n_rollover            | uint64_t  | pkt_count  | Number of packets with seconds rollover.
 */

/** \cond NODOC */

ST_STRUCT(sc_arista7280_48bit_ts_stats)
  ST_FIELD(int,      strip_ticks,              config)
  ST_FIELD(int,      replace_src_mac,          config)
  ST_FIELD(uint64_t, n_filtered_oui,           pkt_count)
  ST_FIELD(uint64_t, n_filtered_arista,        pkt_count)
  ST_FIELD(uint64_t, n_filtered_other,         pkt_count)
  ST_FIELD(uint64_t, n_rollover,               pkt_count)
ST_STRUCT_END

/** \endcond NODOC */
