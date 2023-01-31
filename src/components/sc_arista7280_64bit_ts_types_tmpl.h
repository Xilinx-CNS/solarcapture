/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \page sc_arista7280_64bit_ts_stats sc_arista_ts, switch_model=7280, ts_format=64bit
 *
 * \brief Arista timestamp statistics that are exposed by the \noderef{sc_arista_ts} node when switch_model=7280, ts_format=64bit.
 *
 * Name                  | Type      | Data Type  | Description
 * --------------------- | --------- | ---------- |-------------------------------------------------------------------
 * strip_ticks           | int       | config     | 1 if the node is stripping ticks 0 otherwise.
 * rollover_window_ns    | uint64_t  | config     | The window over which the node is checking for the rollover bug.
 * last_good_delta_ns    | int64_t   | time delta | The last measured time delta between arista and NIC times from packets outside the rollover window.
 */

/** \cond NODOC */

ST_STRUCT(sc_arista7280_64bit_ts_stats)
  ST_FIELD(int,      strip_ticks,              config)
  ST_FIELD(uint64_t, rollover_window_ns,       config)
  ST_FIELD(int64_t,  last_good_delta_ns,       config)
ST_STRUCT_END

/** \endcond NODOC */
