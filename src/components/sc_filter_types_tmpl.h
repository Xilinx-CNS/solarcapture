/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \nodestats{sc_filter}
 *
 * \brief Statistics exposed by the \noderef{sc_filter}, \noderef{sc_range_filter} and \noderef{sc_timestamp_filter} nodes.
 *
 * Name          | Type     | Data Type  | Description
 * --------------| -------- | ---------- | ----------------------------------------------------
 * pkts_rejected | uint64_t | pkt_count  | The number of packets not matched by the filter.
 */
 
/** \cond NODOC */

ST_STRUCT(sc_filter_stats)
  ST_FIELD(uint64_t, pkts_rejected, pkt_count)
ST_STRUCT_END

/** \endcond NODOC */
