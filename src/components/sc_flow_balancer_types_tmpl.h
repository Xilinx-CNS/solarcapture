/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \nodestats{sc_flow_balancer}
 *
 * \brief Statistics exposed by the \noderef{sc_flow_balancer} node.
 *
 * Name                | Type     | Data Type  | Description
 * ------------------- | -------- | ---------- | --------------------------------------------------------------------------
 * flow_table_capacity | uint64_t | magnitude  | Capacity of the flow table.
 * avg_flow_load       | uint64_t | bandwidth  | Moving average of the load per flow.
 * n_flows             | int      | magnitude  | Current number of flows directed to this output.
 * total_flows         | uint64_t | magnitude  | Total number of flows directed to this output.
 * total_work          | uint64_t | magnitude  | Estimate of total work directed to this output.
 * load_est_short      | uint64_t | bandwidth  | Short-term load estimate for this output.
 * load_est_long       | uint64_t | bandwidth  | Long-term load estimate for this output.
 * drops               | uint64_t | pkt_count  | Number of packets dropped at this output due to running out of buffering.
 */

/** \cond NODOC */
ST_STRUCT(sc_flow_balancer_stats)
  ST_FIELD(uint64_t, flow_table_capacity, magnitude)
  ST_FIELD(uint64_t, avg_flow_load,       bandwidth)
ST_STRUCT_END

ST_STRUCT(sc_flow_balancer_output_stats)
  ST_FIELD(int,      n_flows,             magnitude)
  ST_FIELD(uint64_t, total_flows,         magnitude)
  ST_FIELD(uint64_t, total_work,          magnitude)
  ST_FIELD(uint64_t, load_est_short,      bandwidth)
  ST_FIELD(uint64_t, load_est_long,       bandwidth)
  ST_FIELD(uint64_t, drops,               pkt_count)
ST_STRUCT_END
/** \endcond NODOC */
