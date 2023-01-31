/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \nodestats{sc_subnode_helper}
 *
 * \brief Batch limiter statistics are exposed by the \noderef{sc_subnode_helper} node.
 *
 * Name              | Type      | Data Type | Description
 * ----------------- | --------- | --------- |-------------------------------------------------------------------
 * backlog_len       | uint64_t  | pkt_count | Number of packets in backlog.
 */

 /** \cond NODOC */

ST_STRUCT(sc_subnode_helper_stats)
  ST_FIELD(uint64_t, backlog_len,            pkt_count)
ST_STRUCT_END

/** \endcond NODOC */
