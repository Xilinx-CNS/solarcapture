/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \nodestats{sc_shm}
 *
 * \brief Statistics exposed by the \noderef{sc_shm_broadcast} and
 * \noderef{sc_shm_import} nodes.
 *
 * Name                    | Type     | Data Type  | Description
 * ------------------------| -------- | ---------- | ----------------------------------------------------
 * pkts_dropped            | uint64_t | pkt_count  | The number of packets dropped by the node.
 * wake_msgs               | uint64_t | ev_count   | The number of wake messages.
 * sleep_notifies          | uint64_t | ev_count   | The number of sleep notifications.
 * pkts_in_flight          | uint64_t | pkt_count  | The number of packets in flight.
 * reliable_pkts_in_flight | uint64_t | pkt_count  | The number of packets in flight in reliable mode.
 */

/** \cond NODOC */

ST_STRUCT(sc_shm_stats)
  ST_FIELD(uint64_t, pkts_dropped,                pkt_count)
  ST_FIELD(uint64_t, wake_msgs,                   ev_count)
  ST_FIELD(uint64_t, sleep_notifies,              ev_count)
  ST_FIELD(uint64_t, pkts_in_flight,              pkt_count)
  ST_FIELD(uint64_t, reliable_pkts_in_flight,     pkt_count)
ST_STRUCT_END

/** \endcond NODOC */
