/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \page sc_arista7150_ts_stats sc_arista_ts, switch_model=7150
 *
 * \brief Arista timestamp statistics that are exposed by the \noderef{sc_arista_ts} node when switch_model=7150.
 *
 * Name                  | Type      | Data Type | Description
 * --------------------- | --------- | --------- |-------------------------------------------------------------------
 * max_host_t_delta      | double    | config    | Max delta in seconds the node can compute a tick-delta over.
 * max_freq_error        | double    | config    | Max ppm allowed between measured and expected tick frequency before entering no sync state.
 * lost_sync_ms          | int       | config    | Time in milliseconds spent in lost sync state.
 * no_sync_ms            | int       | config    | Time in milliseconds spent in no sync state.
 * exp_tick_freq         | int       | config    | The expected tick frequency in Hz.
 * strip_ticks           | int       | config    | 1 if the node is stripping ticks 0 otherwise.
 * log_level             | int       | config    | The log level.
 * tick_freq             | double    | magnitude | The measured tick frequency in Hz.
 * n_keyframes           | uint64_t  | pkt_count | Number of keyframes processed by the node.
 * n_filtered_oui        | uint64_t  | pkt_count | Number of packets filtered out by OUI.
 * n_filtered_other      | uint64_t  | pkt_count | Number of packets filtered out for other reasons.
 * n_skew_zero_ticks     | uint64_t  | pkt_count | Number of packets without a timestamp (ticks is zero).
 * n_lost_sync           | uint64_t  | pkt_count | Number of packets processed whilst in lost sync state.
 * n_no_sync             | uint64_t  | pkt_count | Number of packets processed whilst in  no sync state.
 * n_kf_len_mismatch     | uint64_t  | pkt_count | Number of packets received where the keyframe length did not match.
 * n_kf_dev_mismatch     | uint64_t  | pkt_count | Number of packets received where the device field did not match.
 * n_kf_bad_fcs_type     | uint64_t  | pkt_count | Number of keyframes with a bad FCS.
 * kf_switch_drops       | uint64_t  | pkt_count | Number of keyframes dropped by the switch.
 * n_kf_big_gap          | uint64_t  | pkt_count | Number of large gaps between keyframes.
 * n_skew                | uint64_t  | pkt_count | Number of skews.
 * n_host_ts_misorder    | uint64_t  | ev_count  | Host timestamp detected out-of-order.
 * n_kf_host_ts_misorder | uint64_t  | ev_count  | Host timestamp of keyframe detected out-of-order.
 * enter_no_sync         | uint64_t  | ev_count  | Number of times the node has entered no sync state.
 * enter_sync1           | uint64_t  | ev_count  | Number of times the node has entered sync1 state.
 * enter_sync2           | uint64_t  | ev_count  | Number of times the node has entered sync2 state.
 * enter_lost_sync       | uint64_t  | ev_count  | Number of times the node has entered lost sync state.
 */

/** \cond NODOC */

ST_STRUCT(sc_arista7150_ts_stats)
  ST_FIELD(double,   max_host_t_delta,         config)
  ST_FIELD(double,   max_freq_error,           config)
  ST_FIELD(int,      lost_sync_ms,             config)
  ST_FIELD(int,      no_sync_ms,               config)
  ST_FIELD(int,      exp_tick_freq,            config)
  ST_FIELD(int,      strip_ticks,              config)
  ST_FIELD(int,      log_level,                config)
  ST_FIELD(int,      has_fcs,                  config)
  ST_FIELD(double,   tick_freq,                magnitude)
  ST_FIELD(uint64_t, n_keyframes,              pkt_count)
  ST_FIELD(uint64_t, n_filtered_oui,           pkt_count)
  ST_FIELD(uint64_t, n_filtered_other,         pkt_count)
  ST_FIELD(uint64_t, n_skew_zero_ticks,        pkt_count)
  ST_FIELD(uint64_t, n_lost_sync,              pkt_count)
  ST_FIELD(uint64_t, n_no_sync,                pkt_count)
  ST_FIELD(uint64_t, n_kf_len_mismatch,        pkt_count)
  ST_FIELD(uint64_t, n_kf_dev_mismatch,        pkt_count)
  ST_FIELD(uint64_t, n_kf_bad_fcs_type,        pkt_count)
  ST_FIELD(uint64_t, kf_switch_drops,          pkt_count)
  ST_FIELD(uint64_t, n_kf_big_gap,             ev_count)
  ST_FIELD(uint64_t, n_skew,                   pkt_count)
  ST_FIELD(uint64_t, n_host_ts_misorder,       ev_count)
  ST_FIELD(uint64_t, enter_no_sync,            ev_count)
  ST_FIELD(uint64_t, enter_sync1,              ev_count)
  ST_FIELD(uint64_t, enter_sync2,              ev_count)
  ST_FIELD(uint64_t, enter_lost_sync,          ev_count)
ST_STRUCT_END

/** \endcond NODOC */
