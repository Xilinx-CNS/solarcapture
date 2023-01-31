/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \nodestats{sc_writer}
 *
 * \brief Statistics exposed by the \noderef{sc_writer} node.
 *
 * Name        | Type     | Data Type  | Description
 * ------------| -------- | -----------| ----------------------------------------------------
 * cap_bytes   | uint64_t | byte_count | Sum of payload bytes.
 * link_bytes  | uint64_t | byte_count | Sum of frame_len (bytes on wire before snapping).
 * write_bytes | uint64_t | byte_count | Sum of bytes written to disk.
 */

/** \cond NODOC */
/* NB. These field names deliberately match sc_rate_monitor_stats. */
ST_STRUCT(sc_writer_stats)
  ST_FIELD(uint64_t, cap_bytes,                byte_count)
  ST_FIELD(uint64_t, link_bytes,               byte_count)
  ST_FIELD(uint64_t, write_bytes,              byte_count)
ST_STRUCT_END

ST_STRUCT(sc_disk_writer_stats)
  ST_FIELD(int,      async_mode,               config)
  ST_FIELD(int,      n_ios,                    config)
  ST_FIELD(int,      current_error,            error_info)
  ST_FIELD(int,      last_error,               error_info)
  ST_FIELD_STR(      error_func, 12,           error_info)

  /* Remaining fields exist only for debug purposes */
  ST_FIELD(int,      writer_state,             state_enum)
  ST_FIELD(int,      in_flight_ios,            io_count)
  ST_FIELD(int,      in_flight_pkts,           pkt_count)
  ST_FIELD(int,      backlog_pkts,             pkt_count)
  ST_FIELD(int,      wc_fill,                  byte_count)
  ST_FIELD(int,      pkt_base_offset,          byte_offset)
  ST_FIELD(int,      head_iov_len,             byte_count)
  ST_FIELD(int,      head_flags,               flags)
ST_STRUCT_END
/** \endcond NODOC */
