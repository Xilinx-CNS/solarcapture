/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

ST_STRUCT(sct_tickler_stats)
  ST_FIELD(uint64_t, tx_syn,                   pkt_count)
  ST_FIELD(uint64_t, tx_msg,                   pkt_count)
  ST_FIELD(uint64_t, tx_ack,                   pkt_count)
  ST_FIELD(uint64_t, tx_fin,                   pkt_count)
  ST_FIELD(uint64_t, rx_msg,                   pkt_count)
  ST_FIELD(uint64_t, rx_msg_psh,               pkt_count)
  ST_FIELD(uint64_t, rx_msg_dup,               pkt_count)
  ST_FIELD(uint64_t, rx_ack,                   pkt_count)
  ST_FIELD(uint64_t, rx_bytes,                 byte_count)
  ST_FIELD(uint64_t, not_for_me,               pkt_count)
  ST_FIELD(double,   latency,                  latency_s)
ST_STRUCT_END
