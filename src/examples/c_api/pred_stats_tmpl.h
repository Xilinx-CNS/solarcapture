/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

ST_STRUCT(pred_stats)
/* ST_FIELD(uint64_t, display_name, 'kind') */
  ST_FIELD(uint64_t, packets_last_second, pkt_count )
  ST_FIELD(uint64_t, subtotal_packets, pkt_count )
ST_STRUCT_END
