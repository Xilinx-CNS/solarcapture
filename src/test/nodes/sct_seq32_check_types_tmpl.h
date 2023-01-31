/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

ST_STRUCT(sct_seq32_check_stats)
  ST_FIELD(uint64_t, resets,                   ev_count)
  ST_FIELD(uint64_t, backwards,                ev_count)
  ST_FIELD(uint64_t, gaps,                     ev_count)
  ST_FIELD(uint64_t, drops,                    pkt_count)
ST_STRUCT_END
