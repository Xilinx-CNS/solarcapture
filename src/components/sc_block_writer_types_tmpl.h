/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/** \cond NODOC */

ST_STRUCT(sc_block_writer_stats)
  ST_FIELD(uint64_t, block_count,       pkt_count)
  ST_FIELD(uint64_t, n_not_enough_ios,  ev_count)
  ST_FIELD(uint64_t, n_free_ios,        ev_count)
  ST_FIELD(uint64_t, n_ios,             ev_count)
ST_STRUCT_END

/** \endcond NODOC */