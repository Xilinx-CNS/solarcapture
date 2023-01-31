/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \nodestats{sc_pcap_packer}
 *
 * \brief Statistics exposed by the \noderef{sc_pcap_packer} node.
 *
 * Name          | Type     | Data Type  | Description
 * --------------| -------- | ---------- | ----------------------------------------------------
 * pcap_bytes    | uint64_t | byte_count | Sum of bytes of encapsulated data send to output.
 * buffer_low    | uint64_t | ev_count   | Number of times the pool of buffers has run out.
 */

/** \cond NODOC */
ST_STRUCT(sc_pcap_packer_stats)
  ST_FIELD(uint64_t, pcap_bytes,               byte_count)
  ST_FIELD(uint64_t, buffer_low,               ev_count)
ST_STRUCT_END
/** \endcond NODOC */
