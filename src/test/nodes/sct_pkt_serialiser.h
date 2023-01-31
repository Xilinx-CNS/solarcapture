/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#include <inttypes.h>

/* Shared data structure for deserialisation and serialisation nodes
   Defines the attributes that are set on the packets when they are deserialised */

/* Pragmas remove structure padding */

#pragma pack(push)
#pragma pack(1)
struct sc_serialised_pkt_hdr
{
  uint32_t packet_length;
  uint32_t metadata_length;
  uint16_t flags;
  uint64_t ts_sec;
  uint32_t ts_nsec;
  uint16_t frame_len;
};

#pragma pack(pop)
