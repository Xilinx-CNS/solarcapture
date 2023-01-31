/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#ifndef __SC_PACKED_STREAM__H__
#define __SC_PACKED_STREAM__H__


/*
 * If (ps_pkt_start_offset > sizeof(struct sc_packed_packet)) then the
 * space between sc_packed_packet and the payload contains a set of option
 * records containing additional information.  Each record starts with
 * sc_packed_record_header.  The set of records ends at the start of the
 * payload, or with a record header with  prh_type==SC_PACKED_RECORD_END.
 */
struct sc_packed_record_header {
  uint16_t prh_type;
  uint16_t prh_len;
};
#pragma pack()


enum sc_packed_record_type {
  SC_PACKED_RECORD_END                    = 0,
  SC_PACKED_RECORD_APPLIANCE_BLOCK_HEADER = 1,
};


#endif /* __SC_PACKED_STREAM__H__ */
