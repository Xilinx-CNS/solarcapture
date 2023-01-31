/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#ifndef __SC_STREAM_H__
#define __SC_STREAM_H__

#include <sc_internal/vi.h>

enum {
  SC_SF_ALL              = 0x1,
  SC_SF_ETH_DHOST        = 0x2,
  SC_SF_ETH_VLAN_ID      = 0x4,
  SC_SF_IP4_PROTOCOL     = 0x8,
  SC_SF_IP4_DEST_ADDR    = 0x10,
  SC_SF_IP4_SOURCE_ADDR  = 0x20,
  SC_SF_IP4_DEST_PORT    = 0x40,
  SC_SF_IP4_SOURCE_PORT  = 0x80,
  SC_SF_ETH_TYPE         = 0x100,
  SC_SF_ETH_SHOST        = 0x200,
  SC_SF_MISMATCH         = 0x400,
};


struct sc_stream {
  struct sc_session* st_tg;
  /* Bit mask indicating which of the remaing fields are valid. */
  unsigned fields;
  uint8_t  eth_dhost[6];
  uint8_t  eth_shost[6];
  uint16_t eth_vlan_id;
  uint16_t eth_type;
  uint8_t  ip4_protocol;
  uint32_t ip4_dest_addr;
  uint32_t ip4_source_addr;
  uint16_t ip4_dest_port;
  uint16_t ip4_source_port;
  enum sc_capture_mode capture_mode;
  enum sc_capture_point capture_point;
  int      promiscuous;
  int      vid_optional;
};


extern int sc_stream_add(struct sc_stream*, void* obj,
                         enum sc_capture_mode mode, int promiscuous,
                         enum sc_capture_point capture_point,
                         int (*add_fn)(void* obj, ef_filter_spec*));


#endif  /* __SC_STREAM_H__ */
