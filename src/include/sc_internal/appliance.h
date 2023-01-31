/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#ifndef __SC_APPLIANCE__H__
#define __SC_APPLIANCE__H__


#include <sc_internal/packed_stream.h>

#define STREAM_ID_STRLEN 64
#define PBH_RESERVED_BYTES 64

#define PBH_LITTLE_ENDIAN 0
#define PBH_VERSION 2
#define FH_VERSION 1


struct sc_appliance_buffer_metadata {
  uint8_t  endianness; /* both for this header and packet headers */
  uint16_t version;
  uint64_t pkt_index;  /* Index of first packet in this buffer */
  uint32_t pkt_count;  /* Number of packets in this buffer */
  uint32_t buffer_len; /* Size of this buffer in bytes (not all may be used) */
  uint32_t pkts_len;   /* Size of pkt data buffer */

  /* These record start and end times of the block in nanoseconds since epoch.
   * Note that as packet timestamps may be out-of-order these do not necessary
   * correspond to the first and last packets in the block */
  uint64_t start_ns_epoch;
  uint64_t end_ns_epoch;

  char     reserved[PBH_RESERVED_BYTES];
  char     stream_id[STREAM_ID_STRLEN];
} __attribute__((packed));


struct sc_appliance_buffer_header {
  struct sc_packed_record_header hdr;
  struct sc_appliance_buffer_metadata data;
} __attribute__((packed));


#define MAX_INDEX_DEVICENAME_LEN 256

struct sc_appliance_index_entry {
  int64_t  pkt_index;
  int32_t  pkt_count;
  int64_t  byte_offset;
  int64_t  start_ns_epoch;
  int64_t  end_ns_epoch;
  int64_t  update_ts_sec;
  char     stream_id[STREAM_ID_STRLEN];
  char     devicename[MAX_INDEX_DEVICENAME_LEN];
} __attribute__((packed));


struct sc_appliance_block_writer_session_close_msg {
  uint64_t allocate_offset;
  char     devicename[MAX_INDEX_DEVICENAME_LEN];
} __attribute__((packed));



/* If this changes then this should be updated in structs.py in the
 * appliance repo */
enum validation_type {BW_REQUEST = 0, BW_RESPONSE = 1};


struct bw_validation_message {
  int32_t        type;
  int32_t        device_id;
  uint64_t       uid;
  uint64_t       valid_region_start;
  uint64_t       valid_region_end;
  uint64_t       wrap_count;
} __attribute__((packed));


enum flow_type {FLOW_RECORD_FILE, FLOW_BLOCK_FILE};

struct flow_header {
  uint8_t         endianness;
  uint16_t        version;
  uint8_t         flow_type;
  uint64_t        stream_id;
  uint64_t        first_pkt_idx;
  uint64_t        last_pkt_idx;
  uint64_t        start_time_sec;
  uint32_t        start_time_nsec;
  uint64_t        end_time_sec;
  uint32_t        end_time_nsec;
  uint32_t        num_flows;
  uint32_t        length;
} __attribute__((packed));


struct sc_appliance_flow_record_entry_db {
  struct flow_header     flow_hdr;
  int64_t                byte_offset;
  int64_t                update_ts_sec;
  uint32_t               byte_length;
  char                   devicename[MAX_INDEX_DEVICENAME_LEN];
} __attribute__((packed)); /* to make unit tests in appliance code possible */


#endif /* __SC_APPLIANCE__H__ */
