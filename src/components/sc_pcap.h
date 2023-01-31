/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/** \cond NODOC */
#ifndef __SC_PCAP_H__
#define __SC_PCAP_H__


#define PCAP_MAGIC             0xa1b2c3d4
#define PCAP_MAGIC_BSWAP       0xd4c3b2a1
/* For details of libpcap support for nanosecond format, visit:
 * http://anonsvn.wireshark.org/viewvc/trunk/wiretap/libpcap.h?revision=37543
 */
#define PCAP_NSEC_MAGIC        0xa1b23c4d
#define PCAP_NSEC_MAGIC_BSWAP  0x4d3cb2a1


struct pcap_file_hdr {
  uint32_t magic_number;   /* magic number */
  uint16_t version_major;  /* major version number */
  uint16_t version_minor;  /* minor version number */
  int32_t  thiszone;       /* GMT to local correction */
  uint32_t sigfigs;        /* accuracy of timestamps */
  uint32_t snap;           /* max length of captured packets, in octets */
  uint32_t network;        /* data link type */
};


struct pcap_rec_hdr {
  uint32_t ts_sec;         /* timestamp seconds */
  uint32_t ts_subsec;      /* timestamp in ms or ns */
  uint32_t incl_len;       /* number of octets of packet saved in file */
  uint32_t orig_len;       /* actual length of packet */
};


enum ts_type {
  ts_micro = 1,
  ts_nano  = 2,
};

#endif  /* __SC_PCAP_H__ */
/** \endcond NODOC */
