/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/** \cond NODOC */

/* name, width, type, default, parser_fn */

SC_HDR_FIELD("ihl_ver",  1, FIELD_INT,   "0x45",    parse_uint8)
SC_HDR_FIELD("tos",      1, FIELD_INT,   "0",       parse_uint8)
SC_HDR_FIELD("ip_len",   2, FIELD_LEN,   "0",       parse_uint16)
SC_HDR_FIELD("id",       2, FIELD_INT,   "0",       parse_uint16)
SC_HDR_FIELD("frag_off", 2, FIELD_INT,   "0",       parse_uint16)
SC_HDR_FIELD("ttl",      1, FIELD_INT,   "0xFF",    parse_uint8)
SC_HDR_FIELD("protocol", 1, FIELD_PROTO, "udp",     parse_proto)
SC_HDR_FIELD("ip_xsum",  2, FIELD_INT,   "0",       parse_uint16)
SC_HDR_FIELD("saddr",    4, FIELD_IP,    "1.2.3.4", parse_ip4)
SC_HDR_FIELD("daddr",    4, FIELD_IP,    "1.2.3.5", parse_ip4)

/** \endcond NODOC */