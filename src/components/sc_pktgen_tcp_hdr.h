/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/** \cond NODOC */

/* name, width, type, default, parser_fn */

SC_HDR_FIELD("sport",        2, FIELD_INT, "0x1234", parse_uint16)
SC_HDR_FIELD("dport",        2, FIELD_INT, "0x5678", parse_uint16)
SC_HDR_FIELD("seqnum",       4, FIELD_INT, "0",      parse_uint32)
SC_HDR_FIELD("acknum",       4, FIELD_INT, "0",      parse_uint32)
SC_HDR_FIELD("data_offset",  1, FIELD_INT, "0x50",   parse_uint8)
SC_HDR_FIELD("tcpflags",     1, FIELD_INT, "0",      parse_uint8)
SC_HDR_FIELD("window_size",  2, FIELD_INT, "0x1000", parse_uint16)
SC_HDR_FIELD("tcp_xsum",     2, FIELD_INT, "0",      parse_uint16)
SC_HDR_FIELD("urgent_ptr",   2, FIELD_INT, "0",      parse_uint16)

/** \endcond NODOC */