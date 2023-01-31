/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/** \cond NODOC */

/* name, width, type, default, parser_fn */

SC_HDR_FIELD("sport",    2, FIELD_INT, "0x1234", parse_uint16)
SC_HDR_FIELD("dport",    2, FIELD_INT, "0x5678", parse_uint16)
SC_HDR_FIELD("udp_len",  2, FIELD_LEN, "0",      parse_uint16)
SC_HDR_FIELD("udp_xsum", 2, FIELD_INT, "0",      parse_uint16)

/** \endcond NODOC */