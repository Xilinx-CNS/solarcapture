/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/** \cond NODOC */

/* name, width, type, default, parser_fn */

SC_HDR_FIELD("dmac",          6, FIELD_MAC, "00:11:22:33:44:55", parse_mac)
SC_HDR_FIELD("smac",          6, FIELD_MAC, "00:66:77:88:99:AA", parse_mac)
SC_HDR_FIELD("vlan_eth_type", 2, FIELD_INT, "0x8100",            parse_uint16)
SC_HDR_FIELD("vlan_id",       2, FIELD_INT, "0x0123",            parse_vlan)
SC_HDR_FIELD("eth_type",      2, FIELD_INT, "0x0800",            parse_uint16)

/** \endcond NODOC */