/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \node{sc_injector}
 *
 * \brief Packets sent to an injector node are transmitted on the network.
 *
 * \nodedetails
 * An sc_injector node is used to transmit packets out of a Solarflare
 * network interface.  Packets are forwarded to the output link after they
 * have been transmitted.
 *
 * \nodeargs
 * Argument    | Optional? | Default | Type           | Description
 * ----------- | --------- | ------- | -------------- | ---------------------------------------------------------------------------------------------------------------------------
 * interface   | No        |         | ::SC_PARAM_STR | The name of the network interface to use.
 * csum_ip     | Yes       | 0       | ::SC_PARAM_INT | Set to 1 to enable offload of the IPv4 header checksum.
 * csum_tcpudp | Yes       | 0       | ::SC_PARAM_INT | Set to 1 to enable offload of TCP/UDP checksums.
 */
