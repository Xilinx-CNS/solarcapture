/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \file
 * \brief This header file defines sc_stream objects for directing packets to
 * a sc_vi instance. A packet must match all the stream criteria for it to be
 * directed by the stream to an sc_vi instance.
 */

#ifndef __SOLAR_CAPTURE_STREAM_H__
#define __SOLAR_CAPTURE_STREAM_H__


/**
 * \struct sc_stream
 * \brief A stream object.
 *
 * An ::sc_stream object specifies criteria to select packets.  The criteria
 * usually refer to fields in packet headers.
 *
 * Stream objects are used to specify which packets should be steered by an
 * adapter to a SolarCapture application via an sc_vi instance.
 *
 * Fields in this structure are not exposed, and must not be directly 
 * accessed. Instead use the functions in stream.h.
 *
 * Different adapter models, different firmware versions and different
 * firmware modes (or variants) all affect the combinations of header
 * fields and other criteria that can be matched.  Attempting to use an
 * unsupported set of criteria may fail when modifying the stream object,
 * or when adding the stream to a VI. For more information, see
 * sc_stream_set_str().
 */
struct sc_stream;

struct sc_attr;
struct sc_session;

/**
 * \brief Create a new stream object for this session.
 *
 * \param stream_out    On success, the created stream.
 * \param attr          Attributes to pass in.
 * \param scs           The session this stream is for.
 *
 * \return 0 on success, or a negative error code.
 */
extern int sc_stream_alloc(struct sc_stream** stream_out,
                           const struct sc_attr* attr, struct sc_session* scs);
/**
 * \brief Free a previously created stream.
 *
 * \param stream        The stream to free.
 *
 * \return 0, always.
 */
extern int sc_stream_free(struct sc_stream* stream);

/**
 * \brief Reinitialise a stream.
 *
 * \param stream        The stream to reinitialise.
 *
 * \return 0 on success, or a negative error code.
 */
extern int sc_stream_reset(struct sc_stream* stream);

#if SC_API_VER >= 2
/**
 * \brief Set the stream to match packets identified by a string.
 *
 * \param stream        A stream object.
 * \param str           Match criteria.
 *
 * \return 0 on success, or a negative error code.
 *
 * This call is the preferred way of configuring a stream, since it offers
 * the most flexibility.
 *
 * Different adapter types support matching on different combinations of
 * header fields.  The combinations supported also depend on firmware
 * version and firmware variant.  (The firmware variant is selected using
 * the sfboot utility).  In the tables below the firmware variants are
 * identified as follows:
 *
 * - FF: Full-featured firmware variant
 * - ULL: Ultra-low latency firmware variant
 * - CPS: Capture-packed-stream firmware variant
 *
 * The abbreviated syntax uses one of the formats shown in the table below.
 * The table also shows the adapter firmware variants that support each
 * format.
 *
 * Abbreviated syntax                                                                  | SFN7xxx
 * ----------------------------------------------------------------------------------- | -----------------
 * eth:\<dest-mac\>                                                                    | FF  ULL  CPS
 * eth:vid=\<vlan\>,\<dest-mac\>                                                       | FF  ULL
 * {udp\|tcp}:\<dest-host\>:\<dest-port\>                                              | FF  ULL  CPS
 * {udp\|tcp}:\<dest-host\>:\<dest-port\>,\<source-host\>:\<source-port\>              | FF  ULL
 * {udp\|tcp}:vid=\<vlan\>,\<dest-host\>:\<dest-port\>                                 | FF
 * {udp\|tcp}:vid=\<vlan\>,\<dest-host\>:\<dest-port\>,\<source-host\>:\<source-port\> | FF
 *
 * The full syntax allows more flexibility.  A stream is constructed as a
 * comma separated list of key-value pairs, except for the special cases
 * "all", "mismatch", "ip", "tcp", and "udp". Available keys are shown in
 * the table below:
 *
 * Key or key-value pairs    | Description
 * ------------------------- | --------------------------------------------------------------------------------------------------------------------------
 * dmac=xx:xx:xx:xx:xx:xx    | Match Ethernet destination MAC address.
 * smac=xx:xx:xx:xx:xx:xx    | Match Ethernet source MAC addres.
 * vid=INT                   | Match Ethernet outer VLAN ID.
 * eth_type=ip\|arp\|INT     | Match Ethernet ether_type.
 * shost=hostname            | Match IPv4 source host.
 * dhost=hostname            | Match IPv4 destination host.
 * ip_protocol=udp\|tcp\|INT | Match IPv4 protocol (implies eth_type=ip).
 * sport=INT                 | Match TCP or UDP source port.
 * dport=INT                 | Match TCP or UDP destination port.
 * all                       | All packets not steered elsewhere.
 * mismatch                  | All packets not steered elsewhere and not requested by the kernel network stack.
 * ip                        | Shorthand for eth_type=ip.
 * tcp                       | Shorthand for ip_protocol=tcp.
 * udp                       | Shorthand for ip_protocol=udp.
 *
 * IPv4 addresses may be given as a dotted quad or a host name that can
 * resolved with getaddrinfo().
 *
 * Supported combinations of keys are shown in the table below, together
 * with the firmware variants required:
 *
 * Key combination                                          | SFN7xxx
 * -------------------------------------------------------- | -------------
 * all                                                      | FF  ULL  CPS
 * mismatch                                                 | FF  ULL  CPS
 * vid                                                      | FF       CPS
 * dmac                                                     | FF  ULL  CPS
 * dmac, vid                                                | FF  ULL
 * ip_protocol, dhost, dport                                | FF  ULL  CPS
 * ip_protocol, dhost, dport, shost, sport                  | FF  ULL
 * [vid,] [dmac,] ip_protocol, dhost, dport                 | FF
 * [vid,] [dmac,] ip_protocol, dhost, dport, shost, sport   | FF
 * eth_type                                                 | FF  ULL
 * eth_type, vid                                            | FF  ULL  CPS
 * eth_type, dmac                                           | FF  ULL
 * ip_protocol                                              | FF  ULL
 * ip_protocol, vid                                         | FF  ULL  CPS
 * [vid,] ip_protocol, dmac                                 | FF
 */
extern int sc_stream_set_str(struct sc_stream* stream, const char* str);
#endif

/**
 * \brief Configure stream to match packets not explicitly steered elsewhere
 *
 * \param stream        A stream object.
 *
 * This stream captures packets that would otherwise be delivered to the OS
 * kernel network stack, and also packets that would normally be discarded
 * by the adapter when not in promiscuous mode.
 *
 * \return 0 on success, or a negative error code.
 */
extern int sc_stream_all(struct sc_stream* stream);

/**
 * \brief Configure stream to match packets not steered elsewhere and not
 * requested by the kernel network stack
 *
 * \param stream        A stream object.
 *
 * This stream matches packets that would normally be discarded by the
 * network adapter when it is not in promiscuous mode.
 *
 * \return 0 on success, or a negative error code.
 */
extern int sc_stream_mismatch(struct sc_stream* stream);

/**
 * \brief Configure this stream to capture all packets with the matching protocol, destination hostname and
 * destination port.
 *
 * \param stream        A stream object.
 * \param protocol      The transport layer protocol to match against.
 * \param dhost         The destination hostname to match against.
 * \param dport         The destination port to match against.
 *
 * \return 0 on success, or a negative error code.
 */
extern int sc_stream_ip_dest_hostport(struct sc_stream* stream, int protocol,
                                      const char* dhost, const char* dport);

/**
 * \brief Configure this stream to capture all packets with the matching protocol, source hostname and
 * source port.
 *
 * \param stream        A stream object.
 * \param shost         The source hostname to match against.
 * \param sport         The source port to match against.
 *
 * \return 0 on success, or a negative error code.
 */
extern int sc_stream_ip_source_hostport(struct sc_stream* stream,
                                        const char* shost, const char* sport);
/**
 * \brief Add the destination MAC address to the set of fields matched.
 *
 * \param stream        A stream object.
 * \param mac_addr      The destination MAC address to match.
 *
 * \return 0 on success, or a negative error code.
 */
extern int sc_stream_eth_dhost(struct sc_stream* stream,
                               const uint8_t* mac_addr);

/**
 * \brief Add the VLAN ID to the set of fields matched.
 *
 * \param stream        A stream object.
 * \param vlan_id       The VLAN ID to match against.
 *
 * \return 0 on success, or a negative error code.
 */
extern int sc_stream_eth_vlan_id(struct sc_stream* stream, int vlan_id);

#if SC_API_VER >= 1
/**
 * \brief Add the source MAC address to the set of fields matched.
 *
 * \param stream        A stream object.
 * \param mac_addr      The source MAC address to match.
 *
 * \return 0 on success, or a negative error code.
 */
extern int sc_stream_eth_shost(struct sc_stream* stream,
                               const uint8_t* mac_addr);

/**
 * \brief Add the Ethernet ether_type field to the set of fields matched.
 *
 * \param stream        A stream object.
 * \param eth_type      The ether_type to match (host endian).
 *
 * \return 0 on success, or a negative error code.
 */
extern int sc_stream_eth_type(struct sc_stream* stream, uint16_t eth_type);


/**
 * \brief Add the IPv4 destination to the set of fields matched.
 *
 * \param stream        A stream object.
 * \param dhost         The destination host name or IP to match.
 *
 * \return 0 on success, or a negative error code.
 */
extern int sc_stream_ip_dest_host(struct sc_stream* stream, const char* dhost);

/**
 * \brief Add the TCP or UDP destination port to the set of fields matched.
 *
 * \param stream        A stream object.
 * \param dport         The destination port to match.
 *
 * \return 0 on success, or a negative error code.
 */
extern int sc_stream_ip_dest_port(struct sc_stream* stream, const char* dport);

/**
 * \brief Add the IPv4 source to the set of fields matched.
 *
 * \param stream        A stream object.
 * \param shost         The source host name or IP to match.
 *
 * \return 0 on success, or a negative error code.
 */
extern int sc_stream_ip_source_host(struct sc_stream* stream,
                                    const char* shost);

/**
 * \brief Add the TCP or UDP source port to the set of fields matched.
 *
 * \param stream        A stream object.
 * \param sport         The source port to match.
 *
 * \return 0 on success, or a negative error code.
 */
extern int sc_stream_ip_source_port(struct sc_stream* stream,
                                    const char* sport);

/**
 * \brief Add the IP protocol to the set of fields matched.
 *
 * \param stream        A stream object.
 * \param protocol      The IP protocol to match.
 *
 * \return 0 on success, or a negative error code.
 */
extern int sc_stream_ip_protocol(struct sc_stream* stream, int protocol);
#endif


#endif  /* __SOLAR_CAPTURE_STREAM_H__ */
/** @} */
