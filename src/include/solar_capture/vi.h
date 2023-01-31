/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \file
 * \brief sc_vi: Supports receiving packets from the network.
 */

#ifndef __SOLAR_CAPTURE_VI_H__
#define __SOLAR_CAPTURE_VI_H__


struct sc_attr;
struct sc_thread;
struct sc_session;
struct sc_vi_group;
struct sc_node;
/**
 * \struct sc_vi
 * \brief A VI object.
 *
 * Fields in this structure are not exposed, and must not be directly 
 * accessed. Instead use the functions in vi.h.
 */
struct sc_vi;
struct sc_stream;

/**
 * \brief Allocate a VI instance.
 *
 * \param vi_out          The allocated VI is returned here
 * \param attr            Attributes
 * \param thread          The thread the VI will be in
 * \param interface       The network interface to receive packets from
 *
 * \return 0 on success, or a negative error code.
 *
 * A VI is a "virtual network interface" and supports receiving packets
 * from the network.  Packets received by a VI are passed to nodes
 * (sc_node) for processing.
 */
extern int sc_vi_alloc(struct sc_vi** vi_out, const struct sc_attr* attr,
                       struct sc_thread* thread, const char* interface);

/**
 * \brief Set the node a VI should deliver its received packets to.
 *
 * \param vi              The VI receiving packets
 * \param node            The node to deliver packets to
 * \param name_opt        Optional ingress port name (may be NULL)
 *
 * \return 0 on success, or a negative error code.
 *
 * Since SolarCapture 1.1, if @p node is in a different thread from @p vi, then
 * this function automatically creates a link between the threads using
 * mailboxes.
 */
extern int sc_vi_set_recv_node(struct sc_vi* vi, struct sc_node* node,
                               const char* name_opt);

/**
 * \brief Direct a packet stream to a VI.
 *
 * \param vi              The VI receiving packets
 * \param stream          The packet stream
 *
 * \return 0 on success, or a negative error code.
 *
 * Arrange for the packet stream identified by @p stream to be copied or
 * steered to @p vi.
 */
extern int sc_vi_add_stream(struct sc_vi* vi, struct sc_stream* stream);

/**
 * \brief Return the thread associated with a VI.
 *
 * \param vi              The VI
 *
 * \return The thread associated with the VI.
 */
extern struct sc_thread* sc_vi_get_thread(const struct sc_vi* vi);


#if SC_API_VER >= 3
/**
 * \brief Return the name of the network interface associated with a VI.
 *
 * \param vi              The VI
 *
 * \return The name of the network interface associated with the
 * ::sc_vi object
 *
 * This call returns the name of the network interface associated with the
 * ::sc_vi object.  This can be different from the interface name used to
 * create the ::sc_vi when application clustering is used.
 *
 * The network interface name is most often needed so that the application
 * can create an injector on the same interface as a VI.
 */
extern const char* sc_vi_get_interface_name(const struct sc_vi* vi);
#endif


/**
 * \brief Allocate a VI group.
 *
 * \param vi_out          The allocated VI is returned here
 * \param attr            Attributes
 * \param session         The SolarCapture session
 * \param interface       The network interface to receive packets from
 * \param num_vis         The number of VIs in the group
 *
 * \return 0 on success, or a negative error code.
 *
 * A VI group provides a way to distribute packet capture over multiple
 * threads.  A VI group consists of a set of VIs, each of which receives a
 * distinct subset of the streams directed at the group.
 *
 * Streams are directed to a group by calling ::sc_vi_group_add_stream().
 *
 * While a VI allocated from a group receives packets from streams directed
 * to the group (::sc_vi_group_add_stream()), it is also possible to use
 * ::sc_vi_add_stream() to direct a specific stream to a specific member of
 * the group.
 */
extern int sc_vi_group_alloc(struct sc_vi_group** vi_out,
                             const struct sc_attr* attr,
                             struct sc_session* session,
                             const char* interface, int num_vis);

/**
 * \brief Return the session associated with a VI group.
 *
 * \param vi_group        The VI group
 *
 * \return The session associated with the VI group.
 */
extern struct sc_session*
  sc_vi_group_get_session(const struct sc_vi_group* vi_group);

/**
 * \brief Allocate a VI instance from a VI group.
 *
 * \param vi_out          The allocated VI is returned here
 * \param attr            Attributes
 * \param thread          The thread the VI will be in
 * \param vi_group        The VI group
 *
 * \return 0 on success, or a negative error code.
 *
 * See also ::sc_vi_group_alloc() and ::sc_vi_alloc().
 */
extern int sc_vi_alloc_from_group(struct sc_vi** vi_out,
                                  const struct sc_attr* attr,
                                  struct sc_thread* thread,
                                  struct sc_vi_group* vi_group);

/**
 * \brief Direct a packet stream to a group of VIs.
 *
 * \param vi_group        The VI group receiving packets
 * \param stream          The packet stream
 *
 * \return The session associated with the VI group.
 *
 * Arrange for the packet stream identified by @p stream to be copied or
 * steered to the VIs that comprise @p vi_group.
 *
 * Note that packets are spread over the VIs in a group by computing a hash
 * on the addresses in the packet headers.  Normally the hash is computed
 * over the IP addresses, and for TCP packets also the port numbers.  The
 * hash selects a VI within the group, so that packets with the same
 * addresses are consistently delivered to the same VI.
 *
 * If @p stream identifies a set of packets that all have the same source and
 * destination IP addresses (and ports in the case of TCP) then they will
 * all be received by a single VI.
 */
extern int sc_vi_group_add_stream(struct sc_vi_group* vi_group, struct sc_stream* stream);


#endif  /* __SOLAR_CAPTURE_VI_H__ */
/** @} */
