/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \file
 * \brief sc_mailbox: A means to pass packets from one thread to another.
 */

#ifndef __SOLAR_CAPTURE_MAILBOX_H__
#define __SOLAR_CAPTURE_MAILBOX_H__


struct sc_mailbox;
struct sc_attr;
struct sc_thread;
struct sc_node;


/**
 * \brief Allocate a mailbox.
 *
 * \param mb_out     The allocated mailbox is returned here.
 * \param attr       Attributes (see ::sc_attr).
 * \param thread     The thread the mailbox will be in.
 *
 * \return 0 on success, or a negative error code.
 *
 * Mailboxes are used to pass packets between threads.  To communicate you
 * need a mailbox in each thread, and together they form a bi-directional
 * link.
 *
 * From SolarCapture 1.1 onwards it is not usually necessary to create
 * mailboxes explicitly: They are created automatically when objects in
 * different threads are connected together.
 */
extern int sc_mailbox_alloc(struct sc_mailbox** mb_out, const struct sc_attr* attr,
                              struct sc_thread* thread);

/**
 * \brief Connect a pair of mailboxes.
 *
 * \param mb1        The first mailbox.
 * \param mb2        The second mailbox.
 *
 * \return 0 on success, or a negative error code.
 *
 * Link a pair of mailboxes so that they can communicate.  A mailbox can
 * only be connected once.
 */
extern int sc_mailbox_connect(struct sc_mailbox* mb1, struct sc_mailbox* mb2);

/**
 * \brief Connect a mailbox to a node.
 *
 * \param mailbox    The mailbox.
 * \param node       The node.
 * \param name_opt   Optional ingress port name (may be NULL).
 *
 * \return 0 on success, or a negative error code.
 *
 * Connect the output of a mailbox to a node.  Packets passed to the
 * send-node of the paired mailbox are passed to @p node.
 */
extern int sc_mailbox_set_recv(struct sc_mailbox* mailbox,
                               struct sc_node* node,
                               const char* name_opt);

/**
 * \brief Return a mailbox's "send node".
 *
 * \param mailbox    The mailbox.
 *
 * \return The mailbox's send-node.  Packets passed to this
 * send-node are forwarded to the paired mailboxes recv-node.
 */
extern struct sc_node* sc_mailbox_get_send_node(struct sc_mailbox* mailbox);

#if SC_API_VER >= 1
/**
 * \brief Poll a mailbox.
 *
 * \param mailbox    The mailbox to poll.
 * \param list       Received packets are appended to this list.
 *
 * \return 0 on success, or a negative error code.
 *
 * This function should only be invoked on an unmanaged mailbox.  It is
 * necessary to poll a mailbox in order to receive packets from other
 * threads, and to ensure that sent packets are delivered.
 */
extern int sc_mailbox_poll(struct sc_mailbox* mailbox,
                           struct sc_packet_list* list);
#endif

#if SC_API_VER >= 1
/**
 * \brief Send a packet through a mailbox to another thread.
 *
 * \param mailbox    The mailbox.
 * \param packet     The packet to send.
 *
 * This function should only be invoked on an unmanaged mailbox.
 *
 * Invoke this function to place a packet on a mailbox's send queue.
 * NB. The packet may not actually be delivered to the remote thread until
 * a later call to sc_mailbox_poll().
 */
extern void sc_mailbox_send(struct sc_mailbox* mailbox,
                            struct sc_packet* packet);
#endif

#if SC_API_VER >= 1
/**
 * \brief Send a list of packets through a mailbox to another thread.
 *
 * \param mailbox    The mailbox.
 * \param list       The packets to send.
 *
 * This function should only be invoked on an unmanaged mailbox.
 *
 * Invoke this function to place packets on a mailbox's send queue.
 * NB. The packets may not actually be delivered to the remote thread until
 * a later call to sc_mailbox_poll().
 */
extern void sc_mailbox_send_list(struct sc_mailbox* mailbox,
                                 struct sc_packet_list* list);
#endif


#endif  /* __SOLAR_CAPTURE_MAILBOX_H__ */
/** @} */
