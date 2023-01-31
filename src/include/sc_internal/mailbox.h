/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#ifndef __SC_MAILBOX_H__
#define __SC_MAILBOX_H__


struct sc_mbox_slot {
  volatile uintptr_t v;
  uintptr_t filler[SC_CACHE_LINE_SIZE - sizeof(uintptr_t)];
} __attribute__ ((aligned (SC_CACHE_LINE_SIZE)));


struct sc_mailbox {
  /* Effectively constant. */
  int                          mb_id;
  struct sc_mbox_slot*         mb_send_slot;
  struct sc_node_impl*         mb_recv_node;
  struct sc_thread*            mb_thread;
  struct sc_thread*            mb_remote_thread;
  struct sc_mailbox_stats*     mb_stats;
  struct sc_callback*          mb_timer_cb;

  /* Written by send path. */
  struct sc_node_impl          mb_send_node;
  struct sc_packet_list        mb_send_list;
  uintptr_t                    mb_send_slot_v;
  unsigned                     mb_n_sent;

  /* Written by receive path. */
  uintptr_t                    mb_recv_slot_v;
  unsigned                     mb_n_recv;
  struct sc_packet_list        mb_recv_q;

  /* Written by peer's send path.  Aligned onto its own cache line. */
  struct sc_mbox_slot          mb_recv_slot;
};


#define SC_MAILBOX_FROM_NODE_IMPL(n)                    \
  SC_CONTAINER(struct sc_mailbox, mb_send_node, (n))


extern const struct sc_node_type    sc_mailbox_send_node_type;


/* Returns peer mailbox or NULL if not connected. */
extern struct sc_mailbox* sc_mailbox_get_peer(struct sc_mailbox*);

/* Returns this mailbox's thread. */
extern struct sc_thread* sc_mailbox_get_thread(struct sc_mailbox*);

/* Returns the peer thread, or NULL if not connected. */
extern struct sc_thread* sc_mailbox_get_remote_thread(struct sc_mailbox*);

/* Set new batching parameters for a mailbox. */
extern void sc_mailbox_set_batching_send(struct sc_mailbox*,
                                         const struct sc_attr*);
extern void sc_mailbox_set_batching_recv(struct sc_mailbox*,
                                         const struct sc_attr*);


static inline int sc_node_is_mailbox(const struct sc_node* node)
{
  return node->nd_type == &sc_mailbox_send_node_type;
}


#endif  /* __SC_MAILBOX_H__ */
