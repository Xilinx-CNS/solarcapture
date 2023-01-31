/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \file
 * \brief sc_packet_list: A list of packets.
 */

#ifndef __SOLAR_CAPTURE_EXT_PACKET_LIST_H__
#define __SOLAR_CAPTURE_EXT_PACKET_LIST_H__

/**
 * \brief A list of packets or packet buffers.
 */
struct sc_packet_list {
  struct sc_packet*   head;     /**< Head of list */
  struct sc_packet**  tail;     /**< Ptr to next field in tail of list */
  int                 num_pkts; /**< Number of pkts in the list */
  int                 num_frags;/**< Number of pkt frags in the list */
};

/** \cond NODOC */
/**
 * \brief Initialise a list (list is not finalised).
 * \param l          The packet list.
 */
static inline void __sc_packet_list_init(struct sc_packet_list* l)
{
  l->num_pkts = 0;
  l->num_frags = 0;
  l->tail = &l->head;
}
/** \endcond */


/**
 * \brief Initialise a list
 * \param l          The packet list.
 */
static inline void sc_packet_list_init(struct sc_packet_list* l)
{
  __sc_packet_list_init(l);
  l->head = NULL;
}

/**
 * \brief Check if packet list is empty
 * \param l          The packet list.
 * \return           True (1) if the packet list is empty, false (0) otherwise
 */
static inline int sc_packet_list_is_empty(const struct sc_packet_list* l)
{
  return l->num_pkts == 0;
}


/**
 * \brief Finalise a list
 * \param l          The packet list.
 *
 * If a list is not finalised, it is possible that the next pointer of
 * tail is not NULL.
 */
static inline void sc_packet_list_finalise(struct sc_packet_list* l)
{
  *(l->tail) = NULL;
}


/**
 * \brief Return the tail of current tail of the list
 * \param l          The packet list.
 * \return           The tail of current tail of the list.
 */
static inline struct sc_packet* sc_packet_list_tail(struct sc_packet_list* l)
{
  return (struct sc_packet*)
    ((char*) l->tail - SC_MEMBER_OFFSET(struct sc_packet, next));
}

/** \cond NODOC */
/**
 * \brief Push a packet to the head of a non-empty list.
 *
 * \param pl    The packet list.
 * \param p     The packet.
 *
 * WARNING: This must only be used on a non-empty list.
 */

static inline void __sc_packet_list_push_head(struct sc_packet_list* pl,
                                              struct sc_packet* p)
{
  p->next = pl->head;
  pl->head = p;
  pl->num_pkts += 1;
  pl->num_frags += p->frags_n;
}
/* \endcond */

/**
 * \brief Push a packet to the head of a list.
 *
 * \param pl    The packet list.
 * \param p     The packet.
 */
static inline void sc_packet_list_push_head(struct sc_packet_list* pl,
                                            struct sc_packet* p)
{
  if( pl->num_pkts == 0 )
    pl->tail = &(p->next);
  __sc_packet_list_push_head(pl, p);
}

/** \cond NODOC */
/**
 * \brief Append a packet to a list.
 *
 * \param pl    The packet list.
 * \param p     The packet.
 * List is not finalised unless [p->next] is NULL.
 */
static inline void __sc_packet_list_append(struct sc_packet_list* l,
                                           struct sc_packet* p)
{
  *(l->tail) = p;
  l->tail = &p->next;
  ++l->num_pkts;
  l->num_frags += p->frags_n;
}
/** \endcond */

/**
 * \brief Append a packet to a list and finalise.
 * \param l     The packet list.
 * \param p     The packet.
 */
static inline void sc_packet_list_append(struct sc_packet_list* l,
                                         struct sc_packet* p)
{
  __sc_packet_list_append(l, p);
  p->next = NULL;
}

/** \cond NODOC */
static inline void __sc_packet_list_append_list(struct sc_packet_list* l,
                                                struct sc_packet* head,
                                                struct sc_packet** tail,
                                                int num_pkts, int num_frags)
{
  *(l->tail) = head;
  l->num_pkts += num_pkts;
  l->num_frags += num_frags;
  l->tail = tail;
}
/** \endcond */

/**
 * \brief Append a list to a list
 *
 * \param dest  The list to be extended.
 * \param src   The list to be appended to @p dest.
 *
 * After this call @p dest is finalised if and only if @p src was finalised.
 *
 * @p src must be non-empty.
 */
static inline void sc_packet_list_append_list(struct sc_packet_list* dest,
                                              struct sc_packet_list* src)
{
  assert(!sc_packet_list_is_empty(src));
  __sc_packet_list_append_list(dest, src->head, src->tail,
                               src->num_pkts, src->num_frags);
}

/** \cond NODOC */
/**
 * \brief Remove and return the head of the list.
 *
 * \param pl    The packet list.
 *
 * This must only be invoked on a non-empty list.  If the tail of the list
 * is popped then the list's tail pointer will be left in an invalid state.
 */
static inline struct sc_packet*
  __sc_packet_list_pop_head(struct sc_packet_list* pl)
{
  struct sc_packet* p = pl->head;
  pl->head = p->next;
  pl->num_pkts -= 1;
  pl->num_frags -= p->frags_n;
  return p;
}
/** \endcond */


/**
 * \brief Remove and return the head of the list.
 *
 * \param pl    The packet list.
 *
 * \return      The removed head of the packet list.
 *
 * This must only be invoked on a non-empty list.
 */
static inline struct sc_packet*
  sc_packet_list_pop_head(struct sc_packet_list* pl)
{
  struct sc_packet* p = __sc_packet_list_pop_head(pl);
  if( pl->num_pkts == 0 )
    pl->tail = &pl->head;
  else
    sc_packet_prefetch_r(pl->head->next);

  return p;
}

#endif  /* __SOLAR_CAPTURE_EXT_PACKET_LIST_H__ */
/** @} */
