/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#include "internal.h"


enum {
  SC_DEBUG_PKTS,
  SC_DEBUG_PKT_LISTS,
  SC_DEBUG_ALL,
};


static void sc_internal_error(struct sc_session* tg, const char* exp,
                              const char* func, int line, const char* caller,
                              const char* ctx1, const char* ctx2)
{
  const char*const msg =
    "ERROR: SolarCapture detected internal error.  This may be due to a bug\n"
    "in SolarCapture, or in an application embedding SolarCapture, or in a\n"
    "plugin extension.\n";
  sc_log(tg, "%s", msg);
  sc_log(tg, "ERROR: exp=%s in %s:%d\n", exp, func, line);
  sc_log(tg, "ERROR: context: %s %s %s\n", caller, ctx1, ctx2);
  abort();
}


#define check(x)                                                        \
  do {                                                                  \
    if( ! (x) )                                                         \
      sc_internal_error(tg, #x, __func__, __LINE__, caller, ctx1, ctx2); \
  } while( 0 )


int ___sc_validate_pbuf(struct sc_session* tg, struct sc_packet* packet,
                        const char* caller, const char* ctx1, const char* ctx2)
{
  check(packet != NULL);
  struct sc_pkt* pkt = SC_PKT_FROM_PACKET(packet);
  check(pkt != NULL);
  check(pkt->sp_usr.iov == pkt->sp_iov_storage);
  return 0;
}


int ___sc_validate_packet(struct sc_session* tg, struct sc_packet* packet,
                          const struct sc_bitmask* pools, const char* caller,
                          const char* ctx1, const char* ctx2)
{
  struct sc_pkt* pkt;
  struct sc_packet** pnext;
  struct sc_pkt* f;
  int i, iov_bytes;

  check(___sc_validate_pbuf(tg, packet, caller, ctx1, ctx2) == 0);
  pkt = SC_PKT_FROM_PACKET(packet);

  check(pools == NULL || sc_bitmask_is_set(pools, (pkt)->sp_pkt_pool_id));
  check(pkt->sp_usr.frags_n < SC_PKT_MAX_IOVS);

  if( pkt->sp_ref_count != 0 ) {
    return 0; /*  TODO: some checking of RHD packets? */
  }

  if( pkt->sp_usr.frags_n == 0 ) {
    check(pkt->sp_usr.frags == NULL);
    check(pkt->sp_usr.frags_tail == &pkt->sp_usr.frags);
  }
  else {
    check(pkt->sp_usr.frags != NULL);
    check(pkt->sp_usr.frags_tail != &pkt->sp_usr.frags);
    pnext = &pkt->sp_usr.frags;
    f = NULL;  /* suppress compiler warning */
    iov_bytes = pkt->sp_usr.iov[0].iov_len;

    for( i = 0; i < pkt->sp_usr.frags_n; ++i ) {
      check(*pnext != NULL);
      f = SC_PKT_FROM_PACKET(*pnext);
      pnext = &f->sp_usr.next;
      check(___sc_validate_pbuf(tg, &f->sp_usr, caller, ctx1, ctx2) == 0);
      check(f->sp_usr.frags_n == 0);
      check(f->sp_usr.frags == NULL);
      check(f->sp_usr.frags_tail == &f->sp_usr.frags);
      /* We used to do the following check, but it is now legal for
       * fragments to be from a different pool when wrapping (even if not
       * ref counting).  TODO: Would be nice to be able to do this check
       * when not wrapped...perhaps look at info in sc_pkt_pool?
       *
       * check(f->sp_pkt_pool_id == pkt->sp_pkt_pool_id);
       */
      iov_bytes += pkt->sp_usr.iov[i + 1].iov_len;
    }
    check(pkt->sp_usr.frags_tail == pnext);
  }

  return 0;
}


int ___sc_validate_list_path(struct sc_session* tg, struct sc_packet_list* pl,
                             const struct sc_bitmask* pools, const char* caller,
                             const char* ctx1, const char* ctx2)
{
  check(pl != NULL);

  if( pl->num_pkts == 0 ) {
    check(pl->num_frags == 0);
    check(pl->head == NULL);
    check(pl->tail == &pl->head);
    return 0;
  }

  check(pl->head != NULL);
  struct sc_packet** pnext = &pl->head;
  struct sc_pkt* pkt = NULL;
  int i;

  for( i = 0; i < pl->num_pkts; ++i ) {
    check(*pnext != NULL);
    pkt = SC_PKT_FROM_PACKET(*pnext);
    pnext = &pkt->sp_usr.next;
    check(___sc_validate_packet(tg, &pkt->sp_usr,
                                pools, caller, ctx1, ctx2) == 0);
  }

  check(pkt->sp_usr.next == NULL);
  check(pl->tail == &pkt->sp_usr.next);

  return 0;
}


#ifndef NDEBUG

static int sc_debug_level(void)
{
  static int dl = -1;
  const char* s;
  if( dl < 0 )
    dl = (s = getenv("SC_DEBUG")) ? atoi(s) : SC_DEBUG_ALL;
  return dl;
}


int __sc_validate_pbuf(struct sc_session* tg, struct sc_packet* pkt,
                       const char* caller,
                       const char* ctx1, const char* ctx2)
{
  if( sc_debug_level() >= SC_DEBUG_PKTS )
    return ___sc_validate_pbuf(tg, pkt, caller, ctx1, ctx2);
  else
    return 0;
}


int __sc_validate_packet(struct sc_session* tg, struct sc_packet* pkt,
                         const struct sc_bitmask* pools, const char* caller,
                         const char* ctx1, const char* ctx2)
{
  if( sc_debug_level() >= SC_DEBUG_PKTS )
    return ___sc_validate_packet(tg, pkt, pools, caller, ctx1, ctx2);
  else
    return 0;
}


int __sc_validate_list_path(struct sc_session* tg, struct sc_packet_list* pl,
                            const struct sc_bitmask* pools, const char* caller,
                            const char* ctx1, const char* ctx2)
{
  if( sc_debug_level() >= SC_DEBUG_PKT_LISTS )
    return ___sc_validate_list_path(tg, pl, pools, caller, ctx1, ctx2);
  else if( sc_debug_level() >= SC_DEBUG_PKTS && pl->num_pkts > 0 )
    return ___sc_validate_packet(tg, pl->head, pools, caller, ctx1, ctx2);
  else
    return 0;
}

#endif


void sc_session_enumerate(struct sc_session* scs)
{
  struct sc_thread* t;
  int i;

  fprintf(stderr, "%s: s%d * ((struct sc_session*)%p)\n",
          __func__, scs->tg_id, scs);
  SC_DLIST_FOR_EACH_OBJ(&scs->tg_threads, t, session_link) {
    fprintf(stderr, "  t%d => * ((struct sc_thread*)%p)\n", t->id, t);
    for( i = 0; i < t->n_mailboxes; ++i )
      fprintf(stderr, "    m%d => * ((struct sc_mailbox*)%p)\n",
              t->mailboxes[i]->mb_id, t->mailboxes[i]);
  }
  for( i = 0; i < scs->tg_netifs_n; ++i )
    fprintf(stderr, "  i%d => * ((struct sc_netif*)%p)\n",
            i, scs->tg_netifs[i]);
  for( i = 0; i < scs->tg_vis_n; ++i )
    fprintf(stderr, "  v%d => * ((struct sc_ef_vi*)%p)\n",
            i, scs->tg_vis[i]);
  for( i = 0; i < scs->tg_pkt_pools_n; ++i )
    fprintf(stderr, "  p%d => * ((struct sc_pkt_pool*)%p)\n",
            i, scs->tg_pkt_pools[i]);
  for( i = 0; i < scs->tg_nodes_n; ++i )
    fprintf(stderr, "  n%d => * ((struct sc_node_impl*)%p)\n",
            i, scs->tg_nodes[i]);
}
