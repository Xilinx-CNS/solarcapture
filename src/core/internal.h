/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#ifndef __INTERNAL_H__
#define __INTERNAL_H__

#ifndef _GNU_SOURCE // Python.h seems to defines this
#define _GNU_SOURCE
#endif

#include <sc_internal.h>
#include <sc_internal/ef_vi.h>

#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <inttypes.h>


#if SC_VI_DEBUG_STATS
# define VI_DBG_STATS(x)    do{ x; }while(0)
#else
# define VI_DBG_STATS(x)    do{} while(0)
#endif

#if SC_NODE_STATS
# define NODE_STATS(x)      do{ x; }while(0)
#else
# define NODE_STATS(x)      do{}while(0)
#endif

#if SC_MBOX_DEBUG_STATS
# define MBOX_DBG_STATS(x)  do{ x; }while(0)
#else
# define MBOX_DBG_STATS(x)  do{}while(0)
#endif


#define TRY(x)   SC_TRY(x)
#define TEST(x)  SC_TEST(x)

#define TG_TRY_MSG(tg, exp, ...)                        \
  do {                                                  \
    int __rc = (exp);                                   \
    if( __rc < 0 )                                      \
      return sc_set_err((tg), (errno), __VA_ARGS__);    \
  } while( 0 )

#define T_TRY_MSG(thread, exp, ...)                     \
  TG_TRY_MSG((thread)->session, exp, __VA_ARGS__)

#define t_set_err(t, errno_code, ...)                           \
  sc_set_err((t)->session, (errno_code), __VA_ARGS__)

#define t_fwd_err(t, ...)                       \
  sc_fwd_err((t)->session, __VA_ARGS__)


#if defined(__PPC__) || defined(__PPC64__)
# define HUGE_PAGE_SZ  ((size_t) 16 * 1024 * 1024)
# define SYS_PAGE_SZ   ((size_t) 64 * 1024)
#elif defined(__i386__) || defined(__x86_64__)
# define HUGE_PAGE_SZ  ((size_t) 2 * 1024 * 1024)
# define SYS_PAGE_SZ   ((size_t) 4 * 1024)
#else
# error "Need HUGE_PAGE_SZ and SYS_PAGE_SZ for this processor."
#endif


struct sc_free_demux {
  /* IDEA: We could add an extra layer of indirection here so that we can
   * easily batch together packets for different pools that are in the same
   * remote thread.
   */
  struct sc_node_link** pp_id_to_link;
  unsigned              len;
};


extern const struct sc_node_factory sc_refill_node_factory;
extern const struct sc_node_factory sc_ref_count_undo_sc_node_factory;
extern const struct sc_node_factory sc_injector_sc_node_factory;
extern const struct sc_node_type    sc_injector_node_type;
extern const struct sc_node_factory sc_free_demux_node_factory;
extern const struct sc_node_type    sc_free_demux_node_type;


extern __thread struct sc_thread* sc_thread_current;


extern int  sc_stats_new_session(struct sc_session*, const struct sc_attr*);

extern void sc_ef_vi_poll(struct sc_ef_vi*);
extern void sc_ef_vi_stop(struct sc_ef_vi*);
extern void sc_ef_vi_set_attr(struct sc_attr* attr, unsigned sc_ef_vi_flags,
                              struct sc_ef_vi* vi);
typedef int (*sc_ef_vi_alloc_fn) (struct sc_ef_vi* vi, int evq_capacity,
                                  int rxq_capacity, int txq_capacity,
                                  enum ef_vi_flags flags, void* data);
extern int sc_ef_vi_alloc_feats(struct sc_session*, struct sc_ef_vi*,
                                struct sc_netif*, const struct sc_attr*,
                                enum ef_vi_flags viflags,
                                sc_ef_vi_alloc_fn alloc_fn, void* alloc_data,
                                unsigned* sc_ef_vi_flags_out);

extern int sc_thread_add_mailbox(struct sc_thread*, struct sc_mailbox*);
extern void sc_thread_add_vi(struct sc_thread*, struct sc_ef_vi*);
extern void sc_thread_get_pool(struct sc_thread*, const struct sc_attr*,
                               struct sc_netif*, struct sc_pkt_pool**);
extern void sc_thread_stop_vis(struct sc_thread* t);
extern bool sc_thread_has_ready_mailbox(struct sc_thread*);

extern int  sc_node_prep(struct sc_node_impl*);
extern void sc_node_init(struct sc_node_impl*, const struct sc_node_type*,
                         struct sc_thread*, char* name, const char*);
extern struct sc_node* sc_node_get_ingress_node(struct sc_node*, char**);
extern struct sc_node_link_impl* sc_node_find_link(struct sc_node*,
                                                   const char*);
extern void sc_node_propagate_pools(struct sc_node_impl*,
                                    const struct sc_bitmask* pools);
extern struct sc_node_link_impl* __sc_node_add_link(struct sc_node_impl*,
                                                    const char*,
                                                    struct sc_node_impl*,
                                                    char* to_name_opt);
extern struct sc_node* sc_node_add_link_cross_thread(struct sc_thread*,
                                                     struct sc_node_impl*,
                                                     const char*);
extern void sc_node_end_of_stream(struct sc_node_impl*);
extern bool sc_node_subnodes_are_preped(struct sc_node_impl*);

extern void sc_setup_pkt_free(struct sc_session*, struct sc_node_impl**,
                              struct sc_thread*, const struct sc_bitmask*);
extern void sc_node_link_setup_pkt_free(struct sc_node_link_impl*);

extern int sc_affinity_set(int affinity);
extern int sc_affinity_save_and_set(struct sc_session*, int affinity);
extern int sc_affinity_restore(struct sc_session*);
extern int sc_thread_affinity_save_and_set(struct sc_thread*);
extern int sc_thread_affinity_restore(struct sc_thread*);

extern int __sc_validate_pbuf(struct sc_session*,
                              struct sc_packet*, const char* caller,
                              const char* ctx1, const char* ctx2);
extern int __sc_validate_packet(struct sc_session*, struct sc_packet*,
                                const struct sc_bitmask* pools,
                                const char* caller,
                                const char* ctx1, const char* ctx2);
extern int __sc_validate_list_path(struct sc_session*, struct sc_packet_list*,
                                   const struct sc_bitmask* pools,
                                   const char* caller,
                                   const char* ctx1, const char* ctx2);

extern int sc_get_vi_mode(struct sc_session *tg,
                          const struct sc_attr *attr,
                          enum sc_vi_mode *mode);
extern int sc_get_capture_mode(struct sc_session *tg,
                               const struct sc_attr *attr,
                               enum sc_capture_mode *mode);
extern int sc_get_capture_point(struct sc_session* tg,
                                const char* attr,
                                enum sc_capture_point* capture_point);
int sc_get_interface_strip_fcs(struct sc_session* tg, const char* interface,
                               int* strip_fcs_out);

extern void sc_session_enumerate(struct sc_session*);

extern int sc_parse_size_string(int64_t* parsed_val, const char* val);

#if 0 //??
#define sc_pkt_validate_path(pkt, pools, ctx1, ctx2)    \
  assert((1llu << (pkt)->sp_pkt_pool_id) & (pools))

#define sc_packet_validate_path(packet, pools, ctx1, ctx2)              \
  sc_pkt_validate_path(SC_PKT_FROM_PACKET(packet), (pools), (ctx1), (ctx2))
#endif

#ifdef NDEBUG
# define sc_validate_pbuf(tg, pkt, c1, c2)                do{}while(0)
# define sc_validate_packet(tg, pkt, c1, c2)              do{}while(0)
# define sc_validate_packet_path(tg, pkt, pools, c1, c2)  do{}while(0)
# define sc_validate_list(tg, pl, c1, c2)                 do{}while(0)
# define sc_validate_list_path(tg, pl, pools, c1, c2)     do{}while(0)
#else
# define sc_validate_pbuf(tg, pkt, c1, c2)                      \
       __sc_validate_pbuf((tg), (pkt), __func__, (c1), (c2))
# define sc_validate_packet(tg, pkt, c1, c2)                            \
       __sc_validate_packet((tg), (pkt), 0xffffffffffffffffllu, __func__, \
                            (c1), (c2))
# define sc_validate_packet_path(tg, pkt, pools, c1, c2)                \
       __sc_validate_packet((tg), (pkt), (pools), __func__, (c1), (c2))
# define sc_validate_list_path(tg, pl, pools, c1, c2)                   \
       __sc_validate_list_path((tg), (pl), (pools), __func__, (c1), (c2))
# define sc_validate_list(tg, pl, c1, c2)                               \
         __sc_validate_list_path((tg), (pl), NULL, __func__, (c1), (c2))
#endif


/* Offset of start of DMA area from beginning of [struct sc_pkt]. */
#define PKT_DMA_OFF  ALIGN_FWD(sizeof(struct sc_pkt), SC_CACHE_LINE_SIZE)


/* Minimum distance between start of one packet and the next.  This is only
 * used for prefetching, so we can get away with using a magic number!
 */
#define PACKED_STREAM_MIN_STRIDE 192

# define RX_RING_MAX_DEFAULT_PACKED_STREAM_64K  104
# define N_BUFS_RX_DEFAULT_PACKED_STREAM_64K    (256 * 16)
# define RX_RING_MAX_DEFAULT_PACKED_STREAM_1M   16
# define N_BUFS_RX_DEFAULT_PACKED_STREAM_1M     256
# define RX_REFILL_BATCH_HIGH_PACKED_STREAM     8
# define RX_REFILL_BATCH_LOW_PACKED_STREAM      8


static inline void sc_node_dispatch(struct sc_node_impl* ni)
{
  sc_tracefp(ni->ni_thread->session, "%s: n%d:%s num_pkts=%d\n",
             __func__, ni->ni_id, ni->ni_node.nd_name,
             ni->ni_pkt_list.num_pkts);
  assert(ni->ni_state == SC_NODE_PREPED);
  assert(! sc_packet_list_is_empty(&ni->ni_pkt_list));
  sc_packet_list_finalise(&ni->ni_pkt_list);
  sc_validate_list_path(ni->ni_thread->session, &ni->ni_pkt_list,
                        &ni->ni_src_pools, ni->ni_node.nd_name, "");
  NODE_STATS(ni->ni_stats->pkts_in += ni->ni_pkt_list.num_pkts);
  ni->ni_node.nd_type->nt_pkts_fn(&ni->ni_node, &ni->ni_pkt_list);
  sc_packet_list_init(&ni->ni_pkt_list);
}


static inline void sc_node_need_dispatch(struct sc_node_impl* ni)
{
  struct sc_node_impl* ni2;
  struct sc_dlist* l;

  assert(!sc_packet_list_is_empty(&ni->ni_pkt_list));
  if( sc_dlist_is_empty(&ni->ni_dispatch_link) ) {
    /* Keep [dispatch_list] sorted by [ni_dispatch_order].  Reason for this
     * is to ensure that when the graph branches and re-joins we'll process
     * the branches before nodes after the join.  This avoids the nodes
     * after the join getting invoked multiple times with subsets of the
     * batch.
     *
     * It is important to get a batch all at once so that we can preserve
     * order if desired.  When the graph branches the packet order can get
     * shuffled.  But at least if you see the whole batch you can put it
     * back into the correct order.
     */
    for( l = ni->ni_thread->dispatch_list.next;
         l != &ni->ni_thread->dispatch_list;
         l = l->next ) {
      ni2 = SC_CONTAINER(struct sc_node_impl, ni_dispatch_link, l);
      if( ni2->ni_dispatch_order > ni->ni_dispatch_order )
        break;
    }
    /* Think of this as sc_dlist_insert_before(in_list, link); */
    sc_dlist_push_tail(l, &ni->ni_dispatch_link);
  }
}


static inline void
  sc_pools_to_threads(struct sc_session* tg,
                      const struct sc_bitmask* pools,
                      struct sc_bitmask* threads)
{
  sc_bitmask_init(threads);

  int pp_id;
  for( pp_id = 0; pp_id < tg->tg_pkt_pools_n; ++pp_id )
    if( sc_bitmask_is_set(pools, pp_id) )
      sc_bitmask_set(threads, tg->tg_pkt_pools[pp_id]->pp_thread->id);
}


static inline struct sc_callback_impl*
  sc_thread_timer_head(struct sc_thread* t)
{
  return SC_CALLBACK_IMPL_FROM_LINK(t->timers.cbi_public.cb_link.next);
}


static inline struct sc_callback_impl*
  sc_pkt_pool_non_empty_head(struct sc_pkt_pool* pp)
{
  struct sc_callback_impl* cbi = &pp->pp_non_empty_events;
  return SC_CALLBACK_IMPL_FROM_LINK(cbi->cbi_public.cb_link.next);
}


struct ef_pd;


static inline struct sc_pkt_pool* sc_pkt_get_pool(const struct sc_session* scs,
                                                  const struct sc_pkt* pkt)
{
  assert(pkt->sp_pkt_pool_id < scs->tg_pkt_pools_n);
  return scs->tg_pkt_pools[pkt->sp_pkt_pool_id];
}


/* This is likely to be slightly faster than sc_pkt_get_buf() when you know
 * you've got an inline pkt because the [sp_buf] field is quite likely to
 * not be in cache.
 */
static inline uint8_t* sc_pkt_get_buf_inline(const struct sc_pkt* pkt)
{
  assert(pkt->sp_is_inline);
  return (uint8_t*) pkt + PKT_DMA_OFF;
}


#endif  /* __INTERNAL_H__ */
