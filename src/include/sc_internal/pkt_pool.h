/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#ifndef __SC_PKT_POOL_H__
#define __SC_PKT_POOL_H__


/* When sc_pkt_pool_get is called, and an in-order packet is retreived from
 * current pool, we prefetch ahead. A stride of 8 packets is chosen for
 * prefetching because around 24 packets has been observed to work well for
 * refilling the rx_ring
 */
#define PREFETCH_STRIDE 24

struct sc_packet;
struct sc_thread;
struct sc_node_impl;
struct sc_netif;
struct sc_packed_packet;


struct sc_pkt_bin {
  struct sc_dlist link;
  int pb_n_bufs;
  int pb_total_bufs;
  int pb_cur_buf;
  size_t pb_sc_pkt_buf_len;
  /* We buffer returned packets until all the packets for a bin have been
   * returned. This helps in two ways. First, for the current bin, we can
   * serve packets while allowing packets to be returned and buffered without
   * messing up our counts. Second, in case we have no fully available bins
   * we can still find packets to use (unless the pool is completely empty)
   */
  struct sc_packet*  pb_returned;
  int                pb_returned_n;
};


/* If we ever want to expose any of the pool's internals, then this is
 * where they should go (and this definition would move into the public
 * headers).
 */
struct sc_pool {
  void*                reserved;
};


struct sc_pkt_pool {
  int                  pp_n_bufs;
  ssize_t              pp_buf_size;        /* size of payload area    */
  int                  pp_refill_batch;
  int                  pp_prefetch_stride;
  int                  pp_id;
  int                  pp_is_inline;
  struct sc_thread*    pp_thread;
  struct sc_node_impl* pp_refill_node;
  uint64_t             pp_netifs;
  /* A bin can be in one of three states: current, available and used
   * Current means that the bin is currently serving buffer requests.
   * There is at most one current bin at a time.
   * Available means the bin has no buffers in use.
   * Used means the bin has buffers in flight.
   * When the current bin is exhausted, it is moved to used, and only
   * a bin that is available can take its place.
   */
  struct sc_dlist       pp_avail_bins;
  struct sc_dlist       pp_used_bins;
  struct sc_pkt_bin*    pp_current_bin;

  struct sc_packet_list pp_put_backlog;
  /* This is similar to [sc_thread::timers].  It is the head of the list of
   * events, and its threshold is very high so that it won't ever be
   * reached.  This makes adding and checking callbacks rather elegant...
   */
  struct sc_callback_impl pp_non_empty_events;
  /* If true, this pool should not be shared. */
  int                  pp_private;
  struct sc_pool_stats*pp_stats;
  struct sc_callback*  pp_cb_backlog;
  char*                pp_mmap_fname;
  void*                pp_mmap_base;
  uintptr_t            pp_bin_mask;
  int                  pp_n_requested_bufs;
  ssize_t              pp_requested_bytes;
  ssize_t              pp_min_bytes;
  ssize_t              pp_bin_size_rq;
  bool                 pp_request_hpages;
  bool                 pp_require_hpages;
  bool                 pp_use_full_bins;
  struct sc_pkt_pool*  pp_linked_pool;
  int                  pp_mmap_fd;
  struct sc_pool       pp_public;
  struct sc_object_impl pp_obj;

  struct sc_pkt_pool_blob* pp_blobs;
  /* Size of each sc_pkt buffer.  For inline buffers this includes sc_pkt
   * and the payload area.  For non-inline it is just sc_pkt.
   */
  size_t               pp_sc_pkt_buf_len;
};


#define SC_PKT_POOL_FROM_POOL(pool)                     \
  SC_CONTAINER(struct sc_pkt_pool, pp_public, (pool))


extern void sc_pkt_pool_alloc(struct sc_pkt_pool**, const struct sc_attr*,
                              struct sc_thread*);
extern int sc_pkt_pool_free(struct sc_session*, struct sc_pkt_pool*);

extern void sc_pkt_pool_add_netif(struct sc_pkt_pool*, struct sc_netif*);

extern void sc_pkt_pool_request_bufs(struct sc_pkt_pool*,
                                     const struct sc_attr*);

/* Returns the number of packet buffers allocated, or -1 if none were
 * allocated.  If unable to allocate all: Sets errno to ENOMEM if unable to
 * allocate memory, or ENOBUFS if unable to register memory.
 */
extern int sc_pkt_pool_alloc_bufs(struct sc_pkt_pool* pp);

extern int sc_pkt_pool_bufs_per_bin(const struct sc_pkt_pool* pp);

extern void sc_pkt_pool_post_refill(struct sc_pkt_pool* pp);

extern struct sc_pkt* sc_pkt_pool_get_slow(struct sc_pkt_pool* pp);
extern void sc_pkt_pool_put_slow(struct sc_pkt_pool* pp, struct sc_pkt* pkt);
extern void sc_pkt_bin_on_full(struct sc_pkt_pool*, struct sc_pkt_bin*);

extern int sc_pkt_pool_callback_check(struct sc_callback_impl*);

/* Configures buffers to be mmaped to the path provided.
 */
extern int sc_pkt_pool_set_mmap_path(struct sc_pkt_pool* pool, char const* path);

extern uint64_t sc_pkt_pool_calc_num_bufs(const struct sc_pkt_pool* pp,
                                          ssize_t pool_size,
                                          int64_t pool_n_bufs);


/* Caller is responsible for freeing *path_out
 */
extern int sc_pkt_pool_get_mmap_path(struct sc_pkt_pool* pool, char** path_out);


inline static struct sc_pkt_bin* __sc_pkt_to_bin(struct sc_pkt* pkt,
                                                 struct sc_pkt_pool* pool)
{
  return (struct sc_pkt_bin*)((uintptr_t)pkt & pool->pp_bin_mask);
}


inline static struct sc_pkt* __sc_bin_to_pkt(struct sc_pkt_bin* bin, int id)
{
  return (void*) ((char*) bin + (id + 1) * (bin->pb_sc_pkt_buf_len));
}


static inline int sc_pkt_pool_is_empty(const struct sc_pkt_pool* pp)
{
  return pp->pp_n_bufs == 0;
}


static inline int sc_pkt_pool_available_bufs(const struct sc_pkt_pool* pp)
{
  return pp->pp_n_bufs;
}


static inline int sc_pool_available_bufs(const struct sc_pool* pool)
{
  return sc_pkt_pool_available_bufs(SC_PKT_POOL_FROM_POOL(pool));
}


static inline void sc_pkt_bin_put(struct sc_pkt_pool* pp, struct sc_pkt* pkt)
{
  struct sc_pkt_bin* bin = __sc_pkt_to_bin(pkt, pp);
  pkt->sp_usr.next = bin->pb_returned;
  bin->pb_returned = &(pkt->sp_usr);
  ++(bin->pb_returned_n);
  if( ! pp->pp_use_full_bins )
    ++(pp->pp_n_bufs);
  if( bin->pb_returned_n == bin->pb_total_bufs )
    sc_pkt_bin_on_full(pp, bin);
}


static inline void sc_pkt_pool_put(struct sc_pkt_pool* pp, struct sc_pkt* pkt)
{
  /* The incoming packet may belong to a bin in the used list or to the
   * current bin.  It should never be for a bin in the available list.
   */
  struct sc_pkt_bin* bin = __sc_pkt_to_bin(pkt, pp);
  assert( bin->pb_n_bufs + bin->pb_returned_n < bin->pb_total_bufs );
  (void) bin;  /* compiler warning (only used in the assert) */
  if( pkt->sp_usr.frags_n == 0 ) {
    sc_pkt_bin_put(pp, pkt);
    pp->pp_stats->n_bufs = pp->pp_n_bufs;
  }
  else {
    sc_pkt_pool_put_slow(pp, pkt);
  }
}


static inline struct sc_pkt* __sc_pkt_pool_get(struct sc_pkt_pool* pp)
{
  assert( ! sc_pkt_pool_is_empty(pp) );
  struct sc_pkt_bin* bin = pp->pp_current_bin;

  if( bin != NULL && bin->pb_n_bufs > 1 ) {
    struct sc_pkt* pkt = __sc_bin_to_pkt(bin, bin->pb_cur_buf);
    ++(bin->pb_cur_buf);
    --(bin->pb_n_bufs);
    --(pp->pp_n_bufs);
    pp->pp_stats->n_bufs = pp->pp_n_bufs;
    return pkt;
  }
  else {
    return sc_pkt_pool_get_slow(pp);
  }
}


static inline struct sc_pkt* sc_pkt_pool_get(struct sc_pkt_pool* pp)
{
  struct sc_pkt* pkt = __sc_pkt_pool_get(pp);

  struct sc_pkt* prefetch_pkt = (void*) ((char*) pkt + pp->pp_prefetch_stride);
  __builtin_prefetch(prefetch_pkt, 1, 2);
  __builtin_prefetch(&prefetch_pkt->sp_iov_storage[0], 1, 2);
  __builtin_prefetch(&prefetch_pkt->sp_ef_addr[0], 1, 2);
  __builtin_prefetch((char*)prefetch_pkt + 256, 1, 2);

  assert(pp->pp_n_bufs >= 0);
  assert(pkt->sp_usr.frags == NULL);
  assert(pkt->sp_usr.frags_tail == &(pkt->sp_usr.frags));
  assert(pkt->sp_usr.frags_n == 0);
  assert(pkt->sp_pkt_pool_id == pp->pp_id);

  return pkt;
}


#endif  /* __SC_PKT_POOL_H__ */
