/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#include "internal.h"
#include <sc_internal/ef_vi.h>
#include <sc_internal/packed_stream.h>

#include <limits.h>
#include <asm/mman.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <fcntl.h>


/* WARNING: Old kernels ignore this flag, so mmap(MAP_HUGETLB) may succeed
 * even if there aren't any huge pages.
 */
#ifndef MAP_HUGETLB
#define MAP_HUGETLB  0x40000  /* Create huge page mapping.  */
#endif


#define MMAP_FLAGS_FMT  "%s%s%s%s%s%s%s%s"
#define MMAP_FLAGS_ARG(f)                       \
  ((f) & MAP_SHARED)    ? "Sha":"",             \
  ((f) & MAP_PRIVATE)   ? "Pri":"",             \
  ((f) & MAP_ANONYMOUS) ? "Ano":"",             \
  ((f) & MAP_HUGETLB)   ? "Hug":"",             \
  ((f) & MAP_LOCKED)    ? "Lkd":"",             \
  ((f) & MAP_NONBLOCK)  ? "Nnb":"",             \
  ((f) & MAP_FIXED)     ? "Fix":"",             \
  ((f) & MAP_POPULATE)  ? "Pop":""


#define pp_scs(pp)  ((pp)->pp_thread->session)


struct sc_memreg {
  struct sc_memreg*  next;
  ef_memreg          mr;
  ef_driver_handle   dh;
};


struct sc_pkt_pool_blob_buf {
  void*                       bb_base;
  size_t                      bb_len;
  void*                       bb_mmap_base;
  size_t                      bb_mmap_len;
  bool                        bb_huge;
};


/* An allocation of memory for a packet pool.  ppb_sc_pkt is always
 * allocated, and contains the [sc_pkt]s.  If this is not an inline pool
 * then ppb_pl is also allocated, and contains the payload buffers.
 */
struct sc_pkt_pool_blob {
  struct sc_pkt_pool_blob*    ppb_next;
  struct sc_pkt_pool_blob_buf ppb_sc_pkt;
  struct sc_pkt_pool_blob_buf ppb_pl;
  ef_driver_handle            ppb_dh[SC_MAX_NETIFS];
  struct sc_memreg*           ppb_memregs;
  unsigned                    ppb_n_bufs;
};


static size_t least_pow_2_ge(size_t val)
{
  /* Slow, but at least it is portable! */
  size_t rc = 1;
  while( rc < val )
    rc *= 2;
  return rc;
}


static size_t greatest_pow_2_le(size_t val)
{
  /* Slow, but at least it is portable! */
  size_t rc = 1;
  while( rc * 2 <= val )
    rc *= 2;
  return rc;
}


static inline unsigned bufs_per_bin(const struct sc_pkt_pool* pp,
                                    size_t bin_size)
{
  return bin_size / pp->pp_sc_pkt_buf_len - 1;
}


static inline size_t pp_bin_size(const struct sc_pkt_pool* pp)
{
  assert( pp->pp_bin_mask != 0 );
  return ~pp->pp_bin_mask + 1;
}


static inline unsigned pp_bufs_per_bin(const struct sc_pkt_pool* pp)
{
  return bufs_per_bin(pp, pp_bin_size(pp));
}


static inline unsigned num_bins(const struct sc_pkt_pool* pp,
                                unsigned bin_size, unsigned n_bufs)
{
  int bufs_per_bin_ = bufs_per_bin(pp, bin_size);
  return (n_bufs + bufs_per_bin_ - 1) / bufs_per_bin_;
}


static inline unsigned pp_num_bins(const struct sc_pkt_pool* pp,
                                   unsigned n_bufs)
{
  int bufs_per_bin = pp_bufs_per_bin(pp);
  return (n_bufs + bufs_per_bin - 1) / bufs_per_bin;
}


static size_t pp_sc_pkt_mem_size(const struct sc_pkt_pool* pp, unsigned n_bufs)
{
  unsigned bufs_per_bin = pp_bufs_per_bin(pp);
  size_t rc = (n_bufs / bufs_per_bin) * pp_bin_size(pp);
  n_bufs -= (n_bufs / bufs_per_bin) * bufs_per_bin;
  if( n_bufs )
    rc += (n_bufs + 1) * pp->pp_sc_pkt_buf_len;
  return rc;
}


static struct sc_pkt* pp_blob_get_pkt(struct sc_pkt_pool* pp,
                                      struct sc_pkt_pool_blob* blob,
                                      unsigned id)
{
  unsigned bufs_per_bin = pp_bufs_per_bin(pp);
  unsigned bin_i = id / bufs_per_bin;
  unsigned bin_pkt_i = id % bufs_per_bin;
  struct sc_pkt_bin* bin =
    (void*) ((uint8_t*) blob->ppb_sc_pkt.bb_base + bin_i * pp_bin_size(pp));
  struct sc_pkt* pkt = __sc_bin_to_pkt(bin, bin_pkt_i);
  SC_TEST( __sc_pkt_to_bin(pkt, pp) == bin );
  return pkt;
}


static int pkts_in_used_bins(struct sc_pkt_pool* pool)
{
  int count = 0;
  struct sc_pkt_bin* bin;
  SC_DLIST_FOR_EACH_OBJ(&pool->pp_used_bins, bin, link)
    count += bin->pb_returned_n;
  return count;
}


static int pkts_in_avail_bins(struct sc_pkt_pool* pool)
{
  int count = 0;
  struct sc_pkt_bin* bin;
  SC_DLIST_FOR_EACH_OBJ(&pool->pp_avail_bins, bin, link) {
    count+= bin->pb_n_bufs;
    SC_TEST(bin->pb_n_bufs == bin->pb_total_bufs);
    SC_TEST(bin->pb_returned_n == 0);
  }
  return count;
}


static bool verify_pool(struct sc_pkt_pool* pool)
 {
  int used_b_pkts = pkts_in_used_bins(pool);
  int avail_b_pkts = pkts_in_avail_bins(pool);
  int cur_b_pkts = (pool->pp_current_bin == NULL)? 0:
    pool->pp_current_bin->pb_n_bufs +
    pool->pp_current_bin->pb_returned_n;

  int total_b_pkts = used_b_pkts + avail_b_pkts + cur_b_pkts;
  SC_TEST(total_b_pkts == pool->pp_n_bufs);
  return (total_b_pkts == pool->pp_n_bufs);
}


static inline void sc_pkt_pool_return_bin(struct sc_pkt_pool* pool,
                                          struct sc_pkt_bin* bin)
{
  assert( bin != pool->pp_current_bin );
  assert( bin->pb_returned_n == bin->pb_total_bufs );
  assert( ! sc_dlist_is_empty(&(pool->pp_used_bins)) );

  /* NB. No need to clear pb_returned as we'll never drop off the tail. */
  bin->pb_returned_n = 0;
  bin->pb_n_bufs = bin->pb_total_bufs;
  /* Making bin available                 */
  /* Bin currently has to be in used list */
  sc_dlist_remove(&bin->link);
  sc_dlist_push_head(&pool->pp_avail_bins, &bin->link);
  ++(pool->pp_stats->n_full_bins);
  if( pool->pp_use_full_bins ) {
    pool->pp_n_bufs += bin->pb_n_bufs;
    pool->pp_stats->n_bufs = pool->pp_n_bufs;
  }
}


void sc_pkt_pool_alloc(struct sc_pkt_pool** pool_out,
                       const struct sc_attr* attr,
                       struct sc_thread* thread)
{
  struct sc_session* tg = thread->session;
  struct sc_pkt_pool* pool = sc_thread_calloc(thread, sizeof(*pool));
  TEST(pool != NULL);

  sc_object_impl_init(&(pool->pp_obj), SC_OBJ_POOL);
  /* pool->pp_head = NULL; */
  /* pool->pp_n_bufs = 0; */
  pool->pp_buf_size = ( attr->buf_size < 0 ) ?
    SC_DMA_PKT_BUF_LEN : attr->buf_size;
  pool->pp_is_inline = attr->buf_inline;
  pool->pp_bin_size_rq = attr->pool_bin_size;
  if( attr->pool_refill_max_pkts > 0 )
    pool->pp_refill_batch = attr->pool_refill_max_pkts;
  else if( attr->batch_max_pkts > 0 )
    pool->pp_refill_batch = attr->batch_max_pkts;
  else
    pool->pp_refill_batch = SC_POOL_REFILL_MAX_PKTS_DEFAULT;
  pool->pp_thread = thread;

  pool->pp_require_hpages = attr->require_huge_pages != 0;
  pool->pp_request_hpages =
    attr->request_huge_pages || attr->require_huge_pages;
  pool->pp_use_full_bins = attr->use_full_bins != 0;

  /* pool->pp_refill_node = NULL; */
  /* pool->pp_netifs = 0; */
  pool->pp_private = attr->private_pool;
  /* pool->pp_blobs = NULL; */
  sc_dlist_init(&pool->pp_avail_bins);
  sc_dlist_init(&pool->pp_used_bins);
  pool->pp_non_empty_events.cbi_pool_non_empty.threshold = INT_MAX;
  assert(pool->pp_non_empty_events.cbi_pool_non_empty.threshold == INT_MAX);
  sc_dlist_init(&pool->pp_non_empty_events.cbi_public.cb_link);

  pool->pp_id = tg->tg_pkt_pools_n++;
  SC_REALLOC(&tg->tg_pkt_pools, tg->tg_pkt_pools_n);
  tg->tg_pkt_pools[pool->pp_id] = pool;
  sc_packet_list_init(&pool->pp_put_backlog);
  /* pool->pp_n_requested_bufs = 0; */
  /* pool->pp_requested_bytes = 0; */
  /* pool->pp_min_bytes = 0; */
  /* pool->pp_linked_pool = NULL; */
  pool->pp_mmap_fd = -1;
  SC_TRY( sc_callback_alloc2(&pool->pp_cb_backlog, attr,
                             pool->pp_thread, "pool_backlog") );

  char* name;
  if( attr->name == NULL )
    TEST(asprintf(&name, "sc_pool(%d)", pool->pp_id) > 0);
  else
    name = strdup(attr->name);
  SC_TRY(sc_stats_add_block(thread, name, "sc_pool_stats", "p", pool->pp_id,
                            sizeof(*pool->pp_stats), &pool->pp_stats));
  free(name);
  if( attr->group_name != NULL )
    sc_stats_add_info_str(tg, "p", pool->pp_id, "group_name", attr->group_name);
  pool->pp_stats->id = pool->pp_id;
  pool->pp_stats->n_bufs = pool->pp_n_bufs;
  pool->pp_stats->interfaces = 0;
  sc_stats_add_info_int(tg, "p", pool->pp_id, "thread_id", thread->id);

  *pool_out = pool;
}


int sc_pkt_pool_set_mmap_path(struct sc_pkt_pool* pool, char const* path)
{
  if( pool->pp_mmap_fname != NULL )
    return -1;
  pool->pp_mmap_fname = strdup(path);
  return 0;
}


int sc_pkt_pool_get_mmap_path(struct sc_pkt_pool* pool, char** path_out)
{
  if( pool->pp_mmap_fname != NULL ) {
    *path_out = strdup(pool->pp_mmap_fname);
    return 0;
  }
  return -1;
}


void sc_pkt_pool_add_netif(struct sc_pkt_pool* pp, struct sc_netif* netif)
{
  /* For now we don't support adding interfaces after we've allocated the
   * memory.
   */
  SC_TEST( pp->pp_blobs == NULL );

  uint64_t netif_bit = 1llu << netif->netif_id;
  if( ! (pp->pp_netifs & netif_bit) ) {
    sc_trace(pp_scs(pp), "%s: p%d netif=%d interface=%s/%s\n",
             __func__, pp->pp_id, netif->netif_id, netif->name,
             netif->interface->if_name);
    pp->pp_netifs |= netif_bit;
    pp->pp_stats->interfaces = pp->pp_netifs;
  }
}


static void sc_pkt_init(struct sc_pkt* pkt, struct sc_pkt_pool* pp,
                        void* payload_buf)
{
  pkt->sp_len = pp->pp_buf_size;
  pkt->sp_pkt_pool_id = pp->pp_id;
  pkt->sp_is_inline = pp->pp_is_inline;
  pkt->sp_ref_count = 0;
  pkt->sp_usr.frags = NULL;
  pkt->sp_usr.frags_tail = &pkt->sp_usr.frags;
  pkt->sp_usr.frags_n = 0;
  pkt->sp_usr.iov = pkt->sp_iov_storage;
  pkt->sp_buf = payload_buf;
}


static void sc_pkt_bin_init(struct sc_pkt_bin* b, struct sc_pkt_pool* pp)
{
  b->pb_n_bufs = 0;
  b->pb_total_bufs = 0;
  b->pb_cur_buf = 0;
  b->pb_sc_pkt_buf_len = pp->pp_sc_pkt_buf_len;
  b->pb_returned = NULL;
  b->pb_returned_n = 0;
}


static unsigned n_hpages(size_t bytes)
{
  return (bytes + HUGE_PAGE_SZ - 1) / HUGE_PAGE_SZ;
}


static void sc_pkt_pool_blob_buf_touch(struct sc_pkt_pool_blob_buf* bb,
                                       size_t page_size)
{
  volatile char* p = bb->bb_base;
  volatile char* end = p + bb->bb_len;
  while( p < end ) {
    (void) *p;
    p += page_size;
  }
}


static int grow_file(int fd, size_t len)
{
  struct stat s;
  if( fstat(fd, &s) < 0 )
    return -1;
  if( s.st_size < len )
    return ftruncate(fd, len);
  else
    return 0;
}


static size_t mmap_extra(size_t bytes, size_t align, size_t page_size)
{
  if( align > page_size )
    return ALIGN_FWD(bytes + align - page_size, page_size) - bytes;
  else
    return ALIGN_FWD(bytes, page_size) - bytes;
}


static int file_is_in_hugetlbfs(int fd)
{
  /* mmap() requires that the offset be page aligned, so we make an attempt
   * with an offset that should not be acceptable for huge pages.
   *
   * NB. Some kernels also require that length be a multiple of the page
   * size, but on recent kernels (inc. rhel7) mmap with offset=0 and
   * len=SYS_PAGE_SZ succeeds on files in hugetlbfs.
   */
  if( grow_file(fd, SYS_PAGE_SZ * 2) < 0 && grow_file(fd, HUGE_PAGE_SZ) < 0 )
    return -1;
  void* m = mmap(NULL, SYS_PAGE_SZ, PROT_READ, MAP_SHARED, fd, SYS_PAGE_SZ);
  if( m == MAP_FAILED )
    return (errno == EINVAL) ? 1 : -1;
  munmap(m, SYS_PAGE_SZ);
  return 0;
}


static int sc_pkt_pool_blob_buf_alloc(struct sc_pkt_pool* pp,
                                      struct sc_pkt_pool_blob_buf* bb,
                                      size_t bytes, size_t align,
                                      bool req_huge_pages,
                                      bool require_huge_pages,
                                      bool try_map_file)
{
  int flags, mmap_fd = -1;
  size_t extra, mmap_align;

  if( pp->pp_mmap_fname && try_map_file ) {
    /* File mapping should happen at most once per pool */
    SC_TEST( pp->pp_mmap_fd < 0 );
    pp->pp_mmap_fd = open(pp->pp_mmap_fname, O_CREAT | O_RDWR, 0640);
    if( pp->pp_mmap_fd < 0 )
      return sc_set_err(pp_scs(pp), errno, "%s: ERROR: Failed to open "
                        "file '%s' for shared memory mapping\n", __func__,
                        pp->pp_mmap_fname);
    mmap_fd = pp->pp_mmap_fd;
    if( flock(pp->pp_mmap_fd, LOCK_EX | LOCK_NB) != 0 ) {
      close(pp->pp_mmap_fd);
      pp->pp_mmap_fd = -1;
      return sc_set_err(pp_scs(pp), errno, "%s: ERROR: Failed to acquire "
                        "flock on file '%s' for shared memory mapping\n",
                        __func__, pp->pp_mmap_fname);
    }
    int is_huge = file_is_in_hugetlbfs(mmap_fd);
    if( is_huge < 0 ) {
      close(pp->pp_mmap_fd);
      pp->pp_mmap_fd = -1;
      return sc_set_err(pp_scs(pp), errno, "%s: ERROR: p%d failed to grow or "
                        "map '%s'\n", __func__, pp->pp_id, pp->pp_mmap_fname);
    }
    mmap_align = is_huge ? HUGE_PAGE_SZ : SYS_PAGE_SZ;
    extra = mmap_extra(bytes, align, mmap_align);
    if( require_huge_pages && ! is_huge ) {
      close(pp->pp_mmap_fd);
      pp->pp_mmap_fd = -1;
      return sc_set_err(pp_scs(pp), errno, "%s: ERROR: require_huge_pages=1 "
                        "but '%s' is not in hugetlbfs\n", __func__,
                        pp->pp_mmap_fname);
    }
    if( grow_file(pp->pp_mmap_fd, bytes + extra) < 0 ) {
      close(pp->pp_mmap_fd);
      pp->pp_mmap_fd = -1;
      return sc_set_err(pp_scs(pp), errno, "sc_pkt_pool_blob_buf_alloc: ERROR: "
                        "failed to grow '%s' (len=%zu align=0x%zx alloc=0x%zx "
                        "huge=%d)\n", pp->pp_mmap_fname, bytes, align,
                        bytes + extra, mmap_align == HUGE_PAGE_SZ);
    }
    flags = MAP_SHARED;
  }
  else {
    /* Allocate enough to ensure we can get the required alignment.  We'll
     * unmap any excess afterwards.
     */
    if( req_huge_pages ) {
      mmap_align = HUGE_PAGE_SZ;
      flags = MAP_ANONYMOUS | MAP_PRIVATE | MAP_HUGETLB;
    }
    else {
      mmap_align = SYS_PAGE_SZ;
      flags = MAP_ANONYMOUS | MAP_PRIVATE;
    }
    extra = mmap_extra(bytes, align, mmap_align);
  }

  sc_trace(pp_scs(pp), "%s: p%d huge=%d,%d,%d len=%zu align=0x%zx\n", __func__,
           pp->pp_id, req_huge_pages, require_huge_pages,
           mmap_align == HUGE_PAGE_SZ, bytes, align);

  void* base_rq = NULL;
 try_again:;
  void* base = mmap(base_rq, bytes + extra, PROT_READ | PROT_WRITE,
                    flags, mmap_fd, 0);
  sc_trace(pp_scs(pp), "%s: p%d mmap(%p, 0x%zx, "MMAP_FLAGS_FMT", fd=%d)"
           " => %p\n", __func__, pp->pp_id, base_rq, bytes + extra,
           MMAP_FLAGS_ARG(flags), mmap_fd, base);
  if( base == MAP_FAILED ) {
    if( flags & MAP_HUGETLB ) {
      if( require_huge_pages )
        return sc_set_err(pp_scs(pp), errno, "%s: ERROR: Huge page alloc "
                          "failed for p%d (len=0x%zx+0x%zx n_hpages=%u)\n",
                          __func__, pp->pp_id, bytes, extra,
                          n_hpages(bytes + extra));
      flags &= ~MAP_HUGETLB;
      mmap_align = SYS_PAGE_SZ;
      extra = mmap_extra(bytes, align, mmap_align);
      goto try_again;
    }
    return sc_set_err(pp_scs(pp), errno, "%s: ERROR: Memory alloc failed for "
                      "p%d (bytes=0x%zx+0x%zx)\n", __func__, pp->pp_id,
                      bytes, extra);
  }

  if( mmap_align == HUGE_PAGE_SZ )
    pp->pp_stats->huge_pages += n_hpages(bytes + extra);

  uintptr_t aligned_ptr = ALIGN_FWD((uintptr_t) base, align);
  uintptr_t unmap_len = aligned_ptr - (uintptr_t) base;
  SC_TEST( ((uintptr_t) base & (mmap_align - 1)) == 0 );
  SC_TEST( unmap_len <= extra );

  /* Try to free any excess memory allocated. */
  if( unmap_len ) {
    sc_trace(pp_scs(pp), "%s: p%d munmap(len=0x%zx) at start (extra=0x%zx)\n",
             __func__, pp->pp_id, unmap_len, extra - unmap_len);
    SC_TRY( munmap(base, unmap_len) );
    extra -= unmap_len;
    base = (char*) base + unmap_len;
    if( mmap_fd >= 0 ) {
      /* Need to redo our mapping as we're no longer mapping the start of
       * the file!
       */
      base_rq = base;
      flags |= MAP_FIXED;
      goto try_again;
    }
  }
  uintptr_t mmap_end = (uintptr_t) ((char*) base + bytes + extra);
  uintptr_t aligned_end = ALIGN_FWD(aligned_ptr + bytes, mmap_align);
  unmap_len = mmap_end - aligned_end;
  if( unmap_len ) {
    sc_trace(pp_scs(pp), "%s: p%d munmap(len=0x%zx) at end (extra=0x%zx)\n",
             __func__, pp->pp_id, unmap_len, extra - unmap_len);
    if( munmap((void*) aligned_end, unmap_len) == 0 )
      extra -= unmap_len;
  }

  bb->bb_base = (void*) aligned_ptr;
  bb->bb_len = bytes;
  bb->bb_mmap_base = base;
  bb->bb_mmap_len = bytes + extra;
  bb->bb_huge = (flags & MAP_HUGETLB) != 0;
  if( require_huge_pages )
    bb->bb_huge = true;
  if( try_map_file )
    pp->pp_mmap_base = base;
  /* Touch each page now to ensure they are faulted in.  We don't want to
   * incur this cost later when we may be on a critical path.
   */
  sc_pkt_pool_blob_buf_touch(bb, mmap_align);
  return 0;
}


static void sc_pkt_pool_blob_buf_free(struct sc_pkt_pool* pp,
                                      struct sc_pkt_pool_blob_buf* bb)
{
  if( bb->bb_mmap_base ) {
    SC_TRY( munmap(bb->bb_mmap_base, bb->bb_mmap_len) );
    bb->bb_mmap_base = NULL;
  }
}


static void sc_pkt_pool_blob_free(struct sc_pkt_pool* pp,
                                  struct sc_pkt_pool_blob* blob)
{
  while( blob->ppb_memregs ) {
    struct sc_memreg* mr = blob->ppb_memregs;
    blob->ppb_memregs = mr->next;
    SC_TRY( ef_memreg_free(&(mr->mr), mr->dh) );
    free(mr);
  }
  int i, rc;
  for( i = 0; i < SC_MAX_NETIFS; ++i )
    if( blob->ppb_dh[i] >= 0 && (rc = ef_driver_close(blob->ppb_dh[i])) < 0 )
      sc_warn(pp_scs(pp), "%s: WARNING: ef_driver_close failed (netif=%d "
              "rc=%d errno=%d)\n", __func__, i, rc, errno);
  sc_pkt_pool_blob_buf_free(pp, &(blob->ppb_sc_pkt));
  sc_pkt_pool_blob_buf_free(pp, &(blob->ppb_pl));
  free(blob);
}


static int sc_pkt_pool_blob_alloc(struct sc_pkt_pool* pp,
                                  struct sc_pkt_pool_blob** blob_out,
                                  unsigned n_bufs)
{
  sc_trace(pp_scs(pp), "%s: p%d buf_size=%zd n=%d inline=%d bin_size=%zu "
           "sc_pkt_buf_len=%zu buf_per_bin=%u n_bins=%u file=%s\n", __func__,
           pp->pp_id, pp->pp_buf_size, n_bufs, pp->pp_is_inline,
           pp_bin_size(pp), pp->pp_sc_pkt_buf_len, pp_bufs_per_bin(pp),
           pp_num_bins(pp, n_bufs), pp->pp_mmap_fname ? pp->pp_mmap_fname : "");

  struct sc_pkt_pool_blob* blob;
  SC_TEST( blob = calloc(1, sizeof(*blob)) );
  /* blob->ppb_sc_pkt.bb_mmap_base = NULL; */
  /* blob->ppb_pl.bb_mmap_base = NULL; */
  /* blob->ppb_memregs = NULL; */
  blob->ppb_n_bufs = n_bufs;
  int i;
  for( i = 0; i < SC_MAX_NETIFS; ++i )
    blob->ppb_dh[i] = -1;

  /* sc_pkt buffers.  (Includes payload buffer when inline). */
  blob->ppb_sc_pkt.bb_len = pp_sc_pkt_mem_size(pp, n_bufs);
  if( sc_pkt_pool_blob_buf_alloc(pp, &(blob->ppb_sc_pkt),
                                 blob->ppb_sc_pkt.bb_len, pp_bin_size(pp),
                                 pp->pp_request_hpages,
                                 pp->pp_require_hpages,
                                 pp->pp_is_inline) < 0 )
    return -1;

  if( ! pp->pp_is_inline ) {
    /* Payload buffers. */
    blob->ppb_pl.bb_len = pp->pp_buf_size * n_bufs;
    if( sc_pkt_pool_blob_buf_alloc(pp, &(blob->ppb_pl),
                                   blob->ppb_pl.bb_len, 1,
                                   pp->pp_request_hpages,
                                   pp->pp_require_hpages,
                                   true) < 0 ) {
      sc_pkt_pool_blob_free(pp, blob);
      return -1;
    }
  }

  *blob_out = blob;
  return 0;
}


static int sc_pkt_pool_blob_dma_map(struct sc_pkt_pool* pp,
                                    struct sc_pkt_pool_blob* blob,
                                    struct sc_netif* netif)
{
  const struct sc_pkt_pool_blob_buf* bb;
  struct sc_pkt* pkt;
  size_t dma_buf_len;
  uint8_t* dma_buf;
  if( pp->pp_is_inline )
    bb = &(blob->ppb_sc_pkt);
  else
    bb = &(blob->ppb_pl);
  dma_buf = bb->bb_base;
  dma_buf_len = bb->bb_len;
  SC_TEST( dma_buf != NULL );
  SC_TEST( dma_buf_len );

  if( blob->ppb_memregs == NULL ) {
    /* First DMA mapping: Ensure that our DMA-mapped memory is not replaced
     * with new zero-pages after a fork() due to copy-on-write.
     */
    int rc = madvise(bb->bb_mmap_base, bb->bb_mmap_len, MADV_DONTFORK);
    if( rc < 0 )
      sc_warn(pp_scs(pp), "%s: WARNING: p%d madvise(len=0x%zx) failed (%d)\n",
              __func__, pp->pp_id, dma_buf_len, errno);
  }

  SC_TEST( blob->ppb_dh[netif->netif_id] == -1 );
  SC_TRY( ef_driver_open(&(blob->ppb_dh[netif->netif_id])) );
  ef_driver_handle dh = blob->ppb_dh[netif->netif_id];

  size_t map_len, min_map_len;
  struct sc_memreg* mrs;
  struct sc_memreg** mrs_tail = &mrs;
  unsigned pkt_i = 0;

  if( bb->bb_huge ) {
    /* Map at least a huge page or 4MiB at a time.  4MiB is significant
     * because it is the largest page size supported by our adapters.
     *
     * It is also important to ensure that we map whole multiples of at
     * least 1MiB when mapping into a PD with packed-stream enabled.
     */
    assert( HUGE_PAGE_SZ >= 1024 * 1024 );
    min_map_len = SC_MIN(HUGE_PAGE_SZ, 4 * 1024 * 1024);
    dma_buf_len = ALIGN_FWD(dma_buf_len, min_map_len);
    SC_TEST( (char*) dma_buf + dma_buf_len <=
             (char*) bb->bb_mmap_base + bb->bb_mmap_len );
    map_len = dma_buf_len;
  }
  else {
    /* Try to map chunks of at least 64KiB so that we get the benefit of
     * the larger NIC page sizes (if we're lucky!).
     */
    map_len = 4 * 1024 * 1024;
    min_map_len = SC_MAX(SYS_PAGE_SZ, 64 * 1024);
  }

  do {
    while( map_len > dma_buf_len && map_len > min_map_len )
      map_len /= 2;
    if( map_len > dma_buf_len )
      map_len = dma_buf_len;
    struct sc_memreg* mr;
    SC_TEST( mr = malloc(sizeof(*mr)) );
    mr->dh = dh;
    int rc = ef_memreg_alloc(&(mr->mr), mr->dh, &(netif->pd),
                             netif->dh, dma_buf, map_len);
    sc_trace(pp_scs(pp), "%s: p%d ef_memreg_alloc(%p, 0x%zx) => %d\n",
             __func__, pp->pp_id, dma_buf, map_len, rc < 0 ? -errno : 0);
    if( rc < 0 ) {
      if( map_len != dma_buf_len && map_len > min_map_len ) {
        map_len /= 2;
        continue;
      }
      sc_warn(pp_scs(pp), "%s: WARN: ef_memreg_alloc failed (rc=%d errno=%d "
              "intf=%s/%s len=0x%zx map_len=0x%zx\n", __func__, rc, errno,
              netif->name, netif->interface->if_name, dma_buf_len, map_len);
      goto fail;
    }
    do {
      SC_TEST( pkt_i < blob->ppb_n_bufs );
      pkt = pp_blob_get_pkt(pp, blob, pkt_i);
      if( (uint8_t*) pkt->sp_buf >= dma_buf + map_len )
        break;
      SC_TEST( (uint8_t*) pkt->sp_buf + pp->pp_buf_size <= dma_buf + map_len );
      pkt->sp_ef_addr[netif->netif_id] =
        ef_memreg_dma_addr(&(mr->mr), (uint8_t*) pkt->sp_buf - dma_buf);
    } while( ++pkt_i < blob->ppb_n_bufs );
    *mrs_tail = mr;
    mrs_tail = &(mr->next);
    dma_buf += map_len;
    dma_buf_len -= map_len;
  } while( dma_buf_len > 0 );

  *mrs_tail = NULL;
  *mrs_tail = blob->ppb_memregs;
  blob->ppb_memregs = mrs;
  return 0;


 fail:
  *mrs_tail = NULL;
  while( mrs != NULL ) {
    struct sc_memreg* mr = mrs;
    mrs = mr->next;
    SC_TRY( ef_memreg_free(&(mr->mr), mr->dh) );
    free(mr);
  }
  ef_driver_close(dh);
  blob->ppb_dh[netif->netif_id] = -1;
  return -1;
}


static void sc_pkt_pool_blob_init_pkts(struct sc_pkt_pool* pp,
                                       struct sc_pkt_pool_blob* blob)
{
  unsigned i, n_inited = 0, bufs_per_bin = pp_bufs_per_bin(pp);
  struct sc_pkt_bin* bin = blob->ppb_sc_pkt.bb_base;
  void* payload;

  do {
    SC_TEST( (uintptr_t) bin <
             (uintptr_t) blob->ppb_sc_pkt.bb_base + blob->ppb_sc_pkt.bb_len );
    sc_pkt_bin_init(bin, pp);
    for( i = 0; i < bufs_per_bin && n_inited < blob->ppb_n_bufs; ++i ) {
      struct sc_pkt* pkt = __sc_bin_to_pkt(bin, i);
      if( pp->pp_is_inline )
        payload = (uint8_t*) pkt + PKT_DMA_OFF;
      else
        payload = (uint8_t*) blob->ppb_pl.bb_base + n_inited * pp->pp_buf_size;
      sc_pkt_init(pkt, pp, payload);
      ++(bin->pb_total_bufs);
      ++n_inited;
    }
    bin = (void*) ((uint8_t*) bin + pp_bin_size(pp));
  } while( n_inited < blob->ppb_n_bufs );
}


static void sc_pkt_pool_blob_push_packets(struct sc_pkt_pool* pp,
                                          struct sc_pkt_pool_blob* blob)
{
  struct sc_pkt_bin* bin = blob->ppb_sc_pkt.bb_base;
  do {
    pp->pp_stats->allocated_bufs += bin->pb_total_bufs;
    sc_dlist_push_tail(&(pp->pp_used_bins), &(bin->link));
    int i;
    for( i = 0; i < bin->pb_total_bufs; ++i )
      sc_pkt_pool_put(pp, __sc_bin_to_pkt(bin, i));
    SC_TEST( sc_dlist_is_empty(&(pp->pp_used_bins)) );
    bin = (void*) ((uint8_t*) bin + pp_bin_size(pp));
  } while( (uint8_t*) bin <
           (uint8_t*) blob->ppb_sc_pkt.bb_base + blob->ppb_sc_pkt.bb_len );
}


static int sc_pkt_pool_blob_add(struct sc_pkt_pool* pp, unsigned n_bufs)
{
  struct sc_session* scs = pp->pp_thread->session;

  /* Allocate the memory. */
  struct sc_pkt_pool_blob* blob;
  int rc = sc_pkt_pool_blob_alloc(pp, &blob, n_bufs);
  if( rc < 0 )
    return sc_store_err(scs, errno, "%s: ERROR: p%d failed to allocate mem "
                        "(buf_size=%zd n=%d inline=%d huge=%d,%d)\n",
                        __func__, pp->pp_id, pp->pp_buf_size,
                        n_bufs,
                        pp->pp_is_inline, pp->pp_request_hpages,
                        pp->pp_require_hpages);

  sc_pkt_pool_blob_init_pkts(pp, blob);

  /* DMA map. */
  int netif_id;
  for( netif_id = 0; netif_id < scs->tg_netifs_n; ++netif_id )
    if( pp->pp_netifs & (1llu << netif_id) ) {
      rc = sc_pkt_pool_blob_dma_map(pp, blob, scs->tg_netifs[netif_id]);
      if( rc < 0 )
        break;
    }
  if( rc < 0 ) {
    sc_pkt_pool_blob_free(pp, blob);
    return sc_store_err(scs, errno, "%s: ERROR: p%d failed to DMA map "
                        "(buf_size=%zd n=%d inline=%d huge=%d,%d "
                        "netifs=%"PRIx64")\n", __func__, pp->pp_id,
                        pp->pp_buf_size, n_bufs,
                        pp->pp_is_inline,
                        pp->pp_request_hpages, pp->pp_require_hpages,
                        pp->pp_netifs);
  }

  /* Complete initialisation and add to pool. */
  sc_pkt_pool_blob_push_packets(pp, blob);
  blob->ppb_next = pp->pp_blobs;
  pp->pp_blobs = blob;
  return 0;
}


static size_t sc_pkt_pool_choose_bin_size(struct sc_pkt_pool* pp)
{
  /* pool_bin_size here comes from attribute of the same name.  The user
   * expects this to be approximately the total size of each bin.
   */
  ssize_t pool_bin_size = pp->pp_bin_size_rq;
  if( pool_bin_size < 0 )
    pool_bin_size = 256 * 1024;

  /* Compute our internal bin_size.  The internal bin size reflects only
   * the sc_pkt memory (including payload if inline).
   */
  size_t bin_size;
  size_t tot_buf_size;
  if( pp->pp_is_inline ) {
    tot_buf_size = pp->pp_sc_pkt_buf_len;
    bin_size = greatest_pow_2_le(pool_bin_size);
  }
  else {
    tot_buf_size = pp->pp_buf_size;
    if( pp->pp_buf_size <= 2048 )
      tot_buf_size += sizeof(struct sc_pkt);
    /* TODO: This may not give the user a bin size that is very close to
     * what they asked for.  We could do better by under-filling bins when
     * the buffer size is large relative to the meta-data.
     */
    unsigned bpb = pool_bin_size / tot_buf_size;
    bin_size = greatest_pow_2_le(pp->pp_sc_pkt_buf_len * bpb);
  }

  /* Each bin needs to be large enough for at least one packet! */
  if( bin_size < pp->pp_sc_pkt_buf_len * 2 )
    bin_size = pp->pp_sc_pkt_buf_len * 2;

  /* Reduce bin size if much bigger than needed.  NB. If this pool only
   * needs a few buffers, then it doesn't make sense to have lots of bins.
   * (If the pool only has a few buffers it is very unlikely that buffers
   * are going to be consumed at a high rate).
   */
  while( bufs_per_bin(pp, bin_size / 2) >= pp->pp_n_requested_bufs )
    bin_size /= 2;

  /* Having huge numbers of buffers per bin gives decreasing benefits, so
   * we're likely better off by making bins smaller so that the working set
   * size is smaller.  (TODO: Perhaps have a tunable for this).
   */
  while( bufs_per_bin(pp, bin_size) >= 256 )
    bin_size /= 2;

  sc_stats_add_info_int(pp_scs(pp), "p", pp->pp_id,
                        "pool_bin_size_rq", pp->pp_bin_size_rq);
  sc_stats_add_info_int(pp_scs(pp), "p", pp->pp_id,
                        "pool_bin_size",
                        bufs_per_bin(pp, bin_size) * tot_buf_size);

  return bin_size;
}


uint64_t sc_pool_get_buffer_size(struct sc_pool* pool)
{
  struct sc_pkt_pool* pp = SC_PKT_POOL_FROM_POOL(pool);
  return pp->pp_buf_size;
}


uint64_t sc_pkt_pool_calc_num_bufs(const struct sc_pkt_pool* pp,
                                   ssize_t pool_size, int64_t pool_n_bufs)
{
  /* Used by sc_ef_vi to determine how many buffers a pool will allocate
   * for the given parameters.
   */
  uint64_t buf_size;
  if( pp->pp_is_inline )
    buf_size = ALIGN_FWD(PKT_DMA_OFF + pp->pp_buf_size, SC_CACHE_LINE_SIZE);
  else
    buf_size = pp->pp_buf_size;

  uint64_t req_bytes = pp->pp_requested_bytes;
  req_bytes += pp->pp_n_requested_bufs * buf_size;
  return (req_bytes + buf_size - 1) / buf_size;
}


static void sc_pkt_pool_set_dimensions(struct sc_pkt_pool* pp)
{
  if( pp->pp_buf_size == 0 )
    pp->pp_is_inline = true;
  else if( pp->pp_is_inline < 0 )
    /* Pretty arbitrary! */
    pp->pp_is_inline = pp->pp_buf_size <= 2048;
  else
    pp->pp_is_inline = !! pp->pp_is_inline;

  if( pp->pp_is_inline ) {
    pp->pp_sc_pkt_buf_len =
      ALIGN_FWD(PKT_DMA_OFF + pp->pp_buf_size, SC_CACHE_LINE_SIZE);
    pp->pp_requested_bytes += pp->pp_n_requested_bufs * pp->pp_sc_pkt_buf_len;
    pp->pp_n_requested_bufs = (pp->pp_requested_bytes + pp->pp_sc_pkt_buf_len - 1) /
      pp->pp_sc_pkt_buf_len;
    if( pp->pp_netifs )
      /* Pool will be DMA mmapped: Ensure we get an integer number of
       * packet buffers per nic buffer so that they don't cross a boundary.
       *
       * TODO: Support large contiguous ef_memreg mappings so that it isn't
       * always necessary to round-up here.
       */
      pp->pp_sc_pkt_buf_len = least_pow_2_ge(pp->pp_sc_pkt_buf_len);
  }
  else {
    /* Zero length buffers are always treated as being inline. */
    SC_TEST(pp->pp_buf_size > 0);
    pp->pp_sc_pkt_buf_len =
      ALIGN_FWD(sizeof(struct sc_pkt), SC_CACHE_LINE_SIZE);
    pp->pp_requested_bytes += pp->pp_n_requested_bufs * pp->pp_buf_size;
    pp->pp_n_requested_bufs = (pp->pp_requested_bytes + pp->pp_buf_size - 1) /
      pp->pp_buf_size;
  }
  pp->pp_prefetch_stride = pp->pp_sc_pkt_buf_len * PREFETCH_STRIDE;

  size_t bin_size = sc_pkt_pool_choose_bin_size(pp);
  pp->pp_bin_mask = ~((uintptr_t) bin_size - 1);

  sc_stats_add_info_int(pp_scs(pp), "p", pp->pp_id,
                        "buf_size", pp->pp_buf_size);
  sc_stats_add_info_int(pp_scs(pp), "p", pp->pp_id,
                        "bufs_per_bin", pp_bufs_per_bin(pp));
  sc_stats_add_info_int(pp_scs(pp), "p", pp->pp_id,
                        "is_inline", pp->pp_is_inline);
  sc_stats_add_info_int(pp_scs(pp), "p", pp->pp_id,
                        "sc_pkt_len", pp->pp_sc_pkt_buf_len);
  sc_stats_add_info_int(pp_scs(pp), "p", pp->pp_id,
                        "refill_max_pkts", pp->pp_refill_batch);

  sc_trace(pp_scs(pp), "%s: p%d inline=%d buf_size=%zd "
           "sc_pkt_buf_len=%zu n_req=%d per_bin=%d\n",
           __func__, pp->pp_id, pp->pp_is_inline, pp->pp_buf_size,
           pp->pp_sc_pkt_buf_len, pp->pp_n_requested_bufs,
           pp_bufs_per_bin(pp));
}


int sc_pkt_pool_alloc_bufs(struct sc_pkt_pool* pp)
{
  SC_TEST( verify_pool(pp) );
  SC_TRY( sc_thread_affinity_save_and_set(pp->pp_thread) );
  sc_pkt_pool_set_dimensions(pp);
  int rc = sc_pkt_pool_blob_add(pp, pp->pp_n_requested_bufs);
  SC_TRY( sc_thread_affinity_restore(pp->pp_thread) );
  pp->pp_stats->min_full_bins = pp->pp_stats->n_full_bins;
  SC_TEST( verify_pool(pp) );
  if( rc < 0 ) {
    sc_commit_err(pp->pp_thread->session);
    return rc;
  }

#if 0  /* ?? fixme: new code doesn't yet support falling back to smaller allocation */
  if( n_alloc < pp->pp_n_bufs )
    sc_warn(tg, "%s: WARNING: Allocated %d buffers for pp %d, wanted %d\n",
            __func__, n_alloc, pp->pp_id, pp->pp_requested_bufs);
#endif

  return 0;
}


void sc_pkt_pool_request_bufs(struct sc_pkt_pool* pp,
                              const struct sc_attr* attr)
{
  if( attr->n_bufs_tx >= 0 )
    pp->pp_n_requested_bufs += attr->n_bufs_tx;
  else if( attr->pool_n_bufs >= 0 )
    pp->pp_n_requested_bufs += attr->pool_n_bufs;
  else if( attr->pool_size >= 0 )
    pp->pp_requested_bytes += attr->pool_size;
  else
    pp->pp_n_requested_bufs += 512;
}


int sc_pkt_pool_free(struct sc_session* tg, struct sc_pkt_pool* pp)
{
  while( pp->pp_blobs ) {
    struct sc_pkt_pool_blob* blob = pp->pp_blobs;
    pp->pp_blobs = blob->ppb_next;
    sc_pkt_pool_blob_free(pp, blob);
  }
  if( pp->pp_mmap_fd >= 0 )
    close(pp->pp_mmap_fd);
  sc_thread_mfree(pp->pp_thread, pp);
  return 0;
}


int sc_pkt_pool_bufs_per_bin(const struct sc_pkt_pool* pp)
{
  return pp_bufs_per_bin(pp);
}


struct sc_pkt* sc_pkt_pool_get_slow(struct sc_pkt_pool* pp)
{
  /* We come here because either there is no current bin, or the current
   * bin is about to go empty.
   */
  assert( ! sc_pkt_pool_is_empty(pp) );
  assert( pp->pp_current_bin == NULL || pp->pp_current_bin->pb_n_bufs < 2 );
  struct sc_pkt_bin* bin;
  struct sc_pkt* pkt;

  if( (bin = pp->pp_current_bin) == NULL ) {
    /* Attempt to use an available (full) bin. */
    if( sc_dlist_is_empty(&pp->pp_avail_bins) ) {
      /* No full bins available: obtain a packet from a partially filled
       * bin.  (For decent performance, this should happen only rarely for
       * performance-critical pools).
       */
      assert( ! pp->pp_use_full_bins );
      ++(pp->pp_stats->n_bufs_out_of_order);
      pkt = NULL;  /* compiler doesn't know we'll find a packet */
      SC_DLIST_FOR_EACH_OBJ(&pp->pp_used_bins, bin, link)
        if( bin->pb_returned_n ) {
          pkt = SC_PKT_FROM_PACKET(bin->pb_returned);
          bin->pb_returned = pkt->sp_usr.next;
          --(bin->pb_returned_n);
          assert( __sc_pkt_to_bin(pkt, pp) == bin );
          break;
        }
      assert( pkt != NULL );
      /* Push bin to head of list so we're faster next time. */
      sc_dlist_remove(&bin->link);
      sc_dlist_push_head(&pp->pp_used_bins, &bin->link);
      goto out;
    }
    else {
      bin = pp->pp_current_bin = (void*) sc_dlist_pop_head(&pp->pp_avail_bins);
      bin->pb_cur_buf = 0;
      --(pp->pp_stats->n_full_bins);
      if( pp->pp_stats->n_full_bins < pp->pp_stats->min_full_bins )
        pp->pp_stats->min_full_bins = pp->pp_stats->n_full_bins;
      assert( bin->pb_n_bufs == bin->pb_total_bufs );
    }
  }

  pkt = __sc_bin_to_pkt(bin, bin->pb_cur_buf);
  ++(bin->pb_cur_buf);
  --(bin->pb_n_bufs);
  if( bin->pb_n_bufs == 0 ) {
    assert( bin->pb_cur_buf == bin->pb_total_bufs );
    sc_dlist_push_tail(&pp->pp_used_bins, &(bin->link));
    if( ! sc_dlist_is_empty(&pp->pp_avail_bins) ) {
      bin = pp->pp_current_bin = (void*) sc_dlist_pop_head(&pp->pp_avail_bins);
      bin->pb_cur_buf = 0;
      --(pp->pp_stats->n_full_bins);
      if( pp->pp_stats->n_full_bins < pp->pp_stats->min_full_bins )
        pp->pp_stats->min_full_bins = pp->pp_stats->n_full_bins;
      assert( bin->pb_n_bufs == bin->pb_total_bufs );
    }
    else {
      pp->pp_current_bin = NULL;
    }
  }

 out:
  --(pp->pp_n_bufs);
  pp->pp_stats->n_bufs = pp->pp_n_bufs;
  return pkt;
}


int sc_pool_get_packets(struct sc_packet_list* list, struct sc_pool* pool,
                        int min_packets, int max_packets)
{
  struct sc_pkt_pool* pp = SC_PKT_POOL_FROM_POOL(pool);
  struct sc_pkt* pkt;
  int i;

  assert(max_packets >= min_packets);

  if( pp->pp_n_bufs >= min_packets ) {
    for( i = 0; i < max_packets && ! sc_pkt_pool_is_empty(pp); ++i ) {
      pkt = sc_pkt_pool_get(pp);
      pkt->sp_usr.iovlen = 1;
      pkt->sp_usr.iov[0].iov_base = sc_pkt_get_buf(pkt);
      pkt->sp_usr.iov[0].iov_len = pp->pp_buf_size;
      pkt->sp_usr.flags = 0;
      pkt->sp_usr.frame_len = 0;
      __sc_packet_list_append(list, &pkt->sp_usr);
    }
    sc_packet_list_finalise(list);
    return i;
  }
  else {
    return -1;
  }
}


void sc_pkt_pool_put_slow(struct sc_pkt_pool* pp, struct sc_pkt* pkt)
{
  struct sc_packet* next = pkt->sp_usr.frags;
  pkt->sp_usr.frags_n = 0;
  pkt->sp_usr.frags = NULL;
  pkt->sp_usr.frags_tail = &(pkt->sp_usr.frags);
  sc_pkt_bin_put(pp, pkt);
  do {
    pkt = SC_PKT_FROM_PACKET(next);
    next = next->next;
    SC_TEST( pkt->sp_usr.frags_n == 0 );
    sc_pkt_bin_put(pp, pkt);
  } while( next != NULL );
  pp->pp_stats->n_bufs = pp->pp_n_bufs;
}


void sc_pkt_bin_on_full(struct sc_pkt_pool* pp, struct sc_pkt_bin* bin)
{
  if( bin != pp->pp_current_bin )
    sc_pkt_pool_return_bin(pp, bin);
}


void sc_pkt_pool_post_refill(struct sc_pkt_pool* pp)
{
  struct sc_callback_impl* cbi;
  while( (cbi = sc_pkt_pool_non_empty_head(pp), 1) &&
         pp->pp_n_bufs >= cbi->cbi_pool_non_empty.threshold ) {
    assert( cbi != &(pp->pp_non_empty_events) );
    assert( cbi->cbi_type == evt_pool_threshold );
    assert( cbi->cbi_pool_non_empty.pool == pp );
    sc_callback_remove(&(cbi->cbi_public));
    sc_callback_call(&(cbi->cbi_public), cbi->cbi_thread, "pool_threshold");
  }
}


void sc_pool_return_packets(struct sc_pool* pool, struct sc_packet_list* pl)
{
  struct sc_pkt_pool* pp = SC_PKT_POOL_FROM_POOL(pool);
  sc_packet_list_append_list(&(pp->pp_put_backlog), pl);
  sc_callback_at_safe_time(pp->pp_cb_backlog);
}


void sc_pool_on_threshold(struct sc_pool* pool, struct sc_callback* cb,
                          int threshold)
{
  struct sc_callback_impl* cbi = SC_CALLBACK_IMPL_FROM_CALLBACK(cb);
  struct sc_pkt_pool* pp = SC_PKT_POOL_FROM_POOL(pool);

  assert(cb->cb_handler_fn != NULL);
  assert(threshold > 0);
  assert(cbi->cbi_thread == pp->pp_thread);

  cbi->cbi_type = evt_pool_threshold;
  cbi->cbi_pool_non_empty.pool = pp;
  cbi->cbi_pool_non_empty.threshold = threshold;

  if( pp->pp_n_bufs < threshold ||
      ! sc_dlist_is_empty(&(pp->pp_non_empty_events.cbi_public.cb_link)) ) {
    /* Push this event to tail of the list.  Idea is that we invoke the
     * handlers in the order that they were registered in order to give
     * fair service.  (NB. This can mean that someone wanting just 1 buffer
     * may have to wait if someone wanting more buffers is ahead in the
     * queue).
     */
    sc_dlist_remove(&cb->cb_link);
    sc_dlist_push_tail(&pp->pp_non_empty_events.cbi_public.cb_link,
                       &cb->cb_link);
  }
  else {
    /* We don't invoke the callback directly here because doing so would
     * require nodes to be robust to being re-entered.
     */
    __sc_callback_at_safe_time(cb);
  }
}


int sc_pkt_pool_callback_check(struct sc_callback_impl* cbi)
{
  /* Invoked by sc_thread_poll() timer handling code.  ie. We come here "at
   * a safe time".  Need to double check that the pool level still exceeds
   * the threshold before invoking the callback.
   */
  assert(cbi->cbi_type == evt_pool_threshold);
  assert(!sc_callback_is_active(&cbi->cbi_public));
  struct sc_pkt_pool* pp = cbi->cbi_pool_non_empty.pool;
  if( pp->pp_n_bufs >= cbi->cbi_pool_non_empty.threshold ) {
    sc_callback_call(&(cbi->cbi_public), cbi->cbi_thread, "pool_threshold");
    return 1;
  }
  else {
    sc_dlist_push_head(&pp->pp_non_empty_events.cbi_public.cb_link,
                       &cbi->cbi_public.cb_link);
    return 0;
  }
}


int sc_packet_append_iovec_ptr(struct sc_packet* head, struct sc_pool* pool,
                               struct sc_iovec_ptr* iovp, int max_bytes)
{
  struct sc_pkt* frag = SC_PKT_FROM_PACKET(head);
  struct sc_pkt_pool* pp = SC_PKT_POOL_FROM_POOL(pool);
  struct iovec* iov;
  int space, n;

  assert(pool == NULL || pp->pp_id == frag->sp_pkt_pool_id);

  if( iovp->iovlen == 0 )
    return 0;

  if( head->frags_n )
    frag = SC_PKT_FROM_PACKET(sc_packet_frags_tail(head));
  iov = head->iov + head->iovlen - 1;

  while( 1 ) {
    uint8_t* frag_ptr = ((uint8_t*) iov->iov_base + iov->iov_len);
    space = sc_pkt_get_buf_end(frag) - frag_ptr;
    n = (iovp->io.iov_len <= space) ? iovp->io.iov_len : space;
    n = (n <= max_bytes) ? n : max_bytes;
    memcpy(frag_ptr, iovp->io.iov_base, n);
    iov->iov_len += n;
    head->frame_len += n;
    if( n == iovp->io.iov_len ) {
      ++(iovp->iov);
      if( --(iovp->iovlen) == 0 )
        return 0;
      iovp->io = iovp->iov[0];
    }
    else {
      iovp->io.iov_base = (uint8_t*) iovp->io.iov_base + n;
      iovp->io.iov_len -= n;
    }
    if( n == max_bytes )
      return 0;
    max_bytes -= n;
    if( n == space ) {
      /* We've filled the current frag, but we should check whether there
       * is any more data to copy before allocating another.  (Zero-length
       * iovec entries are allowed).
       */
      while( iovp->io.iov_len == 0 ) {
        ++(iovp->iov);
        if( --(iovp->iovlen) == 0 )
          return 0;
        iovp->io = iovp->iov[0];
      }
      if( pool == NULL || sc_pkt_pool_is_empty(pp) )
        return -1;
      if( head->frags_n + 1 == SC_PKT_MAX_IOVS )
        return -2;
      frag = sc_pkt_pool_get(pp);
      *(head->frags_tail) = &(frag->sp_usr);
      head->frags_tail = &(frag->sp_usr.next);
      frag->sp_usr.next = NULL;
      ++(head->frags_n);
      iov = head->iov + (head->iovlen)++;
      iov->iov_base = sc_pkt_get_buf(frag);
      iov->iov_len = 0;
    }
  }

  return 0;
}


struct sc_packet* sc_pool_duplicate_packet(struct sc_pool* pool,
                                           struct sc_packet* orig_packet,
                                           int snap)
{
  struct sc_pkt_pool* pp = SC_PKT_POOL_FROM_POOL(pool);
  if( sc_pkt_pool_is_empty(pp) )
    return NULL;

  struct sc_pkt* copy;
  copy = sc_pkt_pool_get(pp);
  copy->sp_usr.iovlen = 1;
  copy->sp_usr.iov[0].iov_base = sc_pkt_get_buf(copy);
  copy->sp_usr.iov[0].iov_len = 0;
  copy->sp_usr.ts_sec = orig_packet->ts_sec;
  copy->sp_usr.ts_nsec = orig_packet->ts_nsec;

  struct sc_iovec_ptr iovp;
  sc_iovec_ptr_init_packet(&iovp, orig_packet);

  if( sc_packet_append_iovec_ptr(&(copy->sp_usr), pool, &iovp, snap) < 0 ) {
    sc_pkt_pool_put(pp, copy);
    return NULL;
  }

  copy->sp_usr.frame_len = orig_packet->frame_len;
  return &(copy->sp_usr);
}


struct sc_packet*
  sc_pool_duplicate_packed_packet(struct sc_pool* pool,
                                  const struct sc_packed_packet* psp, int snap)
{
  struct sc_pkt_pool* pp = SC_PKT_POOL_FROM_POOL(pool);

  int n_bufs = (psp->ps_cap_len + pp->pp_buf_size - 1) / pp->pp_buf_size;
  if( pp->pp_n_bufs < n_bufs )
    return NULL;

  struct sc_pkt* copy = sc_pkt_pool_get(pp);
  copy->sp_usr.iovlen = 1;
  copy->sp_usr.iov[0].iov_base = sc_pkt_get_buf(copy);
  copy->sp_usr.iov[0].iov_len = 0;
  copy->sp_usr.ts_sec = psp->ps_ts_sec;
  copy->sp_usr.ts_nsec = psp->ps_ts_nsec;

  struct sc_iovec_ptr iovp;
  struct iovec io;
  io.iov_base = sc_packed_packet_payload(psp);
  io.iov_len = psp->ps_cap_len;
  __sc_iovec_ptr_init(&iovp, &io, 1);

  if( sc_packet_append_iovec_ptr(&(copy->sp_usr), pool, &iovp, snap) < 0 ) {
    sc_pkt_pool_put(pp, copy);
    return NULL;
  }

  copy->sp_usr.frame_len = psp->ps_orig_len;
  return &(copy->sp_usr);
}


struct sc_node* sc_pool_set_refill_node(struct sc_pool* pool,
                                        struct sc_node* node)
{
  struct sc_pkt_pool* pp = SC_PKT_POOL_FROM_POOL(pool);
  struct sc_node_impl* ni = SC_NODE_IMPL_FROM_NODE(node);
  struct sc_session* scs = ni->ni_thread->session;
  sc_trace(scs, "%s: n%d/%s/%s refills p%d\n", __func__, ni->ni_id,
           ni->ni_node.nd_type->nt_name, ni->ni_node.nd_name, pp->pp_id);
  SC_TEST( pp->pp_thread == ni->ni_thread );
  struct sc_node_impl* prev_refill_node = pp->pp_refill_node;
  pp->pp_refill_node = ni;
  sc_stats_add_info_int(pp_scs(pp), "p", pp->pp_id,
                        "refill_node_id", ni->ni_id);
  ni->ni_stats->is_free_path = 1;
  return prev_refill_node ? &(prev_refill_node->ni_node) : NULL;
}


int sc_pool_wraps_node(struct sc_pool* pool, struct sc_node* node)
{
  struct sc_pkt_pool* pp = SC_PKT_POOL_FROM_POOL(pool);
  struct sc_node_impl* ni = SC_NODE_IMPL_FROM_NODE(node);
  struct sc_session* scs = ni->ni_thread->session;
  sc_trace(scs, "%s: p%d wraps n%d/%s/%s src_pools=%s\n", __func__,
           pp->pp_id, ni->ni_id, ni->ni_node.nd_type->nt_name,
           ni->ni_node.nd_name, sc_bitmask_fmt(&(ni->ni_src_pools)));
  int wrapee_pp_id = sc_bitmask_ffs(&(ni->ni_src_pools)) - 1;

  /* TODO: At the moment a pool can only wrap a single other pool.  We
   * should really allow it to wrap a number of other pools.
   */
  if( ! sc_bitmask_is_single_bit(&(ni->ni_src_pools), wrapee_pp_id) )
    return sc_set_err(scs, EINVAL, "%s: p%d cannot wrap n%d/%s/%s src_pools=%s"
                      " (only single pool supported)\n", __func__,
                      pp->pp_id, ni->ni_id, ni->ni_node.nd_type->nt_name,
                      ni->ni_node.nd_name, sc_bitmask_fmt(&(ni->ni_src_pools)));
  if( pp->pp_linked_pool != NULL )
    return sc_set_err(scs, EINVAL, "%s: p%d cannot wrap n%d/%s/%s; already "
                      "wraps p%d\n", __func__, pp->pp_id, ni->ni_id,
                      ni->ni_node.nd_type->nt_name, ni->ni_node.nd_name,
                      pp->pp_linked_pool->pp_id);

  pp->pp_linked_pool = scs->tg_pkt_pools[wrapee_pp_id];
  return 0;
}


struct sc_object* sc_pool_to_object(struct sc_pool* pool)
{
  if( pool == NULL )
    return NULL;
  struct sc_pkt_pool* pp = SC_PKT_POOL_FROM_POOL(pool);
  return &(pp->pp_obj.obj_public);
}


struct sc_pool* sc_pool_from_object(struct sc_object* obj)
{
  if( obj == NULL || obj->obj_type != SC_OBJ_POOL )
    return NULL;
  struct sc_pkt_pool* pp =
    SC_CONTAINER(struct sc_pkt_pool, pp_obj.obj_public, obj);
  return &(pp->pp_public);
}


/**********************************************************************
 * sc_free_demux_node
 *
 * This node is used on the free path when it is reached by multiple pools.
 * It splits packets out by pool.
 */

static void sc_free_demux_node_pkts(struct sc_node* node,
                                    struct sc_packet_list* pl_in)
{
  struct sc_free_demux* fdm = node->nd_private;
  struct sc_packet_list pl_out;
  struct sc_packet* next;
  struct sc_packet* packet;
  struct sc_pkt* pkt;
  int cur_pp_id = -1;

  /* Suppress compiler warning.  (Not technically needed, as we're
   * guaranteed to process at least one packet, and that'll cause
   * initialisation of pl_out in the loop).
   */
  pl_out.num_pkts = 0;

  for( next = pl_in->head; (packet = next) && ((next = next->next) || 1); ) {
    pkt = SC_PKT_FROM_PACKET(packet);
    __builtin_prefetch(pkt + 12*2048, 0, 2);
    if( pkt->sp_pkt_pool_id != cur_pp_id ) {
      if( cur_pp_id >= 0 ) {
        assert(! sc_packet_list_is_empty(&pl_out));
        __sc_forward_list(node, fdm->pp_id_to_link[cur_pp_id], &pl_out);
      }
      __sc_packet_list_init(&pl_out);
      cur_pp_id = pkt->sp_pkt_pool_id;
    }
    __sc_packet_list_append(&pl_out, packet);
  }

  if( ! sc_packet_list_is_empty(&pl_out) )
    __sc_forward_list(node, fdm->pp_id_to_link[cur_pp_id], &pl_out);
}


/* Since this is on the free path it is possible for prep to be called more than
 * once.
 */
static int sc_free_demux_node_prep(struct sc_node* node,
                                   const struct sc_node_link*const* links,
                                   int n_links)
{
  /* In sc_thread_setup_free_demux() we carefully set nl_pools to just the
   * pool that will be forwarded over that link.  sc_node_prep() will
   * overwrite that good work, so we reset here.
   *
   * NB. Both bits of code are needed because further links can be added to
   * this node by nodes that are preped after this one.
   */
  struct sc_free_demux* fdm = node->nd_private;
  int pp_id;
  for( pp_id = 0; pp_id < fdm->len; ++pp_id )
    if( fdm->pp_id_to_link[pp_id] != NULL ) {
      struct sc_node_link_impl* nl;
      nl = SC_NODE_LINK_IMPL_FROM_NODE_LINK(fdm->pp_id_to_link[pp_id]);
      sc_bitmask_clear_all(&nl->nl_pools);
      sc_bitmask_set(&nl->nl_pools, pp_id);
    }
  return 0;
}


const struct sc_node_type sc_free_demux_node_type = {
  .nt_name           = "sc_free_demux",
  .nt_pkts_fn        = sc_free_demux_node_pkts,
  .nt_prep_fn        = sc_free_demux_node_prep,
};


static int sc_free_demux_node_init(struct sc_node* node,
                                   const struct sc_attr* attr,
                                   const struct sc_node_factory* factory)
{
  struct sc_free_demux* fdm;
  fdm = sc_thread_calloc(sc_node_get_thread(node), sizeof(*fdm));
  TEST(fdm);
  node->nd_private = fdm;
  node->nd_type = &sc_free_demux_node_type;
  SC_NODE_IMPL_FROM_NODE(node)->ni_stats->is_free_path = 1;
  /* fdm->pp_id_to_link = NULL; */
  /* fdm->len = 0; */
  return 0;
}


const struct sc_node_factory sc_free_demux_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_free_demux",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_free_demux_node_init,
};


/**********************************************************************
 * sc_refill_node_type
 */

static void sc_refill_backlog_batch(struct sc_callback* cb, void* event_info)
{
  struct sc_node* node = cb->cb_private;
  struct sc_pkt_pool* pp = node->nd_private;
  struct sc_pkt* prefetch_pkt, *pkt, *next;

  /* n can be zero here, as this handler can be invoked from sc_ef_vi which
   * calls sc_pkt_pool_put() directly.  (And possibly from other places
   * too).
   */
  int n = SC_MIN(pp->pp_refill_batch, pp->pp_put_backlog.num_pkts);

  next = SC_PKT_FROM_PACKET(pp->pp_put_backlog.head);
  int n_left = n;
  while( n_left-- ) {
    pkt = next;
    next = SC_PKT_FROM_PACKET(next->sp_usr.next);
    prefetch_pkt = (void*) ((char*) pkt + pp->pp_prefetch_stride);
    sc_pkt_pool_put(pp, pkt);
    __builtin_prefetch(&(prefetch_pkt->sp_usr), 1, 2);
  }

  if( n == pp->pp_put_backlog.num_pkts ) {
    __sc_packet_list_init(&(pp->pp_put_backlog));
  }
  else {
    sc_timer_expire_after_ns(cb, 1);
    pp->pp_put_backlog.head = &(next->sp_usr);
    pp->pp_put_backlog.num_pkts -= n;
  }

  sc_pkt_pool_post_refill(pp);
}


static void sc_refill_node_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct sc_pkt_pool* pp = node->nd_private;
  sc_packet_list_append_list(&(pp->pp_put_backlog), pl);
  sc_callback_at_safe_time(pp->pp_cb_backlog);
}


static const struct sc_node_type sc_refill_node_type = {
  .nt_name           = "sc_refill_node",
  /* If nt_prep_fn is added it must be safe to call multiple times since this is
   * a free-path node.
   */
  .nt_prep_fn        = NULL,
  .nt_pkts_fn        = sc_refill_node_pkts,
};


static int sc_refill_node_init(struct sc_node* n, const struct sc_attr* attr,
                               const struct sc_node_factory* factory)
{
  n->nd_type = &sc_refill_node_type;

  struct sc_object* obj = NULL;
  SC_TEST( sc_node_init_get_arg_obj(&obj, n, "pool", SC_OBJ_OPAQUE) == 0 );
  struct sc_pkt_pool* pp = sc_opaque_get_ptr(obj);
  n->nd_private = pp;

  struct sc_callback* cb = pp->pp_cb_backlog;
  cb->cb_handler_fn = sc_refill_backlog_batch;
  cb->cb_private = n;

  sc_pool_set_refill_node(&(pp->pp_public), n);
  return 0;
}


const struct sc_node_factory sc_refill_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_refill_node",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_refill_node_init,
};
