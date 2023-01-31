/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \cond NODOC
 *
 * \node{sc_ps_to_ps_packer}
 *
 * \brief TBD Packs packets from a packed-stream buffer into output format
 *
 * \nodedetails
 * TBD. Packs packets from a packed-stream buffer into output format.
 *
 * \nodeargs
 * Argument         | Optional? | Default | Type           | Description
 * ---------------- | --------- | ------- | -------------- | -------------------------------------------------------------------------------------------------------
 * flush_timeout_ns | Yes       |         | ::SC_PARAM_INT | TBD Idle time after which buffer is flushed
 * bytes_per_input  | Yes       | -1      | ::SC_PARAM_INT | TBD Unused
 * pkt_index        | Yes       | 0       | ::SC_PARAM_INT | TBD Initial value for count of packets 
 * stream_id        | Yes       | 0       | ::SC_PARAM_STR | TBD Stream id to use
 * non_temporal     | Yes       | 0       | ::SC_PARAM_INT | TBD Nonzero to use non-temporal copying
 *
 * \nodestatscopy{sc_ps_to_ps_packer}
 */
#include <sc_internal.h>
#include <sc_internal/appliance.h>
#include <errno.h>

#include "../core/internal.h"
#include <sc_internal/packed_stream.h>
#include <sc_internal/builtin_nodes.h>
#include <solar_capture/nodes/subnode_helper.h>


#define SC_TYPE_TEMPLATE  <sc_packer_types_tmpl.h>
#define SC_DECLARE_TYPES  sc_p2p_stats_declare
#include <solar_capture/declare_types.h>

#define SCRATCH_SIZE 4096
#define DEFAULT_BUF_SIZE (1024*1024)


static inline void
ps_nt_memcpy(char* dst, char* src, size_t n_bytes);

static inline void
ps_nt_commit(void);


struct sc_p2p_input_data;

struct sc_p2p {
  struct sc_node*                   node;
  const struct sc_node_link*        next_hop;
  struct sc_packer_stats*           stats;

  struct sc_appliance_buffer_header buf_hdr;

  struct sc_attr*                   pool_attr;
  struct sc_callback*               pool_cb;
  struct sc_pool*                   pool;

  struct sc_packet*                 buffer;
  struct sc_packed_packet*          last_pkt;
  int                               buffer_fill;
  int                               buffer_size;

  struct sc_callback*               flush_cb;
  uint64_t                          flush_timeout_ns;
  bool                              nt_copy;
  void
  (*pack_buffer_fn)                 (struct sc_subnode_helper* sh);

  int                               bytes_per_input;

  struct sc_subnode_helper**        inputs;
  int                               inputs_n;
  int                               eos_waiting;
  void*                             scratch;
  int                               scratch_left;
};


struct sc_p2p_input_data {
  struct sc_p2p* packer;
  int            offset;
  int            max_bytes;
};


#define PACK_UNLIMITED -1


#define PTR_SUB(ptr2, ptr1) ((uint8_t*) ptr2 - (uint8_t*) ptr1)
#define FREE_BYTES(pkt, ptr) PTR_SUB(sc_packet_packed_end(pkt), ptr)
#define USED_BYTES(pkt, ptr) PTR_SUB(ptr, sc_packet_packed_first(pkt))

#define SC_PACKET_OFFSET_PTR(pkt, offset)                       \
  ((void*) ((uint8_t*) (pkt)->iov[0].iov_base + offset))


static bool get_next_pack_buffer(struct sc_p2p* pn)
{
  struct sc_packet_list pl;
  __sc_packet_list_init(&pl);
  if( sc_pool_get_packets(&pl, pn->pool, 1, 1) != 1 ) {
    sc_pool_on_threshold(pn->pool, pn->pool_cb, 1);
    pn->buffer = NULL;
    ++pn->stats->buffer_low;
    return false;
  }
  else {
    pn->buffer = pl.head;
    return true;
  }
}


static struct sc_subnode_helper* sc_p2p_oldest_input(struct sc_p2p* pn)
{
  int i;
  struct sc_subnode_helper* pi_out = NULL;
  uint32_t ts_sec = 0, ts_nsec = 0;
  struct sc_packed_packet* hdr;
  for( i = 0; i < pn->inputs_n; ++i ) {
    struct sc_subnode_helper* pi = pn->inputs[i];
    struct sc_packet* pkt = pi->sh_backlog.head;
    struct sc_p2p_input_data* pid = pi->sh_private;
    if( sc_packet_list_is_empty(&pi->sh_backlog) )
      continue;
    hdr = SC_PACKET_OFFSET_PTR(pkt, pid->offset);
    if( pi_out == NULL || hdr->ps_ts_sec < ts_sec ||
        (hdr->ps_ts_sec == ts_sec && hdr->ps_ts_nsec < ts_nsec) ) {
      pi_out = pi;
      ts_sec = hdr->ps_ts_sec;
      ts_nsec = hdr->ps_ts_nsec;
    }
  }
  return pi_out;
}


static void sc_p2p_pool_cb(struct sc_callback* cb, void* event_info)
{
  struct sc_p2p* pn = cb->cb_private;
  while( true ) {
    struct sc_subnode_helper* sh = sc_p2p_oldest_input(pn);
    if( sh == NULL )
      break;
    int prev_length;
    do {
      prev_length = sh->sh_backlog.num_pkts;
      pn->pack_buffer_fn(sh);
    } while( ! sc_packet_list_is_empty(&sh->sh_backlog) &&
             prev_length != sh->sh_backlog.num_pkts );
    if( pn->buffer == NULL )
      break;
  }
}


/* Emits the current packed buffer and attempts to get a new one from the
 * pool; returns true on acquiring a new buffer or false otherwise */
static bool sc_p2p_emit_buffer(struct sc_p2p* pn)
{
  assert(pn->last_pkt != NULL);
  /* Set the final packet's next_header filed to zero to indicate that any
   * remaining space is unused.
   *
   * Under high load the unused region will be small as we only emit a buffer
   * when it is too full to hold another complete packet. When idle we will
   * emit the current buffer after flush_timeout_ns nanoseconds regardless of
   * fill level (as long as it contains at least one packet).
   */

  if( pn->nt_copy ) {
    /* If scratch buffer is not empty, copy that out first.
     */
    if( pn->scratch_left != SCRATCH_SIZE )
      ps_nt_memcpy((char*)pn->buffer->iov[0].iov_base + pn->buffer_fill -
                   (pn->buffer_fill % SCRATCH_SIZE),
                   pn->scratch, SCRATCH_SIZE);
    pn->scratch_left = SCRATCH_SIZE;
    ps_nt_commit();
  }
  pn->last_pkt->ps_next_offset = 0;
  int hdr_len = sizeof(struct sc_packed_packet);
  struct sc_appliance_buffer_header* buf_hdr =
    SC_PACKET_OFFSET_PTR(pn->buffer, hdr_len);
  buf_hdr->data.pkt_count = pn->buf_hdr.data.pkt_count;
  buf_hdr->data.pkts_len = pn->buf_hdr.data.pkts_len;
  pn->buffer->flags = SC_PACKED_STREAM;
  sc_forward(pn->node, pn->next_hop, pn->buffer);
  pn->last_pkt = NULL;
  pn->buf_hdr.data.pkt_index += pn->buf_hdr.data.pkt_count;
  pn->buf_hdr.data.pkt_count = 0;
  pn->buf_hdr.data.pkts_len = 0;
  pn->buffer_fill = 0;
  sc_timer_expire_after_ns(pn->flush_cb, pn->flush_timeout_ns);
  return get_next_pack_buffer(pn);
}

typedef long long int v16b __attribute__ ((vector_size (16)));


/* We'll have just touched the source, but don't want the desination to pollute
 * the cache. So using movnt*.
 */
static void
ps_nt_memcpy(char* dst, char* src, size_t size)
{
#ifdef __PPC__
  memcpy(dst, src, size);
#else
  assert(size % 128 == 0);
  v16b chunk0, chunk1, chunk2, chunk3, chunk4, chunk5, chunk6, chunk7;
  char* end = dst + size;
  while (end > dst) {
    chunk0 = *((v16b*)src);
    chunk1 = *((v16b*)(src + 16));
    chunk2 = *((v16b*)(src + 32));
    chunk3 = *((v16b*)(src + 48));
    chunk4 = *((v16b*)(src + 64));
    chunk5 = *((v16b*)(src + 80));
    chunk6 = *((v16b*)(src + 96));
    chunk7 = *((v16b*)(src + 112));
    __builtin_ia32_movntdq((v16b*)dst, chunk0);
    __builtin_ia32_movntdq((v16b*)(dst + 16), chunk1);
    __builtin_ia32_movntdq((v16b*)(dst + 32), chunk2);
    __builtin_ia32_movntdq((v16b*)(dst + 48), chunk3);
    __builtin_ia32_movntdq((v16b*)(dst + 64), chunk4);
    __builtin_ia32_movntdq((v16b*)(dst + 80), chunk5);
    __builtin_ia32_movntdq((v16b*)(dst + 96), chunk6);
    __builtin_ia32_movntdq((v16b*)(dst + 112), chunk7);
    src += 128;
    dst += 128;
  }
#endif
}


static inline void
ps_nt_commit(void)
{
#ifndef __PPC__
  __builtin_ia32_sfence();
#endif
}


/* Copy to a write combining scratchpad first, and then stream out to the packed
 * buffer when the scratchpad is full. The intermediate buffer could be avoided,
 * but makes the implementation a lot simpler.
 */
static inline void
copy_to_buffer_nt(struct sc_p2p* pn, void* data, size_t n_bytes) {
  assert(pn->buffer_size - pn->buffer_fill >= n_bytes);
  char* src = (char*) data;
  while( n_bytes > 0 ) {
    size_t copy_size = (n_bytes < pn->scratch_left)? n_bytes : pn->scratch_left;
    n_bytes -= copy_size;
    memcpy((char*)pn->scratch + (SCRATCH_SIZE - pn->scratch_left),
           src, copy_size);
    pn->buffer_fill += copy_size;
    pn->scratch_left -= copy_size;
    src += copy_size;
    if( pn->scratch_left == 0 ) {
      assert(pn->buffer_fill % SCRATCH_SIZE == 0);
      assert(pn->buffer_fill > 0);
      char* dest = (char*)pn->buffer->iov[0].iov_base + pn->buffer_fill -
        SCRATCH_SIZE;
      ps_nt_memcpy(dest, pn->scratch, SCRATCH_SIZE);
      pn->scratch_left = SCRATCH_SIZE;
    }
  }
}


static inline void
copy_to_buffer(struct sc_p2p* pn, void* data, size_t n_bytes) {
  assert(pn->buffer_size - pn->buffer_fill >= n_bytes);
  char* dest = (char*)pn->buffer->iov[0].iov_base + pn->buffer_fill;
  memcpy(dest, data, n_bytes);
  pn->buffer_fill += n_bytes;
}


/* Attempts to pack a single packet from a packed-stream buffer into output
 * format. Returns true on success, or false on failure due to the pack pool
 * running dry.
 * Any changes here must be reflected in put_packed_stream_packet_nt().
 */
static inline bool
put_packed_stream_packet(struct sc_p2p_input_data* pi,
                         struct sc_packed_packet* ps_pkt,
                         int* max_bytes)
{
  struct sc_p2p* pn = pi->packer;
  struct sc_packed_packet  out_hdr;
  int pkt_bytes = ps_pkt->ps_cap_len + sizeof(*ps_pkt);
  char* pkt_payload = sc_packed_packet_payload(ps_pkt);
  int orig_fill = pn->buffer_fill;
  out_hdr = *ps_pkt;
  out_hdr.ps_pkt_start_offset = sizeof(out_hdr);

  if( *max_bytes >= 0 && *max_bytes < pkt_bytes )
      return false;

  if( pkt_bytes > pn->buffer_size - pn->buffer_fill ) {
    if( ! sc_p2p_emit_buffer(pn) )
      return false;
  }

  *max_bytes -= pkt_bytes;

  if( pn->last_pkt == NULL ) {
    /* This is the first packet for this buffer. Insert buffer header. */
    assert(pn->scratch_left == SCRATCH_SIZE);
    pkt_bytes += sizeof(pn->buf_hdr);
    out_hdr.ps_pkt_start_offset += sizeof(pn->buf_hdr);
    out_hdr.ps_next_offset = pkt_bytes;
    copy_to_buffer(pn, &out_hdr, sizeof(out_hdr));
    copy_to_buffer(pn, &pn->buf_hdr, sizeof(pn->buf_hdr));
  }
  else {
    out_hdr.ps_next_offset = pkt_bytes;
    copy_to_buffer(pn, &out_hdr, sizeof(out_hdr));
  }
  copy_to_buffer(pn, pkt_payload, out_hdr.ps_cap_len);
  pn->last_pkt = SC_PACKET_OFFSET_PTR(pn->buffer, orig_fill);
  pn->buf_hdr.data.pkts_len += out_hdr.ps_cap_len;
  ++pn->buf_hdr.data.pkt_count;
  pn->stats->packed_bytes += pkt_bytes;
  pn->stats->cap_bytes += out_hdr.ps_cap_len;
  ++pn->stats->cap_pkts;
  return true;
}


/* Attempts to pack a single packet from a packed-stream buffer into output
 * format. Returns true on success, or false on failure due to the pack pool
 * running dry. Non-temporal version.
 * Any changes here must be reflected in put_packed_stream_packet().
 */
static inline bool
put_packed_stream_packet_nt(struct sc_p2p_input_data* pi,
                            struct sc_packed_packet* ps_pkt,
                            int* max_bytes)
{
  struct sc_p2p* pn = pi->packer;
  struct sc_packed_packet  out_hdr;
  int pkt_bytes = ps_pkt->ps_cap_len + sizeof(*ps_pkt);
  char* pkt_payload = sc_packed_packet_payload(ps_pkt);
  int orig_fill = pn->buffer_fill;
  out_hdr = *ps_pkt;
  out_hdr.ps_pkt_start_offset = sizeof(out_hdr);

  if( *max_bytes >= 0 && *max_bytes < pkt_bytes )
      return false;

  if( pkt_bytes > pn->buffer_size - pn->buffer_fill ) {
    if( ! sc_p2p_emit_buffer(pn) )
      return false;
  }

  *max_bytes -= pkt_bytes;

  if( pn->last_pkt == NULL ) {
    /* This is the first packet for this buffer. Insert buffer header. */
    assert(pn->scratch_left == SCRATCH_SIZE);
    pkt_bytes += sizeof(pn->buf_hdr);
    out_hdr.ps_pkt_start_offset += sizeof(pn->buf_hdr);
    out_hdr.ps_next_offset = pkt_bytes;
    copy_to_buffer_nt(pn, &out_hdr, sizeof(out_hdr));
    copy_to_buffer_nt(pn, &pn->buf_hdr, sizeof(pn->buf_hdr));
  }
  else {
    out_hdr.ps_next_offset = pkt_bytes;
    copy_to_buffer_nt(pn, &out_hdr, sizeof(out_hdr));
  }
  copy_to_buffer_nt(pn, pkt_payload, out_hdr.ps_cap_len);
  pn->last_pkt = SC_PACKET_OFFSET_PTR(pn->buffer, orig_fill);
  pn->buf_hdr.data.pkts_len += out_hdr.ps_cap_len;
  ++pn->buf_hdr.data.pkt_count;
  pn->stats->packed_bytes += pkt_bytes;
  pn->stats->cap_bytes += out_hdr.ps_cap_len;
  ++pn->stats->cap_pkts;
  return true;
}


/* Packs the packets in a large packed-stream buffer into output format;
 * returns true on success or false on failure due to the pack pool running
 * dry. In the failure case some packets may have been successfully packed;
 * calling this function again will resume where it left off.
 * Any changes here must be reflected in pack_packed_stream_buffer_nt()
 */
static void
pack_packed_stream_buffer(struct sc_subnode_helper* sh)
{
  struct sc_p2p_input_data* pi = sh->sh_private;
  struct sc_packet* pkt = sh->sh_backlog.head;
  if( pi->packer->buffer == NULL && ! get_next_pack_buffer(pi->packer) )
    return;
  pi->max_bytes = PACK_UNLIMITED;
  SC_TEST(pkt->flags & SC_PACKED_STREAM);
  SC_TEST(pkt->iovlen == 1);
  struct sc_packed_packet* ps_pkt = SC_PACKET_OFFSET_PTR(pkt, pi->offset);
  struct sc_packed_packet* ps_end = sc_packet_packed_end(pkt);

  while( ps_pkt < ps_end ) {
    if( ! put_packed_stream_packet(pi, ps_pkt, &pi->max_bytes) ) {
      pi->offset = USED_BYTES(pkt, ps_pkt);
      return;
    }
    ps_pkt = sc_packed_packet_next(ps_pkt);
  }
  pi->offset = 0;
  sc_packet_list_pop_head(&sh->sh_backlog);
  sc_forward(sh->sh_node, sh->sh_links[0], pkt);
}


/* Packs the packets in a large packed-stream buffer into output format;
 * returns true on success or false on failure due to the pack pool running
 * dry. In the failure case some packets may have been successfully packed;
 * calling this function again will resume where it left off.
 * Non-temporal version. Any changes here must be reflected in
 * pack_packed_stream_buffer()
 */
static void
pack_packed_stream_buffer_nt(struct sc_subnode_helper* sh)
{
  struct sc_p2p_input_data* pi = sh->sh_private;
  struct sc_packet* pkt = sh->sh_backlog.head;
  if( pi->packer->buffer == NULL && ! get_next_pack_buffer(pi->packer) )
    return;
  pi->max_bytes = PACK_UNLIMITED;
  SC_TEST(pkt->flags & SC_PACKED_STREAM);
  SC_TEST(pkt->iovlen == 1);
  struct sc_packed_packet* ps_pkt = SC_PACKET_OFFSET_PTR(pkt, pi->offset);
  struct sc_packed_packet* ps_end = sc_packet_packed_end(pkt);

  while( ps_pkt < ps_end ) {
    if( ! put_packed_stream_packet_nt(pi, ps_pkt, &pi->max_bytes) ) {
      pi->offset = USED_BYTES(pkt, ps_pkt);
      return;
    }
    ps_pkt = sc_packed_packet_next(ps_pkt);
  }
  pi->offset = 0;
  sc_packet_list_pop_head(&sh->sh_backlog);
  sc_forward(sh->sh_node, sh->sh_links[0], pkt);
  return;
}


/* Called if no buffer is emitted within the flush timeout; emits the
 * current partially-filled buffer */
static void sc_p2p_flush_cb(struct sc_callback* cb, void* event_info)
{
  struct sc_p2p* pn = cb->cb_private;
  if( pn->buffer_fill > 0 )
    sc_p2p_emit_buffer(pn);
  else
    sc_timer_expire_after_ns(pn->flush_cb, pn->flush_timeout_ns);
}


/* Called once all input subnodes have seen EOS and drained their backlog */
static void sc_p2p_propagate_end_of_stream(struct sc_p2p* pn)
{
  if( pn->buffer_fill > 0 )
    sc_p2p_emit_buffer(pn);
  sc_node_link_end_of_stream(pn->node, pn->next_hop);
}


static void
sc_p2p_handle_end_of_stream(struct sc_subnode_helper* sh)
{
  struct sc_p2p_input_data* pi = sh->sh_private;
  if( ! --pi->packer->eos_waiting )
    sc_p2p_propagate_end_of_stream(pi->packer);
  /* Not necessary to produce eos from sh since no links are added. */
}


/* Creates a new subnode for each incoming link. This makes it simple to
 * free input packets once they've been packed as we don't need to work out
 * which pool to free them to. */
static struct sc_node* sc_p2p_select_subnode(struct sc_node* node,
                                             const char* name,
                                             char** new_name_out)
{
  struct sc_p2p* pn = node->nd_private;

  struct sc_p2p_input_data* pi = malloc(sizeof(struct sc_p2p_input_data));
  pi->packer = pn;
  pi->offset = 0;
  struct sc_attr* attr;
  SC_TRY(sc_attr_alloc(&attr));

  struct sc_node* input_node;
  int rc = sc_node_alloc(&input_node, attr, sc_node_get_thread(node),
                         &sc_subnode_helper_sc_node_factory, NULL, 0);
  sc_attr_free(attr);
  if( rc < 0 ) {
    sc_node_fwd_error(node, rc);
    return NULL;
  }

  struct sc_subnode_helper* input = sc_subnode_helper_from_node(input_node);
  input->sh_private = pi;
  input->sh_handle_backlog_fn = pn->pack_buffer_fn;
  input->sh_handle_end_of_stream_fn = sc_p2p_handle_end_of_stream;

  pn->inputs = realloc(pn->inputs, sizeof(input) * (++pn->inputs_n));
  pn->inputs[pn->inputs_n - 1] = input;
  ++pn->eos_waiting;

  return input_node;
}


int sc_p2p_prep(struct sc_node* node, const struct sc_node_link*const* links,
                int n_links)
{
  struct sc_p2p* pn = node->nd_private;
  pn->next_hop = sc_node_prep_get_link_or_free(node, "");
  if( sc_node_prep_check_links(node) < 0 )
    return -1;

  if( sc_node_prep_get_pool(&pn->pool, pn->pool_attr, node, NULL, 0) < 0 )
    return -1;

  sc_timer_expire_after_ns(pn->flush_cb, pn->flush_timeout_ns);

  return 0;
}


int sc_p2p_init(struct sc_node* node, const struct sc_attr* attr,
                const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    SC_TRY(sc_node_type_alloc(&nt, NULL, factory));
    nt->nt_prep_fn = sc_p2p_prep;
    nt->nt_select_subnode_fn = sc_p2p_select_subnode;
  }
  node->nd_type = nt;
  struct sc_thread* thread = sc_node_get_thread(node);
  sc_p2p_stats_declare(sc_thread_get_session(sc_node_get_thread(node)));

  struct sc_p2p* pn = sc_thread_calloc(thread, sizeof(*pn));
  pn->node = node;
  node->nd_private = pn;
  pn->pool_attr = sc_attr_dup(attr);
  pn->pool_attr->private_pool = 1;
  if( pn->pool_attr->buf_size < 0 )
    pn->pool_attr->buf_size = DEFAULT_BUF_SIZE;
  pn->buffer_size = pn->pool_attr->buf_size;
  pn->buf_hdr.hdr.prh_type = SC_PACKED_RECORD_APPLIANCE_BLOCK_HEADER;
  pn->buf_hdr.hdr.prh_len = sizeof(pn->buf_hdr.data);
  pn->buf_hdr.data.endianness = PBH_LITTLE_ENDIAN;
  pn->buf_hdr.data.version = PBH_VERSION;
  pn->buf_hdr.data.buffer_len = pn->buffer_size;

  int64_t tmp64;
  if( sc_node_init_get_arg_int64(&tmp64, node, "flush_timeout_ns",
                                 attr->batch_timeout_nanos) < 0 )
    return -1;
  if( tmp64 < 0 )
    return sc_node_set_error(node, EINVAL, "%s: ERROR: flush_timeout_ns "
                             "must be >= 0\n", __func__);
  pn->flush_timeout_ns = tmp64;

  int tmp;
  if( sc_node_init_get_arg_int(&tmp, node, "bytes_per_input",
                               PACK_UNLIMITED) < 0 )
    return -1;
  pn->bytes_per_input = tmp;

  if( sc_node_init_get_arg_int64(&tmp64, node, "pkt_index", 0) < 0 )
    return -1;
  pn->buf_hdr.data.pkt_index = tmp64;

  const char* s;
  if( sc_node_init_get_arg_str(&s, node, "stream_id", 0) < 0 )
    return -1;
  if( s != NULL ) {
    SC_TEST(strlen(s) < STREAM_ID_STRLEN);
    strncpy(pn->buf_hdr.data.stream_id, s, STREAM_ID_STRLEN);
  }

  if( sc_node_init_get_arg_int(&tmp, node, "non_temporal",
                               0) < 0 )
    return -1;

  pn->nt_copy = tmp;
  if( pn->nt_copy )
    pn->pack_buffer_fn = pack_packed_stream_buffer_nt;
  else
    pn->pack_buffer_fn = pack_packed_stream_buffer;

  SC_TEST(sc_callback_alloc(&pn->pool_cb, NULL, thread) == 0);
  pn->pool_cb->cb_private = pn;
  pn->pool_cb->cb_handler_fn = sc_p2p_pool_cb;

  SC_TEST(sc_callback_alloc(&pn->flush_cb, NULL, thread) == 0);
  pn->flush_cb->cb_private = pn;
  pn->flush_cb->cb_handler_fn = sc_p2p_flush_cb;

  SC_TEST(posix_memalign(&pn->scratch, 4096, SCRATCH_SIZE) == 0);
  pn->scratch_left = SCRATCH_SIZE;
  sc_node_export_state(node, "sc_packer_stats",
                       sizeof(struct sc_packer_stats), &pn->stats);
  return 0;
}


const struct sc_node_factory sc_ps_to_ps_packer_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_ps_to_ps_packer",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_p2p_init,
};

/** \endcond NODOC */
