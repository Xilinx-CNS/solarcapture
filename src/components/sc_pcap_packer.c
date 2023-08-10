/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \node{sc_pcap_packer}
 *
 * \brief A node that packs incoming packets into buffers that are ready to be
 * written to a pcap file.
 *
 * \nodedetails
 * A node that packs incoming packets into buffers that are ready to be
 * written to a pcap file.
 *
 * \nodeargs
 * Argument         | Optional? | Default | Type           | Description
 * ---------------- | --------- | ------- | -------------- | --------------------------------------------------------------------------------------------------------------------------------
 * snap             | Yes       |         | ::SC_PARAM_INT | Bytes of frame data to store.  If unset or zero, use the "snap" attribute, else at least 16KiB if the attribute is not set.
 * rotate_seconds   | Yes       | 0       | ::SC_PARAM_INT | If nonzero, a new capture file is created after the given number of seconds.
 * rotate_file_size | Yes       | 0       | ::SC_PARAM_INT | If nonzero, a new capture file is created whenever the previous file exceeds the given size in bytes.
 * format           | Yes       | "pcap"  | ::SC_PARAM_STR | File format.  Set to "pcap-ns" for nano-second PCAP format or "pcap" for the default format that uses microseconds.
 * on_error         | Yes       | "exit"  | ::SC_PARAM_STR | Set behaviour for errors. Can be one of "exit", "abort", "message" and "silent".
 * discard_mask     | Yes       | 0       | ::SC_PARAM_INT | Mask with packed stream packets to discard. Bits in the mask that take effect are SC_CSUM_ERROR and SC_CRC_ERROR. Not that this argument will have no effect on packets not in packed stream format.
 * filename         | No        |         | ::SC_PARAM_STR | Template for filename. This is used to generate filenames for the initial and post-rotation files. The filename may include a time format defined by strftime(3). If the filename includes the string '$i' then it is replaced by an incrementing index.
 *
 *
 * \namedinputlinks
 * Input links may be named, in which case the packets are forwarded to a matching named output link.
 *
 * \outputlinks
 * Link           | Description
 * -------------- | -----------------------------------
 *  ""            | Packed buffers in pcap format are sent out on this link.
 *  "#input"      | Packets from all inputs are forwarded to this link.
 *  NAME          | If NAME matches the name of an input link, then input packets are forwarded to the corresponding output link.
 *
 * \nodestatscopy{sc_pcap_packer}
 *
 * \cond NODOC
 */

#include <sc_internal.h>
#include <sc_internal/builtin_nodes.h>
#include <sc_internal/ef_vi.h>
#include <inttypes.h>
#include "sc_pcap.h"
#include "sc_writer.h"
#include "../core/internal.h"

#include <sc_internal/packed_stream.h>
#include <solar_capture/nodes/subnode_helper.h>
#include <sc_internal/nodes/eos_fwd.h>

#define SC_TYPE_TEMPLATE  <sc_pcap_packer_types_tmpl.h>
#define SC_DECLARE_TYPES  sc_pcap_packer_stats_declare
#include <solar_capture/declare_types.h>

#include <errno.h>
#include <limits.h>

#define IDLE_CHECK_NS 1000000000ULL
#define EMPTY_ROTATE_MAX_SEC 3600

/* Space allowed for expanding strftime and index from template */
#define TEMPLATE_EXPANSION_SPACE 80

enum pcap_packer_idle_state {
  ST_BUSY,
  ST_IDLE
};


struct sc_pcap_packer_state {
  struct sc_node*              node;
  struct sc_pool*              pool;
  enum ts_type                 ts_type;
  struct sc_packet*            pkt;
  struct sc_packet_list        list_out;
  enum pcap_packer_idle_state  input_idle_state;
  enum pcap_packer_idle_state  output_idle_state;
  struct sc_attr*              pool_attr;
  int                          pkt_fill;
  int                          pkt_remaining;
  int                          prev_partial_fill;
  size_t                       buffer_size;
  int                          snap;
  int                          rotate_secs;
  int64_t                      rotate_file_size;
  uint                         file_index;
  uint64_t                     next_rotate_sec;
  int                          eos_waiting;
  uint64_t                     file_byte_count;
  bool                         first_time;
  bool                         ready;
  bool                         eos_redirected;
  int64_t                      packet_sys_time_diff;
  char*                        filename_template;
  char*                        filename_time_rotated;
  struct sc_subnode_helper**   inputs;
  char**                       input_names;
  int                          inputs_n;
  struct sc_callback*          pool_cb;
  struct sc_callback*          idle_cb;
  struct sc_callback*          rotate_timer_cb;
  struct sc_callback*          buffer_flush_cb;
  const struct sc_node_link*   next_hop;
  struct sc_pcap_packer_stats* stats;
  enum on_error                on_error;
  int                          ps_flags_mask;
  bool                         added_named_input_link;
  struct sc_node*              all_inputs_to_node;
  char*                        all_inputs_to_name_opt;
};


static inline bool pcap_put_file_header(struct sc_pcap_packer_state *st);


static void sc_pcap_packer_error(struct sc_pcap_packer_state* st, int err)
{
  switch( st->on_error ) {
  case ON_ERROR_EXIT:
    exit(1);
  case ON_ERROR_ABORT:
    abort();
  case ON_ERROR_MESSAGE:
  case ON_ERROR_SILENT:
    break;
  }
}


void sc_pcap_packer_set_file_byte_count(struct sc_node* node,
                                        uint64_t file_byte_count)
{
  struct sc_pcap_packer_state* st = node->nd_private;
  st->file_byte_count = file_byte_count;
  SC_TEST(st->pkt);
  SC_TEST(st->pkt_fill == 0);
  unsigned start_offset = file_byte_count % st->buffer_size;
  st->pkt->iov[0].iov_base = (char*)st->pkt->iov[0].iov_base + start_offset;
  st->pkt_remaining = st->buffer_size - start_offset;
  st->ready = true;
}


static inline struct sc_packet* get_buffer(struct sc_pcap_packer_state* st)
{
  struct sc_packet_list pl;
  __sc_packet_list_init(&pl);
  if( sc_pool_get_packets(&pl, st->pool, 1, 1) != 1 )
    return NULL;
  else
    return pl.head;
}


static inline bool get_next_pcap_buffer(struct sc_pcap_packer_state* st)
{
  struct sc_packet* pkt = get_buffer(st);
  if( pkt == NULL ) {
    st->stats->buffer_low++;
    sc_pool_on_threshold(st->pool, st->pool_cb, 1);
    return false;
  }
  else {
    st->pkt = pkt;
    st->pkt->frame_len = SC_FRAME_LEN_LARGE;
    st->pkt_fill = 0;
    st->pkt_remaining = st->buffer_size - st->prev_partial_fill;
    st->pkt->iov[0].iov_base = (char*)st->pkt->iov[0].iov_base + st->prev_partial_fill;
    return true;
  }
}


static inline bool put_data(struct sc_pcap_packer_state* st, const void* data,
                            unsigned len)
{
  SC_TEST(st->pkt != NULL);

  int to_write = len;
  char* w_data = (char *)data;
  char* dest = (char *)st->pkt->iov[0].iov_base + st->pkt_fill;

  if( st->pkt_remaining <= to_write ) {
    /* We insist that each packet (plus headers) can fit into a single
     * output buffer.  See sc_pcap_packer_prep() for the logic that ensures
     * this.
     */
    assert( to_write + sizeof(struct pcap_rec_hdr) +
            sizeof(struct pcap_file_hdr) <= st->buffer_size );
    int part_write = st->pkt_remaining;
    memcpy(dest, w_data, part_write);
    st->pkt_fill += part_write;

    to_write -= part_write;
    w_data += part_write;

    st->stats->pcap_bytes += st->pkt_fill;

    st->pkt->iov[0].iov_len = st->pkt_fill;
    sc_packet_list_append(&st->list_out, st->pkt);
    st->prev_partial_fill = 0;
    SC_TEST( get_next_pcap_buffer(st) );
    dest = (char *)st->pkt->iov[0].iov_base;
  }

  memcpy(dest, w_data, to_write);
  /* This works well if the stream has close to minimum sized packets.
   * It probably won't hurt in other cases either. Since minimum sized
   * packets are the most challenging case, we're probably fine to optimise
   * for them.
   */
  __builtin_prefetch(dest + 76 * 8 ,1, 2);

  st->pkt_fill += to_write;
  st->pkt_remaining -= to_write;
  st->file_byte_count += len;
  return true;
}


/* Adjust timestamp back to the nearest natural boundary. */
static uint64_t get_natural_time_boundary(uint64_t ts_sec,
                                          uint64_t rotate_sec)
{
  uint64_t factor_list[] = { 5,
                             10,
                             15,
                             20,
                             30,
                             60,
                             60*2,
                             60*5,
                             60*10,
                             60*15,
                             60*20,
                             60*30,
                             60*40,
                             60*45,
                             3600,
                             3600*2,
                             3600*4,
                             3600*6,
                             3600*8,
                             3600*12,
                             3600*24 };

  uint64_t max_factor = 1;
  int i;

  if( ! rotate_sec )
    return ts_sec;

  for( i = 0; i < sizeof(factor_list)/ sizeof(factor_list[0]); ++i )
    if( rotate_sec % factor_list[i] == 0 )
      max_factor = factor_list[i];

  return ts_sec - (ts_sec % max_factor);
}


static inline bool pcap_put_pkt_header(struct sc_pcap_packer_state *st,
                                       uint16_t incl_len,
                                       uint16_t orig_len,
                                       uint64_t ts_sec,
                                       uint32_t ts_nsec)
{
  if( st->file_byte_count == 0 )
    pcap_put_file_header(st);

  struct pcap_rec_hdr h;
  h.ts_sec = ts_sec;
  h.ts_subsec = (st->ts_type == ts_micro) ?
    ts_nsec / 1000 : ts_nsec;
  h.incl_len = incl_len;
  h.orig_len = orig_len;
  return put_data(st, &h, sizeof(h));
}


static inline bool pcap_put_file_header(struct sc_pcap_packer_state *st)
{
  struct pcap_file_hdr hdr = {
    .magic_number = st->ts_type == ts_micro? PCAP_MAGIC: PCAP_NSEC_MAGIC,
    /* As of 14-09-2012, according to libpcap-1.3.0 from www.tcpdump.org,
     * this is the current version of the pcap file format.  This is also
     * known to work with tcpdump on RHEL-6.2, tcpdump version
     * 4.1-PRE-CVS_2009_12_11, libpcap version 1.0.0.
     */
    .version_major = 2,
    .version_minor = 4,
    .thiszone = 0,
    .sigfigs = 0,
    .snap = st->snap,
    .network = 1,
  };
  return put_data(st, &hdr, sizeof(hdr));
}


static inline void
sc_pcap_put_packed_stream_packet(struct sc_pcap_packer_state* st,
                                 struct sc_packed_packet* ps_pkt)
{
  assert( SC_PKT_POOL_FROM_POOL(st->pool)->pp_n_bufs > 0 );
  int bytes_left =
    (ps_pkt->ps_cap_len <= st->snap) ? ps_pkt->ps_cap_len : st->snap;
  pcap_put_pkt_header(st, bytes_left, ps_pkt->ps_orig_len,
                      ps_pkt->ps_ts_sec, ps_pkt->ps_ts_nsec);
  put_data(st, sc_packed_packet_payload(ps_pkt), bytes_left);
}


static inline void sc_pcap_put_packet(struct sc_pcap_packer_state* st,
                                      struct sc_packet* pkt,
                                      int pkt_len)
{
  assert( SC_PKT_POOL_FROM_POOL(st->pool)->pp_n_bufs > 0 );
  int i, bytes_left = (pkt_len <= st->snap) ? pkt_len : st->snap;
  pcap_put_pkt_header(st, bytes_left, pkt->frame_len, pkt->ts_sec,
                      pkt->ts_nsec);
  for( i = 0; bytes_left && i < pkt->iovlen; ++i ) {
    int to_write = (bytes_left > pkt->iov[i].iov_len) ?
      pkt->iov[i].iov_len: bytes_left;
    put_data(st, pkt->iov[i].iov_base, to_write);
    bytes_left -= to_write;
  }
}


static void do_partial_flush(struct sc_node* node)
{
  struct sc_pcap_packer_state* st = node->nd_private;
  SC_TEST(st->eos_waiting > 0);
  if( st->pkt_fill > 0 ) {
    SC_TEST( st->pkt != NULL );
    if( st->file_byte_count == 0 )
      pcap_put_file_header(st);

    st->pkt->iov[0].iov_len = st->pkt_fill;
    st->stats->pcap_bytes += st->pkt_fill;
    st->prev_partial_fill += st->pkt_fill;
    st->prev_partial_fill %= st->buffer_size;
    SC_TEST(st->pkt->iov[0].iov_len > 0);
    sc_forward(node, st->next_hop, st->pkt);
    if( ! get_next_pcap_buffer(st) ) {
      st->pkt_fill = 0;
      st->pkt = NULL;
    }
  }
}


static inline void pcap_flush_buffer(struct sc_node* node)
{
  struct sc_pcap_packer_state* st = node->nd_private;
  SC_TEST(st->pkt != NULL);
  /* Handling for the case where we haven't received any packets for the current
   * file, and hence do not have a file header.
   */
  if( st->file_byte_count == 0 && ! st->first_time )
    pcap_put_file_header(st);

  st->file_byte_count = 0;
  st->pkt->iov[0].iov_len = st->pkt_fill;
  /* When the node gets its first packet, a dummy buffer is emitted to
   * communicate the filename.
   */
  st->stats->pcap_bytes += st->pkt_fill;

  sc_packet_list_append(&st->list_out, st->pkt);

  st->pkt_fill = 0;
  st->prev_partial_fill = 0;

  if( ! get_next_pcap_buffer(st) )
    st->pkt = NULL;

  __sc_forward_list(node, st->next_hop, &st->list_out);
  /* Since we've emitted a buffer, push back the flush callback.
   */
  sc_timer_expire_after_ns(st->buffer_flush_cb, IDLE_CHECK_NS);
  sc_packet_list_init(&st->list_out);
  st->output_idle_state = ST_BUSY;
}


static inline void pcap_rotate(struct sc_node* node, uint64_t rotate_sec,
                               bool is_time_rotate)
{
  struct sc_pcap_packer_state* st = node->nd_private;
  if( st->first_time ) {
    SC_TEST( get_next_pcap_buffer(st) );
    st->pkt->iovlen = 0;
  }
  if( st->pkt ) {
    st->pkt->ts_sec = rotate_sec;
    st->pkt->ts_nsec = 0;
    st->pkt->flags |= SC_FILE_ROTATE;
    if( st->filename_template != NULL ) {
      int name_len = strlen(st->filename_template) + TEMPLATE_EXPANSION_SPACE;
      /* Evil hack: This is freed downstream in the disk writer.
       * TODO: Do this properly with wrapping/managed metadata.
       */
      st->pkt->metadata = malloc(name_len);
      struct timespec ts;
      ts.tv_sec = rotate_sec;
      if( is_time_rotate ) {
        st->file_index = 0;
        if( sc_pcap_filename(st->filename_time_rotated, name_len,
                             st->filename_template, true, false, ts, 0) != 0 ) {
          if( st->on_error != ON_ERROR_SILENT )
            sc_node_set_error(node, ENOMEM, "%s: ERROR: filename too long "
                              "after template expansion (max %d chars).\n",
                              __func__, name_len);
          sc_pcap_packer_error(st, ENOMEM);
        }
      }
      char* template = ( st->rotate_secs > 0 ) ? st->filename_time_rotated :
        st->filename_template;
      if( sc_pcap_filename((char*)st->pkt->metadata, name_len,
                           template, st->rotate_secs, st->rotate_file_size,
                           ts, st->file_index) != 0 ) {
        if( st->on_error != ON_ERROR_SILENT )
          sc_node_set_error(node, ENOMEM, "%s: ERROR: filename too long after "
                            "template expansion (max %d chars).\n",
                            __func__, name_len);
        sc_pcap_packer_error(st, ENOMEM);
      }
    }
    ++st->file_index;
    pcap_flush_buffer(node);
  }
}


void sc_pcap_packer_handle_end_of_stream(struct sc_subnode_helper* sh)
{
  struct sc_pcap_packer_state* st = sh->sh_private;
  assert( sc_packet_list_is_empty(&(sh->sh_backlog)) );
  if( ! st->eos_redirected )
    sc_node_link_end_of_stream2(sh->sh_links[0]);
  st->eos_waiting--;
  if( st->eos_waiting == 0 ) {
    if( st->first_time ) {
      struct timespec ts;
      sc_thread_get_time(sc_node_get_thread(st->node), &ts);
      SC_TEST( get_next_pcap_buffer(st) );
      pcap_rotate(st->node,
                  get_natural_time_boundary(ts.tv_sec, st->rotate_secs),
                  st->rotate_secs);
      SC_TEST( get_next_pcap_buffer(st) );
      pcap_put_file_header(st);
      st->first_time = false;
    }
    if( st->pkt && (st->pkt_fill > 0 || st->file_byte_count == 0) )
      pcap_flush_buffer(st->node);
    sc_node_link_end_of_stream(st->node, st->next_hop);
    if( sc_callback_is_active(st->idle_cb) )
      sc_callback_remove(st->idle_cb);
    if( sc_callback_is_active(st->rotate_timer_cb) )
      sc_callback_remove(st->rotate_timer_cb);
    if( sc_callback_is_active(st->buffer_flush_cb) )
      sc_callback_remove(st->buffer_flush_cb);
  }
}


static inline void pcap_empty_rotate(struct sc_node* node) {
  struct sc_pcap_packer_state* st = node->nd_private;
  struct timespec ts;
  sc_thread_get_time(sc_node_get_thread(node), &ts);
  SC_TEST(st->eos_waiting > 0);

  while( st->rotate_secs &&
         ts.tv_sec + st->packet_sys_time_diff > st->next_rotate_sec ) {
    st->file_index = 0;
    pcap_rotate(node, st->next_rotate_sec, true);
    st->next_rotate_sec += st->rotate_secs;
  }
}


static void sc_pcap_packer_pool_cb(struct sc_callback* cb, void* event_info)
{
  struct sc_node* node = cb->cb_private;
  struct sc_pcap_packer_state* st = node->nd_private;
  if( st->pkt == NULL) {
    /* This can happen if we failed to get a buffer after rotating */
    SC_TEST( get_next_pcap_buffer(st) );
  }
}


static void sc_pcap_packer_rotate_timer_cb(struct sc_callback* cb,
                                           void* event_info)
{
  struct sc_node* node = cb->cb_private;
  struct sc_pcap_packer_state* st = node->nd_private;
  if( st->input_idle_state == ST_IDLE ) {
    pcap_empty_rotate(node);
    st->input_idle_state = ST_BUSY;
  }
}


static void sc_pcap_packer_buffer_flush_cb(struct sc_callback* cb,
                                           void* event_info)
{
  struct sc_node* node = cb->cb_private;
  do_partial_flush(node);
}


static void sc_pcap_packer_idle_check_cb(struct sc_callback* cb,
                                         void* event_info)
{
  struct sc_node* node = cb->cb_private;
  struct sc_pcap_packer_state* st = node->nd_private;

  /* Normally we only rotate files when a packet comes in. If we're doing
   * time-based rotation, we still need to rotate periodically if no packets
   * are coming in. So if we haven't seen an input packet for a while,
   * check whether a rotate is due and do it if so.
   */
  if( st->input_idle_state == ST_BUSY ) {
    st->input_idle_state = ST_IDLE;
    sc_timer_expire_after_ns(st->rotate_timer_cb, IDLE_CHECK_NS);
  }
  sc_callback_on_idle(st->idle_cb);
}


static inline void do_rotate(struct sc_node* node, uint64_t ts_sec)
{
  struct sc_pcap_packer_state* st = node->nd_private;
  bool time_rotate = st->rotate_secs &&
    (st->next_rotate_sec <= ts_sec);
  bool size_rotate = st->rotate_file_size &&
    (st->file_byte_count >= st->rotate_file_size);
  if( ! (size_rotate || time_rotate) )
    return;

  struct timespec ts;
  sc_thread_get_time(sc_node_get_thread(node), &ts);
  st->packet_sys_time_diff = ts_sec - ts.tv_sec;
  /* If there is a large jump forward, skipping producing all intermediate
   * empty files
   */
  if ( time_rotate &&
       (ts_sec - st->next_rotate_sec) > EMPTY_ROTATE_MAX_SEC ) {
    while( st->next_rotate_sec < (ts_sec - st->rotate_secs) )
      st->next_rotate_sec += st->rotate_secs;
  }
  do {
    pcap_rotate(node, time_rotate ? st->next_rotate_sec : ts_sec, time_rotate);
    if( time_rotate )
      st->next_rotate_sec += st->rotate_secs;
    time_rotate = st->rotate_secs &&
      (st->next_rotate_sec <= ts_sec);
  } while( time_rotate );
}


static inline bool pack_packed_stream_buffer(struct sc_node* node,
                                             struct sc_packet* pkt,
                                             int* frame_bytes,
                                             int* cap_bytes)
{
  SC_TEST(pkt->flags & SC_PACKED_STREAM);
  SC_TEST(pkt->iovlen == 1);
  struct sc_pcap_packer_state* st = node->nd_private;
  struct sc_packed_packet* ps_pkt = pkt->iov[0].iov_base;
  struct sc_packed_packet* ps_end =
    (void*) ((uint8_t*) pkt->iov[0].iov_base + pkt->iov[0].iov_len);

  while( ps_pkt < ps_end ) {
    if( ! (ps_pkt->ps_flags & st->ps_flags_mask) ) {
      /* This works well if the stream is all < 114 byte packets.  It
       * probably won't hurt in other cases either. Since minimum sized
       * packets are the most challenging case, we're probably fine to
       * optimise for them.
       */
      __builtin_prefetch(ps_pkt + PACKED_STREAM_MIN_STRIDE * 8 ,0, 2);
      __builtin_prefetch(ps_pkt + PACKED_STREAM_MIN_STRIDE * 8 +
                         SC_CACHE_LINE_SIZE, 0, 2);

      do_rotate(node, ps_pkt->ps_ts_sec);
      /* Breaking out of packet packing loop if rotation caused us to run
       * out of buffers.
       */
      if( SC_PKT_POOL_FROM_POOL(st->pool)->pp_n_bufs < 2 ) {
        /* ?? fixme: We are modifying the packed-stream packet in-place,
         * which is highly undesirable because downstream nodes cannot any
         * longer use these packets.
         */
        pkt->iov[0].iov_base = ps_pkt;
        pkt->iov[0].iov_len = (uint8_t*) ps_end - (uint8_t*) ps_pkt;
        return false;
      }
      /* We have at least one packet in the pool, so this is guaranteed to
       * succeed.
       */
      sc_pcap_put_packed_stream_packet(st, ps_pkt);
      *frame_bytes += ps_pkt->ps_orig_len;
      *cap_bytes +=
        (ps_pkt->ps_cap_len <= st->snap) ? ps_pkt->ps_cap_len : st->snap;
      *cap_bytes += sizeof(struct pcap_rec_hdr);
    }
    ps_pkt = sc_packed_packet_next(ps_pkt);
  }
  return true;
}


static inline bool pack_normal_buffer(struct sc_node* node,
                                      struct sc_packet* pkt,
                                      int* frame_bytes, int* cap_bytes)
{
  struct sc_pcap_packer_state* st = node->nd_private;
  do_rotate(node, pkt->ts_sec);
  /* Breaking out of packet packing loop if rotation caused us to run out
   * of buffers
   */
  if( SC_PKT_POOL_FROM_POOL(st->pool)->pp_n_bufs < 2 )
    return false;
  int pkt_len = sc_packet_bytes(pkt);
  /* Since we have at least one packet in the bool, put_packet is guaranteed
   * to succeed.
   */
  sc_pcap_put_packet(st, pkt, pkt_len);
  *frame_bytes += pkt->frame_len;
  *cap_bytes += (pkt_len <= st->snap) ? pkt_len : st->snap;
  *cap_bytes += sizeof(struct pcap_rec_hdr);

  struct sc_packet* prefetch_pkt =
    (struct sc_packet*)((char *)(pkt) +
                        SC_DMA_PKT_BUF_SIZE * PREFETCH_STRIDE);
  sc_packet_prefetch_r((prefetch_pkt));
  return true;
}


static inline void pack_packet_list(struct sc_node* node,
                                    struct sc_packet_list* pl,
                                    struct sc_packet_list* done,
                                    int* frame_bytes,
                                    int* cap_bytes)
{
  while( !sc_packet_list_is_empty(pl) ) {
    if(pl->head->flags & SC_PACKED_STREAM) {
      if( ! pack_packed_stream_buffer(node, pl->head,
                                      frame_bytes, cap_bytes))
        break;
    }
    else {
      if( ! pack_normal_buffer(node, pl->head,
                               frame_bytes, cap_bytes))
        break;
    }
    sc_packet_list_append(done, sc_packet_list_pop_head(pl));
  }
}


static void
sc_pcap_packer_handle_backlog(struct sc_subnode_helper* sh)
{
  struct sc_pcap_packer_state* st = sh->sh_private;

  /* Normally our sh_pool_threshold ensures this, but at start of day
   * we can be scheduled from a timer which skips the pool check */
  if( sc_pool_available_bufs(st->pool) < 2 )
    return;

  st->input_idle_state = ST_BUSY;
  struct sc_packet_list done;
  int frame_bytes = 0;
  int cap_bytes = 0;
  sc_packet_list_init(&done);
  /* Normally we don't push data to disk until we've filled a pcap buffer. This
   * could leave data buffered in this node indefinitely. So we add a callback
   * to flush a part-filled buffer.
   */
  if( ! sc_callback_is_active(st->buffer_flush_cb) )
    sc_timer_expire_after_ns(st->buffer_flush_cb, IDLE_CHECK_NS);

  struct sc_packet_list* pl = &sh->sh_backlog;
  if( st->first_time && st->filename_template != NULL ) {
    struct timespec ts;
    sc_thread_get_time(sc_node_get_thread(st->node), &ts);
    st->packet_sys_time_diff = pl->head->ts_sec - ts.tv_sec;
    uint64_t first_timestamp = get_natural_time_boundary(pl->head->ts_sec,
                                                         st->rotate_secs);
    pcap_rotate(st->node, first_timestamp, st->rotate_secs);
    if( st->rotate_secs ) {
      st->next_rotate_sec = first_timestamp + st->rotate_secs;
    }
    st->first_time = false;
    if( st->rotate_secs )
      sc_callback_on_idle(st->idle_cb);
  }

  if( ! st->ready ) {
    sh->sh_poll_backlog_ns = 10000;
    return;
  }

  sh->sh_poll_backlog_ns = 0;

  if( st->pkt == NULL) {
    /* This can happen if we failed to get a buffer after rotating */
    SC_TEST( get_next_pcap_buffer(st) );
  }

  pack_packet_list(st->node, pl, &done, &frame_bytes, &cap_bytes);

  if( !sc_packet_list_is_empty(&st->list_out) ) {
    __sc_forward_list(st->node, st->next_hop, &st->list_out);
    sc_packet_list_init(&st->list_out);
    /* Since we've emitted buffers, push back the flush callback.
     */
    sc_timer_expire_after_ns(st->buffer_flush_cb, IDLE_CHECK_NS);
    st->output_idle_state = ST_BUSY;
  }

  if( !sc_packet_list_is_empty(&done) )
    __sc_forward_list(sh->sh_node, sh->sh_links[0], &done);
}


static struct sc_node* sc_pcap_packer_select_subnode(struct sc_node* node,
                                                     const char* name_opt,
                                                     char** new_name_out)
{
  struct sc_pcap_packer_state* st = node->nd_private;

  /* Select subnodes by link to_name. If this name hasn't been seen before,
   * allocate new subnode.
   */
  if( name_opt != NULL ) {
    int i;
    for( i = 0 ; i < st->inputs_n; ++i )
      if( st->input_names[i] && ! strcmp(name_opt, st->input_names[i]) )
        return st->inputs[i]->sh_node;
  }

  struct sc_attr* attr;
  SC_TRY( sc_attr_alloc(&attr) );

  struct sc_node* input_node;
  SC_TRY( sc_attr_set_from_fmt(attr, "name", "%s.sh(%s)", node->nd_name,
                               name_opt) );
  int rc = sc_node_alloc(&input_node, attr, sc_node_get_thread(node),
                         &sc_subnode_helper_sc_node_factory, NULL, 0);
  sc_attr_free(attr);
  if( rc < 0 ) {
    sc_node_fwd_error(node, rc);
    return NULL;
  }

  struct sc_subnode_helper* input = sc_subnode_helper_from_node(input_node);
  input->sh_private = st;
  input->sh_handle_backlog_fn = sc_pcap_packer_handle_backlog;
  input->sh_handle_end_of_stream_fn = sc_pcap_packer_handle_end_of_stream;

  ++st->inputs_n;
  st->inputs = realloc(st->inputs, sizeof(input) * (st->inputs_n));
  st->input_names = realloc(st->input_names, sizeof(char*) * (st->inputs_n));
  st->inputs[st->inputs_n - 1] = input;
  st->input_names[st->inputs_n - 1] = (name_opt) ? strdup(name_opt) : NULL;
  ++st->eos_waiting;
  if( st->all_inputs_to_node != NULL ) {
    rc = sc_node_add_link(input->sh_node, "", st->all_inputs_to_node,
                          st->all_inputs_to_name_opt);
    if( rc < 0 ) {
      sc_node_fwd_error(node, rc);
      return NULL;
    }
  }
  return input_node;
}


static int sc_pcap_packer_add_link(struct sc_node* from_node,
                                   const char* link_name,
                                   struct sc_node* to_node,
                                   const char* to_name_opt)
{
  struct sc_pcap_packer_state* st = from_node->nd_private;
  int i, rc;
  if( ! strcmp("", link_name) ) {
    /* This output gets the PCAP output. */
    return sc_node_add_link(from_node, link_name, to_node, to_name_opt);
  }
  else if( ! strcmp("#input", link_name) ) {
    /* This output gets all inputs. */
    if( st->added_named_input_link )
      return sc_node_set_error(from_node, EINVAL, "%s: ERROR: Cannot add #input"
                               " after a named link\n", __func__);
    for( i = 0 ; i < st->inputs_n ; ++i )
      if( (rc = sc_node_add_link(st->inputs[i]->sh_node, "",
                                 to_node, to_name_opt)) < 0 )
        return sc_node_fwd_error(from_node, rc);
    st->all_inputs_to_node = to_node;
    st->all_inputs_to_name_opt = (to_name_opt) ? strdup(to_name_opt) : NULL;
    return 0;
  }
  else {
    /* Otherwise link_name should be the name of a particular input. */
    if( st->all_inputs_to_node != NULL )
      return sc_node_set_error(from_node, EINVAL, "%s: ERROR: Cannot add link "
                               "'%s' after #input\n", __func__, link_name);
    for( i = 0 ; i < st->inputs_n ; ++i )
      if( st->input_names[i] && ! strcmp(link_name, st->input_names[i]) ) {
        st->added_named_input_link = true;
        return sc_node_add_link(st->inputs[i]->sh_node, link_name,
                                to_node, to_name_opt);
      }
    return sc_node_set_error(from_node, EINVAL, "%s: ERROR: Link name should "
                             "be \"\", \"#input\" or match an input\n",
                             __func__);
  }
}


void sc_pcap_packer_redirect_eos(struct sc_node* node,
                                 struct sc_node* eos_fwd)
{
  int i;
  struct sc_pcap_packer_state* st = node->nd_private;
  for( i = 0 ; i < st->inputs_n ; ++i )
    sc_eos_fwd_register_link(eos_fwd, st->inputs[i]->sh_links[0]);
  st->eos_redirected = true;
}


static int sc_pcap_packer_prep(struct sc_node* node,
                               const struct sc_node_link*const* links,
                               int n_links)
{
  struct sc_pcap_packer_state* st = node->nd_private;
  st->next_hop = sc_node_prep_get_link_or_free(node, "");
  int rc = sc_node_prep_check_links(node);
  if( rc < 0 )
    return rc;

  /* We require that a max size packet plus file and per-packet headers
   * fits in a single output buffer.  We set the output buffer size and/or
   * snap length so that we don't have to bomb-out later if an over-length
   * packet arrives.
   */
  int max_headers = sizeof(struct pcap_file_hdr) + sizeof(struct pcap_rec_hdr);
  if( st->pool_attr->buf_size_pcap > 0 )
    st->pool_attr->buf_size = st->pool_attr->buf_size_pcap;
  else if( st->snap + max_headers <= 32768 )
    st->pool_attr->buf_size = 32768;
  else
    st->pool_attr->buf_size = st->snap + max_headers;
  int min_snap = (st->snap > 0) ? st->snap : 16*1024;
  if( min_snap + max_headers > st->pool_attr->buf_size )
    return sc_node_set_error(node, EINVAL, "sc_pcap_packer: ERROR: snap=%d "
                             "is incompatible with buf_size_pcap=%d\n",
                             st->snap, (int) st->pool_attr->buf_size);
  if( st->snap <= 0 )
    /* If they've not asked to snap, use the largest value we can without
     * breaking the above rule.
     */
    st->snap = st->pool_attr->buf_size - max_headers;

  rc = sc_node_prep_get_pool(&st->pool, st->pool_attr, node, NULL, 0);
  if( rc < 0 )
    return sc_node_fwd_error(node, rc);

  int i;
  for( i = 0 ; i < st->inputs_n ; ++i ) {
    st->inputs[i]->sh_pool = st->pool;
    st->inputs[i]->sh_pool_threshold = 2;
  }
  __sc_packet_list_init(&st->list_out);
  st->buffer_size = SC_PKT_POOL_FROM_POOL(st->pool)->pp_buf_size;
  return 0;
}


#define get_arg_int     sc_node_init_get_arg_int
#define get_arg_int64   sc_node_init_get_arg_int64
#define get_arg_str     sc_node_init_get_arg_str


static int sc_pcap_packer_init(struct sc_node* node, const struct sc_attr* attr,
                               const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_prep_fn = sc_pcap_packer_prep;
    nt->nt_select_subnode_fn = sc_pcap_packer_select_subnode;
    nt->nt_add_link_fn = sc_pcap_packer_add_link;
  }
  sc_pcap_packer_stats_declare(sc_thread_get_session(sc_node_get_thread(node)));
  node->nd_type = nt;

  int snap, rotate_secs, wait_for_byte_count, discard_mask;
  int64_t rotate_fs;
  const char *format, *on_error_s, *filename;
  if( get_arg_int(&snap, node, "snap", 0)                                 < 0 ||
      get_arg_int(&rotate_secs, node, "rotate_seconds", 0)                < 0 ||
      get_arg_int64(&rotate_fs, node, "rotate_file_size", 0)              < 0 ||
      get_arg_str(&format, node, "format", "pcap")                        < 0 ||
      get_arg_str(&on_error_s, node, "on_error", "exit")                  < 0 ||
      get_arg_str(&filename, node, "filename", NULL)                      < 0 ||
      get_arg_int(&wait_for_byte_count, node, "wait_for_byte_count", 0)   < 0 ||
      get_arg_int(&discard_mask, node, "discard_mask", 0)                 < 0  )
    return -1;

  enum ts_type ts_type;
  if( ! ts_type_from_str(format, &ts_type) )
    return sc_node_set_error(node, EINVAL, "sc_pcap_packer: ERROR: bad format "
                             "'%s'; expected one of: pcap pcap-ns\n", format);
  if( rotate_secs < 0 )
    return sc_node_set_error(node, EINVAL, "sc_pcap_packer: ERROR: "
                             "rotate_seconds must be >= 0\n");

  if( rotate_fs < 0 )
    return sc_node_set_error(node, EINVAL,
                             "sc_pcap_packer: ERROR: rotate_file_size must "
                             "be >= 0\n");

  enum on_error on_error;
  if( ! on_error_from_str(on_error_s, &on_error) )
    return sc_node_set_error(node, EINVAL, "sc_pcap_packer: ERROR: bad "
                             "on_error '%s'; expected one of: exit abort "
                             "message silent\n", on_error_s);


  struct sc_pcap_packer_state* st;
  st = sc_thread_calloc(sc_node_get_thread(node), sizeof(*st));
  node->nd_private = st;
  st->node = node;
  st->first_time = true;
  st->next_rotate_sec = UINT64_MAX;
  st->file_index = 0;
  st->snap = (snap > 0) ? snap : attr->snap;
  st->rotate_secs = rotate_secs;
  st->rotate_file_size = rotate_fs;
  st->on_error = on_error;
  st->ts_type = ts_type;
  st->ready = ! wait_for_byte_count;
  st->ps_flags_mask = 0;
  st->pool_attr = sc_attr_dup(attr);
  if( discard_mask & SC_CSUM_ERROR )
    st->ps_flags_mask |= (SC_PS_FLAG_BAD_L3_CSUM | SC_PS_FLAG_BAD_L4_CSUM);
  if( discard_mask & SC_CRC_ERROR )
    st->ps_flags_mask |= SC_PS_FLAG_BAD_FCS;

  if( filename != NULL ) {
    st->filename_template = strdup(filename);
    SC_TEST( st->filename_time_rotated =
               malloc(strlen(filename) + TEMPLATE_EXPANSION_SPACE) );
    strcpy(st->filename_time_rotated, filename);
  }
  else {
    st->filename_template = NULL;
  }

  SC_TEST(sc_callback_alloc(&st->pool_cb, NULL, sc_node_get_thread(node)) == 0);
  st->pool_cb->cb_private = node;
  st->pool_cb->cb_handler_fn = sc_pcap_packer_pool_cb;

  SC_TEST(sc_callback_alloc(&st->idle_cb, NULL, sc_node_get_thread(node)) == 0);
  st->idle_cb->cb_private = node;
  st->idle_cb->cb_handler_fn = sc_pcap_packer_idle_check_cb;

  SC_TEST(sc_callback_alloc(&st->rotate_timer_cb, NULL,
                            sc_node_get_thread(node)) == 0);
  st->rotate_timer_cb->cb_private = node;
  st->rotate_timer_cb->cb_handler_fn = sc_pcap_packer_rotate_timer_cb;

  SC_TEST(sc_callback_alloc(&st->buffer_flush_cb, NULL,
                            sc_node_get_thread(node)) == 0);
  st->buffer_flush_cb->cb_private = node;
  st->buffer_flush_cb->cb_handler_fn = sc_pcap_packer_buffer_flush_cb;

  sc_node_export_state(node, "sc_pcap_packer_stats",
                       sizeof(struct sc_pcap_packer_stats), &st->stats);
  return 0;
}


const struct sc_node_factory sc_pcap_packer_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_pcap_packer",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_pcap_packer_init,
};

/** \endcond NODOC */
