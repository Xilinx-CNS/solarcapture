/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/** \cond NODOC */
/*
 * NOTE: We do not want customers to use this node at this point.
 *       If you add any Doxygen documentation, mark it as \internal.
 */
 #ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#include "../core/internal.h"
#include <sc_internal.h>
#include <sc_internal/builtin_nodes.h>
#include <sc_internal/io.h>
#include <sc_internal/appliance.h>
#include <solar_capture/nodes/subnode_helper.h>


#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <libaio.h>
#include <inttypes.h>
#include <float.h>
#include <stdbool.h>

#define SC_TYPE_TEMPLATE  <sc_block_writer_types_tmpl.h>
#define SC_DECLARE_TYPES  sc_block_writer_stats_declare
#include <solar_capture/declare_types.h>

#define MAX_RESP_LEN                  255

#define MAX_SUBMIT                    32
#define MAX_REAP                      128
#define DEFAULT_N_IOS                 2048
#define FREE_IO_BLOCK_THRESHOLD       4
#define MEMORY_ALIGNMENT              4096

#define SCORE_DEFAULT_SCALE_ALLOC     0.001

#define SCORE_Q_QUANT                 5
#define MAX_OUTSTANDING               80

#define REAP_PERIOD_NS                100000000 /* 100ms */
#define LOG_PERIOD_DEFAULT_MS         100


const struct sc_node_factory sc_block_writer_io_sc_node_factory;


struct sc_async_io {
  struct   sc_dlist link;
  struct   iocb iocb;
  struct   sc_packet* pkt;
  struct   sc_subnode_helper* sh;
  uint64_t offset;
  uint64_t start_offset;
  int      device_i;
  bool     done;
  int      size;
};


struct sc_block_writer_device {
  int fd;
  int32_t id;
  char device[MAX_INDEX_DEVICENAME_LEN];
  int n_outstanding_ios;
  uint64_t complete_offset;
  uint64_t size;
  uint64_t offset;
  uint64_t n_wraps;
  uint64_t n_allocations;
};


struct sc_block_writer {
  struct sc_node*                 node;
  struct sc_block_writer_stats*   stats;
  struct sc_subnode_helper*       index_io;
  struct sc_subnode_helper*       session_closer_io;
  struct sc_block_writer_device*  devices;
  uint64_t                        write_offset;
  uint64_t                        max_allocations;
  unsigned                        max_write_size;
  unsigned                        min_write_size;
  int                             devices_n;
  int                             device_i;
  struct sc_dlist                 free_async_ios;
  int                             n_free_ios;
  unsigned                        n_ios;
  io_context_t                    io_ctx;
  struct sc_dlist                 submitted_async_ios;
  struct sc_subnode_helper**      inputs;
  struct sc_callback*             reap_cb;
  struct sc_callback*             log_cb;
  char*                           valid_req_sock;
  int                             max_io_message_size;
  bool                            indexing;
  bool                            session_closer_connected;
  bool                            output_added;
  int                             inputs_n;
  int                             eos_waiting;
  FILE*                           log_file;
  uint64_t                        log_ns;
  bool                            (*emit_index)(struct sc_block_writer*, struct sc_async_io*);
};


static void
sc_block_writer_try_propagate_end_of_stream(struct sc_block_writer* bw);

static void
sc_block_writer_do_backlog(struct sc_block_writer* bw,
                           struct sc_subnode_helper* sh);

static bool
sc_block_writer_emit_block_index(struct sc_block_writer* bw,
                                 struct sc_async_io* aio);

static bool
sc_block_writer_emit_flow_index(struct sc_block_writer* bw,
                                struct sc_async_io* aio);


static void
sc_block_writer_log_header(struct sc_block_writer* bw) {
  unsigned i;
  fprintf(bw->log_file, "timestamp,free_ios");
  for( i = 0 ; i < bw->devices_n ; ++i ) {
    fprintf(bw->log_file, ",%s_n_oustanding_ios,%s_n_allocations",
            bw->devices[i].device,
            bw->devices[i].device);
  }
  for( i = 0 ; i < bw->inputs_n ; ++i )
    fprintf(bw->log_file, ",%d_input_backlog",i);
  fprintf(bw->log_file, "\n");
}


static void
sc_block_writer_dump_state(struct sc_block_writer* bw) {
  unsigned i;
  struct timespec ts;
  sc_thread_get_time(sc_node_get_thread(bw->node), &ts);
  fprintf(bw->log_file, "%llu.%09lu,%d", (unsigned long long)ts.tv_sec,
          ts.tv_nsec, bw->n_free_ios);
  for( i = 0 ; i < bw->devices_n ; ++i )
    fprintf(bw->log_file, ",%d,%"PRIu64, bw->devices[i].n_outstanding_ios,
            bw->devices[i].n_allocations);
  for( i = 0 ; i < bw->inputs_n ; ++i )
    fprintf(bw->log_file, ",%d", bw->inputs[i]->sh_backlog.num_pkts);
  fprintf(bw->log_file, "\n");
}


static void
sc_block_writer_log_cb(struct sc_callback* cb,
                       void* event_info)
{
  struct sc_block_writer* bw = cb->cb_private;
  sc_block_writer_dump_state(bw);
  sc_timer_expire_after_ns(cb, bw->log_ns);
}


/* Completed io requests are freed in order. This is important for cases where
 * there is a downstream consumer and also makes it simpler to track valid
 * regions.  Strictly speaking, we only need ordering per device for valid
 * regions, and ordering per input for downstream consumers. We do it globally
 * for simplicity.
 */
static void
sc_block_writer_try_free_submitted_ios(struct sc_block_writer* bw)
{
  while( !sc_dlist_is_empty(&bw->submitted_async_ios) ) {
    struct sc_async_io* aio =
      SC_CONTAINER(struct sc_async_io, link,
                   sc_dlist_pop_head(&bw->submitted_async_ios));
    if( !aio->done ) {
      sc_dlist_push_head(&bw->submitted_async_ios, &aio->link);
      break;
    }
    /* If we split incoming blocks into multiple write requests, only the last
     * one of these has aio->pkt set to non-NULL.
     */
    if( aio->pkt ) {
      if( bw->emit_index(bw, aio) ) {
        sc_forward(aio->sh->sh_node, aio->sh->sh_links[0], aio->pkt);
      }
      else {
        sc_dlist_push_head(&bw->submitted_async_ios, &aio->link);
        break;
      }
      bw->devices[aio->device_i].complete_offset = aio->start_offset + aio->size;
    }

    sc_dlist_push_tail(&bw->free_async_ios, &aio->link);
     ++bw->n_free_ios;
   }
   bw->stats->n_free_ios = bw->n_free_ios;
 }


static float
score_device(struct sc_block_writer* bw, int device_i)
{
  SC_TEST(device_i <= bw->devices_n);
  struct sc_block_writer_device* dev = &bw->devices[device_i];
  uint64_t alloc_diff = bw->max_allocations - dev->n_allocations;
  /* Favouring devices with fewer outstanding IOs and fewer total allocations.
   * Choice of parameters needs further thought and experiments. It may be that
   * that they need to be tuned for particular RAID controllers.
   */
  return (dev->n_outstanding_ios / SCORE_Q_QUANT) * -1.0 +
    alloc_diff * SCORE_DEFAULT_SCALE_ALLOC;
}


static bool
get_next_device(struct sc_block_writer* bw)
{
  float max_score = -FLT_MAX;
  int max_dev = -1;
  unsigned i;
  for( i = 0 ; i < bw->devices_n ; i++ ) {
    float score = score_device(bw, i);
    /* Placing a hard limit on the number of in-flight writes. This is necessary
     * for getting decent performance from HP devices. This might need to be
     * exposed as an argument if it turns out we need differing values for
     * different controllers.
     */
    if( bw->devices[i].n_outstanding_ios <= MAX_OUTSTANDING &&
        score > max_score ) {
      max_score = score;
      max_dev = i;
    }
  }
  if( max_dev == -1 )
    return false;
  bw->device_i = max_dev;
  return true;
}


static bool
sc_block_writer_get_block(struct sc_block_writer* bw, int length)
{
  if( !get_next_device(bw) )
    return false;

  bw->write_offset = bw->devices[bw->device_i].offset;
  if( bw->write_offset + length > bw->devices[bw->device_i].size ){
    bw->write_offset = 0;
    ++bw->devices[bw->device_i].n_wraps;
  }
  bw->devices[bw->device_i].offset = bw->write_offset + length;

  ++bw->devices[bw->device_i].n_allocations;
  if( bw->devices[bw->device_i].n_allocations > bw->max_allocations )
    bw->max_allocations = bw->devices[bw->device_i].n_allocations;
  ++bw->stats->block_count;
  return true;
}


static bool
sc_block_writer_emit_block_index(struct sc_block_writer* bw,
                                 struct sc_async_io* aio)
{
  struct sc_packet* pkt;
  struct sc_appliance_index_entry* ie;
  struct timespec ts;

  if( !bw->indexing )
    return true;

  sc_thread_get_time(sc_node_get_thread(bw->node), &ts);

  struct sc_packet_list pl;
  __sc_packet_list_init(&pl);

  /* In case we run out of packets and emit_index fails, there's a periodic
   * retry of sc_block_writer_try_free_submitted_ios() via
   * sc_block_writer_reap_cb(). So we don't need to add a threshold
   * callback here.
   */
  if( sc_pool_get_packets(&pl, bw->index_io->sh_pool, 1, 1) != 1 )
    return false;

  pkt = pl.head;
  SC_TEST( pkt->iovlen == 1 && pkt->iov[0].iov_len >= sizeof(*ie));
  ie = pkt->iov[0].iov_base;

  strncpy(ie->devicename, bw->devices[aio->device_i].device,
          MAX_INDEX_DEVICENAME_LEN);
  ie->byte_offset = aio->start_offset;
  struct sc_packed_packet* pkt_hdr = aio->pkt->iov[0].iov_base;
  struct sc_appliance_buffer_header* buf_hdr = (void*)(pkt_hdr + 1);
  SC_TEST(buf_hdr->hdr.prh_type == SC_PACKED_RECORD_APPLIANCE_BLOCK_HEADER);
  SC_TEST(buf_hdr->data.version == PBH_VERSION);
  ie->pkt_index = buf_hdr->data.pkt_index;
  ie->pkt_count = buf_hdr->data.pkt_count;
  ie->start_ns_epoch = buf_hdr->data.start_ns_epoch;
  ie->end_ns_epoch = buf_hdr->data.end_ns_epoch;
  ie->update_ts_sec = ts.tv_sec;
  strncpy(ie->stream_id, buf_hdr->data.stream_id, STREAM_ID_STRLEN);
  pkt->iov[0].iov_len = sizeof(*ie);
  sc_forward(bw->index_io->sh_node, bw->index_io->sh_links[0], pkt);
  return true;
}


static bool
sc_block_writer_emit_flow_index(struct sc_block_writer* bw,
                                struct sc_async_io* aio)
{
  struct sc_packet* pkt;
  struct sc_appliance_flow_record_entry_db* flow_db_message;
  struct timespec ts;

  if( !bw->indexing )
    return true;

  sc_thread_get_time(sc_node_get_thread(bw->node), &ts);

  struct sc_packet_list pl;
  __sc_packet_list_init(&pl);

  /* In case we run out of packets and emit_index fails, there's a periodic
   * retry of sc_block_writer_try_free_submitted_ios() via
   * sc_block_writer_reap_cb(). So we don't need to add a threshold
   * callback here.
   */
  if( sc_pool_get_packets(&pl, bw->index_io->sh_pool, 1, 1) != 1 )
    return false;

  pkt = pl.head;
  SC_TEST( pkt->iov[0].iov_len >= sizeof(*flow_db_message) );
  flow_db_message = pkt->iov[0].iov_base;

  struct flow_header* flow_header = aio->pkt->iov[0].iov_base;
  memcpy(&flow_db_message->flow_hdr, flow_header, sizeof(*flow_header));
  flow_db_message->byte_offset = aio->start_offset;
  flow_db_message->byte_length = aio->size;
  flow_db_message->update_ts_sec = ts.tv_sec;

  /* The length should be memory aligned */
  SC_TEST( flow_db_message->byte_length % MEMORY_ALIGNMENT == 0 );

  strncpy(flow_db_message->devicename, bw->devices[aio->device_i].device,
            MAX_INDEX_DEVICENAME_LEN);
  pkt->iov[0].iov_len = sizeof(*flow_db_message);
  sc_forward(bw->index_io->sh_node, bw->index_io->sh_links[0], pkt);
  return true;
}


static void
sc_block_writer_reap(struct sc_block_writer* bw, int min_reap)
{
  struct io_event events[MAX_REAP];
  int num_events, i;
  struct sc_async_io* async_io;

  num_events = io_getevents(bw->io_ctx, min_reap, MAX_REAP, events, NULL);

  for( i = 0; i < num_events; i++ ) {
    assert( !sc_dlist_is_empty(&bw->submitted_async_ios));
    async_io = (struct sc_async_io*)events[i].data;
    --bw->devices[async_io->device_i].n_outstanding_ios;
    async_io->done = true;
  }
  sc_block_writer_try_free_submitted_ios(bw);
}


static void
sc_block_writer_send_session_close_msgs(struct sc_block_writer* bw)
{
  SC_TEST(bw->session_closer_connected);
  struct sc_packet* pkt;
  int i;
  for( i = 0 ; i < bw->devices_n ; ++i ) {
    struct sc_packet_list pl;
    __sc_packet_list_init(&pl);
    /* This pool is only ever used at end of stream, so we're guaranteed to get
     *  a packet.
     */
    SC_TEST(sc_pool_get_packets(&pl, bw->session_closer_io->sh_pool, 1, 1) == 1);
    pkt = pl.head;

    struct sc_appliance_block_writer_session_close_msg* msg =
      pkt->iov[0].iov_base;
    msg->allocate_offset = bw->devices[i].offset;
    SC_TEST(strlen(bw->devices[i].device) <= MAX_INDEX_DEVICENAME_LEN);
    strcpy(msg->devicename, bw->devices[i].device);
    pkt->iov[0].iov_len = sizeof(*msg);
    sc_forward(bw->session_closer_io->sh_node,
               bw->session_closer_io->sh_links[0], pkt);
  }
}


static void
sc_block_writer_try_propagate_end_of_stream(struct sc_block_writer* bw)
{
  SC_TEST( bw->eos_waiting == 0 );
  while( !sc_dlist_is_empty(&bw->submitted_async_ios) )
        sc_block_writer_reap(bw, 1);

  int i;
  for( i = 0 ; i < bw->inputs_n ; ++i )
    sc_node_link_end_of_stream(bw->inputs[i]->sh_node,
                               bw->inputs[i]->sh_links[0]);
  if( bw->indexing )
    sc_node_link_end_of_stream(bw->index_io->sh_node,
                               bw->index_io->sh_links[0]);

  if( bw->session_closer_connected ) {
    /* Message send cannot fail because this is the only time we ever use
     * buffers from the pool.
     */
    sc_block_writer_send_session_close_msgs(bw);
    sc_node_link_end_of_stream(bw->session_closer_io->sh_node,
                               bw->session_closer_io->sh_links[0]);
  }
}


static struct sc_async_io*
prep_write(struct sc_block_writer* bw, struct sc_subnode_helper* sh,
           void* src, int write_size, struct sc_packet* pkt,
           struct sc_packet* pkt_info, uint64_t start_offset)
{
  SC_TEST(bw->n_free_ios > 0);
  struct sc_async_io* async_io =
    SC_CONTAINER(struct sc_async_io, link,
                 sc_dlist_pop_head(&bw->free_async_ios));
  --bw->n_free_ios;
  SC_TEST(write_size % MEMORY_ALIGNMENT == 0);
  io_prep_pwrite(&async_io->iocb, bw->devices[bw->device_i].fd,
                 src, write_size, bw->write_offset);

  async_io->done = false;
  async_io->iocb.data = async_io;
  async_io->pkt = pkt;
  async_io->sh = sh;
  async_io->device_i = bw->device_i;
  async_io->offset = bw->write_offset;
  async_io->size = pkt_info->iov[0].iov_len;
  async_io->start_offset = start_offset;
  return async_io;
}


static struct iocb*
create_write_request_and_update_current_write_offset(struct sc_block_writer* bw, struct sc_subnode_helper* sh,
                                                     void* src, int write_size, struct sc_packet* pkt,
                                                     struct sc_packet* pkt_info, uint64_t start_offset)
 {
  struct sc_async_io* io_callback = prep_write(bw, sh, src, write_size, pkt,
                                               pkt_info, start_offset);
  ++bw->devices[bw->device_i].n_outstanding_ios;
  bw->write_offset += write_size;
  return &io_callback->iocb;
}


static void
submit_write(struct sc_block_writer* bw, struct iocb** cbs, int n_writes,
             int submit_chunk)
{
  unsigned i;
  for( i = 0; i < n_writes; ++i )
    sc_dlist_push_tail(&bw->submitted_async_ios, &((struct sc_async_io*)(cbs[i]->data))->link);

  for( i = 0; i < n_writes / submit_chunk ; i++)
    SC_TEST(io_submit(bw->io_ctx, submit_chunk,
                      &cbs[i * submit_chunk]) == submit_chunk);
  unsigned n_tail = n_writes % submit_chunk;
  if( n_tail > 0 )
    SC_TEST(io_submit(bw->io_ctx, n_tail, &cbs[n_writes - n_tail]) == n_tail);
}


static void
sc_block_writer_submit_list(struct sc_block_writer* bw,
                            struct sc_subnode_helper* sh)
{
  unsigned n_reqs = 0;
  struct iocb* iocbs_to_submit[MAX_SUBMIT];
  struct sc_packet_list* backlog = &sh->sh_backlog;
  SC_TEST( !sc_packet_list_is_empty(backlog) );

  while( !sc_packet_list_is_empty(backlog) ) {
    unsigned n_ios_req_quot = backlog->head->iov[0].iov_len / bw->max_write_size;
    unsigned n_ios_req_rem = backlog->head->iov[0].iov_len % bw->max_write_size;

    unsigned num_io_reqs_to_create = n_ios_req_quot;
    uint64_t final_req_write_size = bw->max_write_size;
    if( n_ios_req_rem ) {
      ++num_io_reqs_to_create;
      final_req_write_size = n_ios_req_rem;
    }

    SC_TEST( final_req_write_size % bw->min_write_size == 0 );
    SC_TEST( num_io_reqs_to_create <= MAX_SUBMIT );

    uint64_t block_size = backlog->head->iov[0].iov_len;

    if( n_reqs + num_io_reqs_to_create >= MAX_SUBMIT   ||
        ! sc_block_writer_get_block(bw, block_size)    )
      break;

    if( bw->n_free_ios < num_io_reqs_to_create ) {
      bw->stats->n_not_enough_ios++;
      break;
    }

    struct sc_packet* pkt_to_write = sc_packet_list_pop_head(backlog);
    uint64_t start_offset = bw->write_offset;
    unsigned i;
    for( i = 0; i < num_io_reqs_to_create - 1; ++i )
      iocbs_to_submit[n_reqs++] = create_write_request_and_update_current_write_offset(bw, sh,
                                                                         (char*)pkt_to_write->iov[0].iov_base +
                                                                         i * bw->max_write_size,
                                                                         bw->max_write_size, NULL, pkt_to_write,
                                                                         start_offset);


    /* The final prep needs to set the pkt pointer to indicate that this is
     * the last chunk of the packet to write to disk */
    iocbs_to_submit[n_reqs++] = create_write_request_and_update_current_write_offset(bw, sh,
                                           (char*)pkt_to_write->iov[0].iov_base + (num_io_reqs_to_create - 1) * bw->max_write_size,
                                           final_req_write_size, pkt_to_write, pkt_to_write,
                                           start_offset);
  }
  if( n_reqs > 0)
    submit_write(bw, iocbs_to_submit, n_reqs, 1);
}


static void
sc_block_writer_do_backlog(struct sc_block_writer* bw,
                           struct sc_subnode_helper* sh)
{
  if( !sc_dlist_is_empty(&bw->submitted_async_ios) ) {
    /* If we're running out of async_ios, blocking on reap. Otherwise get what
     * we can and continue.
     */
    int min_reap = ( bw->n_free_ios > FREE_IO_BLOCK_THRESHOLD ) ? 0 : 1;
    sc_block_writer_reap(bw, min_reap);
  }

  if( !sc_packet_list_is_empty(&sh->sh_backlog) )
    sc_block_writer_submit_list(bw, sh);

  bw->stats->n_free_ios = bw->n_free_ios;
}


static int
sc_block_writer_alloc_device(struct sc_block_writer* bw, const char* device,
                             int32_t device_id, uint64_t initial_offset,
                             uint64_t size)
{
  struct sc_session* tg = sc_thread_get_session(sc_node_get_thread(bw->node));
  struct sc_block_writer_device* odev;

  bw->devices = realloc(bw->devices, sizeof(*odev) * ++bw->devices_n);
  odev = &bw->devices[bw->devices_n - 1];
  if( strlen(device) + 1 > MAX_INDEX_DEVICENAME_LEN ) {
      sc_trace(tg, "%s: Device name too large (len(%s) > %d)\n", __func__, device,
               MAX_INDEX_DEVICENAME_LEN);
    return -1;
  }
  if( initial_offset % bw->min_write_size != 0 ||
      initial_offset > size - bw->min_write_size ) {
      sc_trace(tg, "%s: Invalid minimum write size (size: %"PRIu64" initial offset: %"
               PRIu64" min_write_size: %u\n", __func__, size, initial_offset, bw->min_write_size);
    return -1;
  }

  strcpy(odev->device, device);
  odev->id = device_id;
  odev->n_outstanding_ios = 0;
  odev->n_wraps = 0;
  odev->n_allocations = 0;
  odev->offset = initial_offset;
  /* Initial valid region is (initial_offset + block_length) to
     initial_offset */
  odev->complete_offset = initial_offset;
  odev->size = size;
  int flags = O_WRONLY|O_DIRECT;
  int mode = S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH;
  odev->fd = open(device, flags, mode);
  sc_trace(tg, "%s: device %s opened with fd %d\n", __func__, device, odev->fd);
  return odev->fd;
}


static void create_disconnect_pkt(struct sc_packet* out_pkt)
{
  struct sc_io_msg_hdr* out_hdr = out_pkt->iov[0].iov_base;
  out_hdr->msg_type = SC_IO_MSG_CLOSE;
  out_pkt->iov[0].iov_len = sizeof(*out_hdr);
}

static void
sc_block_writer_construct_valid_resp_msg(struct sc_block_writer* bw,
                                         int connection_id, int32_t device_id,
                                         uint64_t uid,
                                         struct sc_packet* out_pkt)
{
  struct sc_io_msg_hdr* out_hdr = out_pkt->iov[0].iov_base;
  int device_i = -1;
  int i;
  for( i = 0 ; i < bw->devices_n ; ++i ) {
    if( device_id == bw->devices[i].id ) {
      device_i = i;
      break;
    }
  }
  out_hdr->connection_id = connection_id;
  if( device_i == -1 ) {
    /* Invalid device string. Close connection. */
    create_disconnect_pkt(out_pkt);
  }
  else {
    out_hdr->msg_type = SC_IO_MSG_DATA;
    struct bw_validation_message* resp = (struct bw_validation_message*)(out_hdr + 1);
    resp->type = BW_RESPONSE;
    resp->device_id = device_id;
    resp->uid = uid;
    resp->valid_region_start = (bw->devices[device_i].offset + bw->min_write_size) % bw->devices[device_i].size;
    resp->valid_region_end = bw->devices[device_i].complete_offset;
    resp->wrap_count = bw->devices[device_i].n_wraps;
    out_pkt->iov[0].iov_len = sizeof(*out_hdr) + sizeof(*resp);
  }
}


static void
sc_block_writer_reap_cb(struct sc_callback* cb, void* event_info)
{
  struct sc_block_writer* bw = cb->cb_private;
  sc_block_writer_reap(bw, 0);
  sc_timer_expire_after_ns(bw->reap_cb, REAP_PERIOD_NS);
}


static void
sc_block_writer_io_backlog_handler(struct sc_subnode_helper* sh)
{
  struct sc_block_writer* bw = sh->sh_private;
  struct sc_packet* pkt = sc_packet_list_pop_head(&sh->sh_backlog);
  SC_TEST(pkt->iovlen == 1);
  struct sc_io_msg_hdr* hdr = pkt->iov[0].iov_base;
  struct sc_session* tg = sc_thread_get_session(sc_node_get_thread(bw->node));
  SC_TEST(pkt->iov[0].iov_len >= sizeof(*hdr));
  if( hdr->msg_type == SC_IO_MSG_NEW_CONN ) {
    sc_trace(tg, "%s: New connection. connection id :%d\n", __func__, hdr->connection_id);
    sc_forward(sh->sh_node, sh->sh_free_link, pkt);
  }
  else if( hdr->msg_type == SC_IO_MSG_DATA ) {
    struct bw_validation_message* req;
    sc_trace(tg, "%s: Data: %.*s. connection_id: %d\n", __func__,
             (int)(pkt->iov[0].iov_len - sizeof(*hdr)),
             (char*)pkt->iov[0].iov_base + sizeof(*hdr), hdr->connection_id);
    if( pkt->iov[0].iov_len != sizeof(*hdr) + sizeof(*req) ) {
      sc_trace(tg, "%s: Bad request\n", __func__);
      create_disconnect_pkt(pkt);
    }
    else {
      req = (struct bw_validation_message*)(hdr + 1);
      if( req->type != BW_REQUEST )
        create_disconnect_pkt(pkt);
      else
        sc_block_writer_construct_valid_resp_msg(bw, hdr->connection_id,
                                                 req->device_id, req->uid, pkt);
    }
    sc_forward(sh->sh_node, sh->sh_links[0], pkt);
  }
  else {
    SC_TEST( hdr->msg_type == SC_IO_MSG_CLOSE );
    sc_forward(sh->sh_node, sh->sh_free_link, pkt);
  }
}


static int
init_io(struct sc_node* node, const struct sc_attr* attr)
{
  struct sc_block_writer* bw = node->nd_private;
  struct sc_node* index_io_node;

  struct sc_arg index_input_args[] = {
    SC_ARG_INT("with_pool", 1),
  };

  int rc = sc_node_alloc(&index_io_node, attr, sc_node_get_thread(node),
                         &sc_subnode_helper_sc_node_factory, index_input_args,
                         sizeof(index_input_args)/sizeof(index_input_args[0]));
  if( rc < 0 ) {
    sc_node_fwd_error(node, rc);
    return -1;
  }
  struct sc_subnode_helper* snh = sc_subnode_helper_from_node(index_io_node);
  snh->sh_private = bw;
  bw->index_io = snh;

  /* Set up session_closer node */
  struct sc_node* session_closer_io_node;
  struct sc_arg session_closer_io_args[] = {
    SC_ARG_INT("with_pool", 1),
  };
  struct sc_attr* session_closer_attr;
  SC_TRY(sc_attr_alloc(&session_closer_attr));
  session_closer_attr->buf_size =
    sizeof(struct sc_appliance_block_writer_session_close_msg);
  session_closer_attr->n_bufs_tx = bw->devices_n;
  rc = sc_node_alloc(&session_closer_io_node, session_closer_attr,
                     sc_node_get_thread(node),
                     &sc_subnode_helper_sc_node_factory,
                     session_closer_io_args,
                     sizeof(session_closer_io_args)/sizeof(session_closer_io_args[0]));
  if( rc < 0 ) {
    sc_node_fwd_error(node, rc);
    return -1;
  }
  snh = sc_subnode_helper_from_node(session_closer_io_node);
  snh->sh_private = bw;
  bw->session_closer_io = snh;
  sc_attr_free(session_closer_attr);

  /* Set up io_demux for valid requests */
  if( bw->valid_req_sock != NULL ) {
    struct sc_node* io_demux_node;
    struct sc_node* io_node;
    struct sc_arg io_demux_args[] = {
      SC_ARG_STR("listen", bw->valid_req_sock),
      SC_ARG_INT("reconnect", 0),
    };
    bw->max_io_message_size = ( attr->buf_size < 0 ) ?
      SC_DMA_PKT_BUF_LEN : attr->buf_size;

    if( sc_node_alloc(&io_demux_node, attr, sc_node_get_thread(node),
                      &sc_io_demux_sc_node_factory, io_demux_args,
                      sizeof(io_demux_args)/sizeof(io_demux_args[0])) < 0 ||
        sc_node_alloc(&io_node, attr, sc_node_get_thread(node),
                      &sc_subnode_helper_sc_node_factory, NULL, 0) < 0 ||
        sc_node_add_link(io_demux_node,  "", io_node, "") < 0 ||
        sc_node_add_link(io_node, "", io_demux_node,  "") < 0 )
      rc = -1;
    snh = sc_subnode_helper_from_node(io_node);
    snh->sh_private = bw;
    snh->sh_handle_backlog_fn = sc_block_writer_io_backlog_handler;

    if( rc < 0 ) {
      sc_node_fwd_error(node, rc);
      return -1;
    }
  }
  return 0;
}


static void
sc_block_writer_handle_pkt(struct sc_subnode_helper* sh)
{
  struct sc_block_writer* bw = sh->sh_private;
  sc_block_writer_do_backlog(bw, sh);
}


static int
sc_block_writer_prep(struct sc_node* node,
                     const struct sc_node_link*const* links,
                     int n_links)
{
  struct sc_block_writer* bw = node->nd_private;
  sc_timer_expire_after_ns(bw->reap_cb, 0);
  if( bw->log_file != NULL ) {
    sc_block_writer_log_header(bw);
    sc_timer_expire_after_ns(bw->log_cb, 0);
  }
  return 0;
}


static void
sc_block_writer_handle_eos(struct sc_subnode_helper* sh)
{
  struct sc_block_writer* bw = sh->sh_private;
  if( --bw->eos_waiting == 0 )
    sc_block_writer_try_propagate_end_of_stream(bw);
}


/* Creates a new subnode for each incoming link. This makes it simple to
 * free input packets once they've been packed as we don't need to work out
 * which pool to free them to. */
static struct sc_node*
sc_block_writer_select_subnode(struct sc_node* node, const char* name,
                               char** new_name_out)
{
  struct sc_block_writer* bw = node->nd_private;

  if( bw->output_added ) {
    sc_node_set_error(node, EINVAL, "%s: ERROR: All inputs to "
                      "sc_block_writer must be added before any outputs.\n",
                      __func__);
    return NULL;
  }

  struct sc_attr* attr;
  SC_TRY(sc_attr_alloc(&attr));

  struct sc_node* input_node;
  int rc = sc_node_alloc(&input_node, attr, sc_node_get_thread(node),
                         &sc_subnode_helper_sc_node_factory, NULL, 0);

  struct sc_subnode_helper* input = sc_subnode_helper_from_node(input_node);
  input->sh_private = bw;
  input->sh_handle_backlog_fn = sc_block_writer_handle_pkt;
  input->sh_handle_end_of_stream_fn = sc_block_writer_handle_eos;
  input->sh_poll_backlog_ns = 1000;

  sc_attr_free(attr);

  if( rc < 0 ) {
    sc_node_fwd_error(node, rc);
    return NULL;
  }

  bw->inputs = realloc(bw->inputs, sizeof(input) * (++bw->inputs_n));
  bw->inputs[bw->inputs_n - 1] = input;
  ++bw->eos_waiting;

  return input_node;
}


static int
sc_block_writer_add_link(struct sc_node* from_node, const char* link_name,
                         struct sc_node* to_node, const char* to_name_opt)
{
  struct sc_block_writer* bw = from_node->nd_private;
  int rc = 0;
  if( ! strcmp(link_name, "") ) {
    int i;
    bw->output_added = true;
    for( i = 0; i < bw->inputs_n; i++ ) {
      rc = sc_node_add_link(bw->inputs[i]->sh_node, link_name, to_node, to_name_opt);
      if( rc < 0 )
        break;
    }
  }
  else if( ! strcmp(link_name, "index") ) {
    bw->indexing = true;
    rc = sc_node_add_link(bw->index_io->sh_node, "", to_node, to_name_opt);
  }
  else if( ! strcmp(link_name, "session_close") ) {
    bw->session_closer_connected = true;
    rc = sc_node_add_link(bw->session_closer_io->sh_node, "",
                          to_node, to_name_opt);
  }
  else {
    return sc_node_set_error(from_node, EINVAL, "%s: ERROR: bad "
                             "link name '%s'\n", __func__, link_name);
  }
  if( rc < 0 )
    return sc_node_fwd_error(from_node, rc);
  return 0;
}


static int
get_mode_and_setup_function_pointers(struct sc_block_writer* bw)
{
  const char* disk_writer_mode;
  if( sc_node_init_get_arg_str(&disk_writer_mode, bw->node, "mode", "block") >= 0 ) {
    if( ! strcmp(disk_writer_mode, "block") ) {
      bw->emit_index = sc_block_writer_emit_block_index;
      return 0;
    }
    else if( ! strcmp(disk_writer_mode, "flow") ) {
      bw->emit_index = sc_block_writer_emit_flow_index;
      return 0;
    }
  }
  return sc_node_set_error(bw->node, EINVAL, "%s: ERROR: bad value for argument "
                           "flow_writer, can only be \'flow\' or \'block\'\n", __func__);
}


static int
process_device_string(struct sc_block_writer* bw, const char* device_string_in)
{
  char* dev_str = strdup(device_string_in);
  /* Parsing device list of the form:
   * path_1,id_1,initial_offset_1,size_1;path_2,initial_offset_2,size_2...
   *
   * Each device is used as a ring buffer, with the entire device from offset
   * 0-size in use, with the first write at initial_offset.
   */
  char* dev;
  char* dev_s_ptr = NULL;
  char* par_s_ptr = NULL;
  int rc = 0;

  dev = strtok_r(dev_str, ";", &dev_s_ptr);

  while( dev != NULL ) {
    char* dev_path = strtok_r(dev, ",", &par_s_ptr);
    char* dev_id = strtok_r(NULL, ",", &par_s_ptr);
    char* dev_init_offset = strtok_r(NULL, ",", &par_s_ptr);
    char* dev_size = strtok_r(NULL, ",", &par_s_ptr);

    if( dev_path == NULL || dev_id == NULL || dev_init_offset == NULL ||
        dev_size == NULL || strtok_r(NULL, ",", &par_s_ptr) != NULL ) {
      rc = sc_node_set_error(bw->node, EINVAL, "%s: ERROR: Invalid device: %s\n",
                             __func__, dev);
      goto exit;
    }

    char dummy;
    uint64_t start;
    uint64_t size;
    int32_t device_id;
    if( sscanf(dev_init_offset, "%"SCNd64"%c", &start, &dummy) != 1 ||
        sscanf(dev_size, "%"SCNd64"%c", &size, &dummy) != 1         ||
        sscanf(dev_id, "%"SCNd32"%c", &device_id, &dummy) != 1      ) {
      rc =  sc_node_set_error(bw->node, EINVAL, "%s: ERROR: Invalid device offset specified "
                               "(expected device,id,start_offset,size;...)\n", __func__);
      goto exit;
    }

    if( sc_block_writer_alloc_device(bw, dev_path, device_id, start, size) < 0 ) {
      rc = sc_node_set_error(bw->node, EINVAL, "%s: ERROR: Cannot open device: %s\n",
                             __func__, dev_path);
      goto exit;
    }

    dev = strtok_r(NULL, ";", &dev_s_ptr);
  }

exit:
  free(dev_str);
  return rc;
}


static int
get_unsigned_write_size(unsigned* write_size, struct sc_node* node,
                        const char* var_name)
{
  int tmp_write_size;
  if( sc_node_init_get_arg_int(&tmp_write_size, node, var_name, 0) != 0 ||
      tmp_write_size <= 0 || tmp_write_size % MEMORY_ALIGNMENT != 0 )
    return sc_node_set_error(node, EINVAL, "%s: ERROR: %s must be "
                                 "positive integer multiple of %d\n", __func__,
                                  var_name, MEMORY_ALIGNMENT);
  *write_size = tmp_write_size;
  return 0;
}


static void initialise_block_writer_stats(struct sc_block_writer* bw)
{
  sc_node_export_state(bw->node, "sc_block_writer_stats",
                       sizeof(struct sc_block_writer_stats), &bw->stats);
  bw->stats->block_count = 0;
  bw->stats->n_not_enough_ios = 0;
  bw->stats->n_ios = bw->n_ios;
  bw->stats->n_free_ios = bw->n_free_ios;
}


static int
sc_block_writer_init(struct sc_node* node, const struct sc_attr* attr,
                     const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    SC_TRY(sc_node_type_alloc(&nt, NULL, factory));
    nt->nt_add_link_fn = sc_block_writer_add_link;
    nt->nt_prep_fn     = sc_block_writer_prep;
    nt->nt_select_subnode_fn = sc_block_writer_select_subnode;
  }
  struct sc_thread* thread = sc_node_get_thread(node);
  node->nd_type = nt;
  sc_block_writer_stats_declare(sc_thread_get_session(thread));

  struct sc_block_writer* bw;
  bw = sc_thread_calloc(thread, sizeof(*bw));
  bw->node = node;
  node->nd_private = bw;

  int rc;
  if( (rc = get_unsigned_write_size(&bw->max_write_size, node, "max_write_size")) != 0 )
    return rc;


  if( (rc = get_unsigned_write_size(&bw->min_write_size, node, "min_write_size")) != 0 )
    return rc;


  const char* s;
  if( sc_node_init_get_arg_str(&s, node, "valid_req_sock", NULL) < 0 )
    return -1;

  bw->valid_req_sock = (s != NULL) ? strdup(s) : NULL;

  if( sc_node_init_get_arg_str(&s, node, "log_file", NULL) < 0 )
    return -1;
  if( s != NULL ) {
    bw->log_file = fopen(s, "w");
    if( bw->log_file == NULL )
      return sc_node_set_error(node, errno, "%s: ERROR: could not open log  "
                               "file\n", __func__);
  }
  int log_ms;
  if( sc_node_init_get_arg_int(&log_ms, node, "log_period_ms",
                               LOG_PERIOD_DEFAULT_MS) < 0 )
    return -1;
  bw->log_ns = log_ms * 1000000ULL;

  int n_ios;
  if( sc_node_init_get_arg_int(&n_ios, node, "n_io_descriptors", DEFAULT_N_IOS) < 0 )
    return -1;

  if( n_ios < 1 )
    return sc_node_set_error(node, EINVAL, "%s: ERROR: n_io_descriptors must be > 0\n",
                             __func__);
  bw->n_ios = n_ios;


  if( sc_node_init_get_arg_str(&s, node, "devices", NULL) != 0 )
    return sc_node_set_error(node, EINVAL, "%s: ERROR: devices must be  "
                             "specified\n", __func__);

  if( (rc = process_device_string(bw, s)) != 0 )
    return rc;

  if( init_io(node, attr) < 0 )
    return -1;

  if( get_mode_and_setup_function_pointers(bw) != 0 )
    return rc;

  if( (rc = io_setup(bw->n_ios, &bw->io_ctx)) != 0 )
    return sc_node_set_error(node, errno, "%s: ERROR: io_setup failed rc=%d\n",
                             __func__, rc);


  /* Redundantly initialise this pointer to prevent a compiler warning
   * on gcc 4.9.2.
   * (The init is redundant because posix_memalign will initialise it
   * or SC_TRY will abort). */
  void* async_ios = 0;
  int i;
  sc_dlist_init(&bw->submitted_async_ios);
  sc_dlist_init(&bw->free_async_ios);
  posix_memalign(&async_ios, MEMORY_ALIGNMENT,
                 sizeof(struct sc_async_io) * bw->n_ios);
  for( i = 0; i < bw->n_ios; i++) {
    struct sc_dlist* link = &((struct sc_async_io*)
                              ((char*)async_ios +
                               sizeof(struct sc_async_io)*i))->link;
    sc_dlist_init(link);
    sc_dlist_push_head(&bw->free_async_ios, link);
    ++bw->n_free_ios;
  }

  initialise_block_writer_stats(bw);

  SC_TRY(sc_callback_alloc(&bw->reap_cb, attr,
                           sc_node_get_thread(node)));
  bw->reap_cb->cb_private = bw;
  bw->reap_cb->cb_handler_fn = sc_block_writer_reap_cb;

  if( bw->log_file != NULL ) {
    SC_TRY(sc_callback_alloc(&bw->log_cb, attr,
                             sc_node_get_thread(node)));
    bw->log_cb->cb_private = bw;
    bw->log_cb->cb_handler_fn = sc_block_writer_log_cb;
  }

  return 0;
}


const struct sc_node_factory sc_block_writer_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_block_writer",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_block_writer_init,
};

/** \endcond NODOC */
