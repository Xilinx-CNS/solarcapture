/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \node{sc_shm_import}
 *
 * \brief Import packets or messages from a shared memory channel.
 *
 * \nodedetails
 * This node is used in conjunction with \noderef{sc_shm_broadcast} or
 * \noderef{sc_shm_export} to form a unidirectional shared memory channel
 * between two SolarCapture sessions.  \noderef{sc_shm_import} is the
 * receiving end of the channel.  Packets pushed into the channel are
 * emitted by this node on its output.
 *
 * \nodeargs
 * Argument                | Optional? | Default | Type           | Description
 * ----------------------- | --------- | ------- | -------------- | -------------------------------------------------------------------------------
 * path                    | No        |         | ::SC_PARAM_STR | Location in the filesystem for the control socket.
 * reliable                | Yes       | 0       | ::SC_PARAM_INT | Set to 1 to request a reliable connection (which may cause head-of-line blocking).
 * active_connect          | Yes       | 1       | ::SC_PARAM_INT | If set to 0 then a listening socket is created at the path provided, and the remote side should do an active open.
 * \internal
 * poll_batch              | Yes       | 8       | ::SC_PARAM_INT | The maximum number of packets to import in one batch.
 * broadcast_count_drops   | Yes       | 1       | ::SC_PARAM_INT | Should the shared memory interface count packet losses for this client in the sc_shm_broadcast statistics
 * report_drops            | Yes       | 0       | ::SC_PARAM_INT | If set, forwarded packets have their metadata field points to a (struct sc_import_metadata).
 * emit_tail_drops         | Yes       | 0       | ::SC_PARAM_INT | If set, empty packets with drop metadata are emitted on tail drops. If this is not set, the drops are reported with the next received packet. Note that this only has any effect when report_drops is set.
 * \endinternal
 *
 * \namedinputlinks
 * Packets arriving on an input link named "foo" are forwarded to an output
 * link named "foo" on the other side of the shared memory channel.  Note
 * that these named channels do not support high performance.
 *
 * \nodestatscopy{sc_shm}
 *
 * \cond NODOC
 */

#define _GNU_SOURCE
#include <limits.h>
#include <asm/mman.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <../core/internal.h>
#include <sc_internal.h>
#include <sc_internal/builtin_nodes.h>
#include <sc_internal/shm_endpoint.h>
#include <sc_internal/io.h>
#include <sc_internal/packed_stream.h>
#include <solar_capture/nodes/subnode_helper.h>
#include <solar_capture/nodes/shm_import.h>

#define SC_TYPE_TEMPLATE <sc_shm_types_tmpl.h>
#define SC_DECLARE_TYPES sc_shm_stats_declare
#include <solar_capture/declare_types.h>

#define CONNECTION_ID_ROLLOVER 60000
#define MAX_CTL_MSG_LEN 1536

#define WAIT_FOR_DISCONNECT_POLL_NS 1000000ULL
#define DEFAULT_MAX_PACKETS 20480
static const struct sc_node_factory sc_shm_return_sc_node_factory;


enum packet_type_state {
  PKT_TYPE_UNKNOWN,
  PKT_TYPE_NORMAL,
  PKT_TYPE_PACKED_STREAM
};


enum connection_state {
  CONN_CONNECTED,
  CONN_DISCONNECTED,
  CONN_WAITING_FOR_DISCONNECT
};


/* We need a special refill node because when packets that have been sourced from
 * shared memory are freed, we need to send a message back to the producer.
 */
struct sc_shm_return_node {
  struct sc_node*                        node;
  struct sc_pkt_pool*                    import_pp;
  struct sc_shm_import_endpoint_state*   shm_state;
};


/* State for shm import connection */
struct sc_shm_import_endpoint_state {
  char*                   sis_buffer_path;
  char*                   sis_endpoint_path;
  void*                   sis_buffer_base;
  uint64_t                sis_buffer_size;
  uint64_t                sis_n_pkts_in_flight;
  struct sc_shm_import_state* sis_sin;
  struct sc_shm_endpoint* sis_shm_endpoint;
  struct sc_pkt_pool*     sis_pkt_pool;
  struct sc_node*         sis_return_node;
  struct sc_packet_list   sis_stream_list;
  enum packet_type_state  sis_packet_type;
  enum connection_state   sis_connection_state;
  int                     sis_endpoint_id;
  int                     sis_buffer_fd;
  int                     sis_endpoint_fd;
  int                     sis_current_connection;
};

/* sc_shm_import node state */
struct sc_shm_import_state {
  struct sc_node*                        node;
  struct sc_node*                        io_demux;
  const struct sc_node_link*             next_hop;
  struct sc_callback*                    callback;
  struct sc_callback*                    wake_msg_cb;
  struct sc_shm_import_endpoint_state*   shm_state;
  char*                                  sock;
  struct sc_packet_list                  unpack_backlog;
  struct sc_node*                        undo_node;
  struct sc_node*                        io_node;
  uint64_t                               drops_to_notify;
  uint64_t                               last_wake_seq;
  int                                    poll_batch;
  int                                    offset;
  int                                    io_connection_id;
  int                                    max_io_message_size;
  int                                    reliable;
  int                                    broadcast_count_drops;
  int                                    pool_size;
  bool                                   unpack;
  bool                                   mode_connect;
  bool                                   report_drops;
  bool                                   emit_tail_drops;
  bool                                   ready_to_sleep;
  struct sc_shm_stats*                   stats;
};


/* Inflight packets need metadata attached to them. This is required when
 * freeing packets.
 */
struct sc_shm_packet_metadata {
  uintptr_t packet_id;
  int       connection_id;
};



/*******************************************************************************
 * HELPER FUNCTIONS
 ******************************************************************************/

#define SC_PACKET_OFFSET_PTR(pkt, offset)                       \
  ((void*) ((uint8_t*) (pkt)->iov[0].iov_base + offset))


static struct sc_shm_import_endpoint_state*
sc_shm_import_alloc(struct sc_node* node, int pool_size, int buf_size)
{
  struct sc_thread* thread = sc_node_get_thread(node);
  struct sc_shm_import_state* sin = node->nd_private;
  SC_TEST(thread != NULL);
  struct sc_shm_import_endpoint_state* st =
    calloc(1, sizeof(struct sc_shm_import_endpoint_state));
  SC_TEST(st != NULL);

  struct sc_attr* pool_attr;
  SC_TEST(sc_attr_alloc(&pool_attr) == 0);
  SC_TRY(sc_attr_set_int(pool_attr, "buf_inline", 1));
  SC_TRY(sc_attr_set_int(pool_attr, "private_pool", 1));
  SC_TRY(sc_attr_set_str(pool_attr, "name", "sc_shm_import.sis_pkt_pool"));
  /* Need to allocate buffer to store packet metadata, which we will need when
   * freeing the packet.
   */
  SC_TRY(sc_attr_set_int(pool_attr, "buf_size", buf_size));
  SC_TRY(sc_attr_set_int(pool_attr, "n_bufs_tx", pool_size));

  sc_pkt_pool_alloc(&st->sis_pkt_pool, pool_attr, thread);
  sc_pkt_pool_request_bufs(st->sis_pkt_pool, pool_attr);

  sc_attr_free(pool_attr);

  struct sc_attr* return_attr;
  SC_TEST(sc_attr_alloc(&return_attr) == 0);
  struct sc_object* pkt_pool_ptr;
  sc_opaque_alloc(&pkt_pool_ptr, st->sis_pkt_pool);
  struct sc_object* shm_ptr;
  sc_opaque_alloc(&shm_ptr, st);

  struct sc_arg return_args[] = {
    SC_ARG_OBJ("pp_ptr", pkt_pool_ptr),
    SC_ARG_OBJ("shm_ptr", shm_ptr),
  };

  sc_attr_set_from_fmt(return_attr, "name", "%s.return", node->nd_name);
  TRY(sc_node_alloc(&st->sis_return_node, return_attr, thread,
                    &sc_shm_return_sc_node_factory, return_args,
                    sizeof(return_args) / sizeof(return_args[0])));

  sc_opaque_free(pkt_pool_ptr);
  sc_opaque_free(shm_ptr);
  sc_attr_free(return_attr);

  st->sis_endpoint_id = -1;
  st->sis_connection_state = CONN_DISCONNECTED;
  st->sis_sin = sin;

  return st;
}


static int sc_shm_import_connect(struct sc_shm_import_endpoint_state* st)
{
  int rc;
  SC_TEST(st != NULL);
  SC_TEST(st->sis_buffer_path != NULL);
  SC_TEST(st->sis_endpoint_path != NULL);

  st->sis_buffer_fd = open(st->sis_buffer_path, O_RDONLY);
  if( st->sis_buffer_fd < 0 ) {
    rc = -errno;
    goto out1;
  }

  struct stat sb;
  fstat(st->sis_buffer_fd, &sb);
  st->sis_buffer_size = sb.st_size;
  st->sis_buffer_base = mmap(NULL, st->sis_buffer_size, PROT_READ , MAP_SHARED,
                             st->sis_buffer_fd, 0);
  if( st->sis_buffer_base == MAP_FAILED ) {
    rc = -errno;
    goto out2;
  }
  st->sis_shm_endpoint =  sc_shm_endpoint_attach(st->sis_endpoint_path);
  if( st->sis_shm_endpoint == NULL ) {
    rc = -errno;
    goto out3;
  }

  sc_packet_list_init(&st->sis_stream_list);

  return 0;

 out3:
  munmap(st->sis_buffer_base, sb.st_size);
 out2:
  close(st->sis_buffer_fd);
 out1:
  return rc;
}


static int sc_shm_import_try_disconnect(struct sc_shm_import_endpoint_state* st)
{
  if( st->sis_n_pkts_in_flight > 0 )
    return -1;
  munmap(st->sis_buffer_base, st->sis_buffer_size);
  sc_shm_endpoint_detach(st->sis_shm_endpoint);
  close(st->sis_buffer_fd);
  st->sis_endpoint_id = -1;
  st->sis_connection_state = CONN_DISCONNECTED;
  return 0;
}


static int sc_shm_import_free_packet(struct sc_shm_import_endpoint_state* st,
                                     struct sc_packet* packet)
{
  struct sc_shm_message sm;
  struct sc_shm_packet_metadata* metadata = SC_PKT_FROM_PACKET(packet)->sp_buf;

  /* We drain all outstanding packets before making the import available again,
   * so it is not possible to get a packet with the wrong connection id here.
   */
  assert(metadata->connection_id == st->sis_current_connection);
  sm.ssm_message_type = SSM_TYPE_FREE_PACKET;
  sm.ssm_message.usm_free_packet.usm_packet_id =
    metadata->packet_id;
  if( st->sis_connection_state != CONN_CONNECTED  ||
      sc_shm_endpoint_msg_send(st->sis_shm_endpoint, &sm) == 0 ) {
    --st->sis_n_pkts_in_flight;
    return 0;
  }
  else {
    return -1;
  }
}


/* This assumes that all packets received are in packed stream
 * format and tags them accordingly.
 *
 * Returns true if there can be pending activity in the ring. This can be
 * either because we are unable to poll, or we polled and found messages.
 * Returns false if ring was checked and no buffers were found.
 */
static bool sc_shm_import_poll(struct sc_shm_import_state* sin,
                               int poll_batch)
{
  struct sc_shm_import_endpoint_state* st = sin->shm_state;
  bool ring_checked = false;
  bool msg_found = false;
  unsigned n = 0;
  while( (st->sis_pkt_pool->pp_n_bufs > 0) &&
         n++ < poll_batch ) {
    struct sc_shm_message sm;
    ring_checked = true;
    if( sc_shm_endpoint_msg_get(st->sis_shm_endpoint, &sm) != 0 )
      break;
    msg_found = true;
    switch (sm.ssm_message_type) {
    case SSM_TYPE_STREAM_PACKET:
      {
      struct sc_pkt* pkt = sc_pkt_pool_get(st->sis_pkt_pool);
      ++st->sis_n_pkts_in_flight;
      enum sc_shm_packet_type pkt_type =
        sm.ssm_message.usm_stream_packet.usm_packet_type;
      pkt->sp_usr.iovlen = 1;
      if( st->sis_packet_type == PKT_TYPE_UNKNOWN ) {
        if( pkt_type == SSM_PKT_TYPE_PACKED_STREAM ) {
          st->sis_packet_type = PKT_TYPE_PACKED_STREAM;
        }
        else if ( pkt_type == SSM_PKT_TYPE_NORMAL )
          {
            st->sis_packet_type = PKT_TYPE_NORMAL;
            sin->unpack = false;
          }
      }
      /* Not allowed to mix packet types on a channel. */
      assert(((st->sis_packet_type == PKT_TYPE_PACKED_STREAM) &&
              (pkt_type == SSM_PKT_TYPE_PACKED_STREAM)) ||
             ((st->sis_packet_type == PKT_TYPE_NORMAL) &&
              (pkt_type == SSM_PKT_TYPE_NORMAL)));
      pkt->sp_usr.flags =
        ( pkt_type == SSM_PKT_TYPE_PACKED_STREAM ) ? SC_PACKED_STREAM : 0;
      pkt->sp_usr.iov[0].iov_base = (void*)
        ((uintptr_t)st->sis_buffer_base +
         sm.ssm_message.usm_stream_packet.usm_buffer_offset);
      pkt->sp_usr.iov[0].iov_len =
        sm.ssm_message.usm_stream_packet.usm_buffer_len;
      pkt->sp_usr.frame_len = ( pkt->sp_usr.iov[0].iov_len > SC_FRAME_LEN_LARGE ) ?
        SC_FRAME_LEN_LARGE : pkt->sp_usr.iov[0].iov_len;
      pkt->sp_usr.ts_sec =  sm.ssm_message.usm_stream_packet.usm_ts_sec;
      pkt->sp_usr.ts_nsec =  sm.ssm_message.usm_stream_packet.usm_ts_nsec;
      pkt->sp_usr.frags = &pkt->sp_usr;
      pkt->sp_usr.frags_tail = &pkt->sp_usr.next;
      pkt->sp_usr.frags_n = 1;
      pkt->sp_ref_count = 1;
      struct sc_shm_packet_metadata* metadata = pkt->sp_buf;
      metadata->packet_id =
        (uintptr_t)sm.ssm_message.usm_stream_packet.usm_packet_id;
      metadata->connection_id = st->sis_current_connection;
      if( sin->report_drops ) {
        struct sc_shm_import_metadata* dr_metadata = (void*)(metadata + 1);
        pkt->sp_usr.metadata = (void*)dr_metadata;
        dr_metadata->drop_count = sm.ssm_message.usm_stream_packet.usm_drop_count +
          sin->drops_to_notify;
        sin->drops_to_notify = 0;
      }
      sin->stats->pkts_dropped += sm.ssm_message.usm_stream_packet.usm_drop_count;
      sc_packet_list_append(&st->sis_stream_list, &pkt->sp_usr);
      break;
      }
    case SSM_TYPE_DROP_NOTIFICATION:
      sin->stats->pkts_dropped += sm.ssm_message.usm_drop_notification.usm_drop_count;
      if( sin->report_drops && sin->emit_tail_drops ) {
        struct sc_pkt* pkt = sc_pkt_pool_get(st->sis_pkt_pool);
        pkt->sp_usr.iovlen = 0;
        pkt->sp_usr.frame_len = 0;
        pkt->sp_usr.frags = &pkt->sp_usr;
        pkt->sp_usr.frags_tail = &pkt->sp_usr.next;
        pkt->sp_usr.frags_n = 1;
        pkt->sp_ref_count = 1;
        struct sc_shm_packet_metadata* metadata = pkt->sp_buf;
        metadata->packet_id = 0;
        /* Setting connection id to -1 stops the refill node from attempting to
           send a free message. */
        metadata->connection_id = -1;
        struct sc_shm_import_metadata* dr_metadata = (void*)(metadata + 1);
        pkt->sp_usr.metadata = (void*)dr_metadata;
        dr_metadata->drop_count = sm.ssm_message.usm_drop_notification.usm_drop_count;
        sc_packet_list_append(&st->sis_stream_list, &pkt->sp_usr);
      }
      else {
        sin->drops_to_notify += sm.ssm_message.usm_drop_notification.usm_drop_count;
      }
      break;
    default:
      SC_TEST(0);
    }
  }

  return !ring_checked || msg_found;
}


static inline void sc_shm_import_unpack_one(struct sc_shm_import_state* sin,
                                            struct sc_pkt* ps_buf,
                                            struct sc_packed_packet* psp)
{
  assert(sin->unpack);
  assert(sin->shm_state->sis_pkt_pool->pp_n_bufs > 0);
  assert(ps_buf->sp_usr.flags & SC_PACKED_STREAM);
  struct sc_pkt* out_pkt = sc_pkt_pool_get(sin->shm_state->sis_pkt_pool);
  assert(out_pkt != NULL);
  out_pkt->sp_usr.frags = &ps_buf->sp_usr;
  out_pkt->sp_usr.frags_tail = &ps_buf->sp_usr.next;
  out_pkt->sp_usr.frags_n++;
  out_pkt->sp_usr.flags = 0;
  out_pkt->sp_ref_count = 1;  /* needed to suppress debug checks */
  out_pkt->sp_usr.ts_sec = psp->ps_ts_sec;
  out_pkt->sp_usr.ts_nsec = psp->ps_ts_nsec;
  out_pkt->sp_usr.frame_len = psp->ps_orig_len;
  out_pkt->sp_usr.iov[0].iov_len = psp->ps_cap_len;
  out_pkt->sp_usr.iov[0].iov_base = sc_packed_packet_payload(psp);
  out_pkt->sp_usr.iovlen = 1;
  struct sc_shm_packet_metadata* metadata = out_pkt->sp_buf;
  metadata->packet_id = 0;
  metadata->connection_id = -1;
  ++(ps_buf->sp_ref_count);
  sc_forward(sin->node, sin->next_hop, &out_pkt->sp_usr);
}


static bool sc_shm_import_unpack_buffer(struct sc_shm_import_state* sin,
                                        struct sc_packet* ps_buf)
{
  struct sc_packed_packet* ps_pkt = SC_PACKET_OFFSET_PTR(ps_buf, sin->offset);
  struct sc_packed_packet* ps_end = sc_packet_packed_end(ps_buf);
  struct sc_packed_packet* next_pkt;
  while( ps_pkt < ps_end ) {
    if( sc_pkt_pool_is_empty(sin->shm_state->sis_pkt_pool) )
      return false;
    sc_shm_import_unpack_one(sin, SC_PKT_FROM_PACKET(ps_buf), ps_pkt);
    /* FIXME - This needs to be cleaned up when sc_ps_to_ps_packer uses
     * next_offset properly (task 48308)
     */
    next_pkt = sc_packed_packet_next(ps_pkt);
    if( next_pkt == ps_pkt )
      break;
    else
      ps_pkt = next_pkt;
    sin->offset = (uintptr_t) ps_pkt -
      (uintptr_t) sc_packet_packed_first(ps_buf);
  }
  return true;
}


static void sc_shm_import_unpack_backlog(struct sc_shm_import_state* sin)
{
  while( !sc_packet_list_is_empty(&sin->unpack_backlog) &&
         sc_shm_import_unpack_buffer(sin, sin->unpack_backlog.head) ) {
    struct sc_pkt* pkt =
      SC_PKT_FROM_PACKET(sc_packet_list_pop_head(&sin->unpack_backlog));
    --(pkt->sp_ref_count);
    if( pkt->sp_ref_count == 0 )
      sc_pkt_pool_put(sin->shm_state->sis_pkt_pool, pkt);
    sin->offset = 0;
  }
}


static void sc_shm_import_emit_stream_list(struct sc_shm_import_state* sin)
{
  struct sc_packet_list out_list;
  struct sc_shm_import_endpoint_state* st = sin->shm_state;
  unsigned n_appended = 0;
  sc_packet_list_init(&out_list);
  while( n_appended++ < sin->poll_batch &&
         !sc_packet_list_is_empty(&st->sis_stream_list) )
    sc_packet_list_append(&out_list,
                          sc_packet_list_pop_head(&st->sis_stream_list));

  if( !sc_packet_list_is_empty(&out_list) ) {
    if( sin->unpack )
      sc_packet_list_append_list(&sin->unpack_backlog, &out_list);
    else
      sc_forward_list(sin->node, sin->next_hop, &out_list);
  }
}


static void sc_shm_import_poll_callback(struct sc_callback* cb, void* event_info)
{
  struct sc_shm_import_state* sin = cb->cb_private;
  struct sc_shm_import_endpoint_state* st = sin->shm_state;
  /* If ring is non-empty, polling again. Otherwise, marking ourselves ready to
   * sleep.
   */
  if( sin->shm_state->sis_connection_state == CONN_CONNECTED ) {
    unsigned max_poll = sin->poll_batch;
    if( sin->unpack ) {
      /* Since we unpack using the import pool, we must not let the entire pool
       * sit in the unpack backlog. Limiting the unpack backlog to half the
       * size of the pool.
       *
       * TODO: To deal with this in a less hacky manner, unpacking should be
       * done from a different pool.
       */
      unsigned backlog_max = st->sis_pkt_pool->pp_stats->allocated_bufs / 2;
      assert(backlog_max >= sin->unpack_backlog.num_pkts);
      if( sin->unpack_backlog.num_pkts + max_poll > backlog_max )
        max_poll = backlog_max - sin->unpack_backlog.num_pkts;
    }
    bool activity_pending = sc_shm_import_poll(sin, max_poll);
    sc_shm_import_emit_stream_list(sin);
    if( activity_pending || ! sc_packet_list_is_empty(&st->sis_stream_list) ) {
      sc_timer_expire_after_ns(sin->callback, 1);
      sin->ready_to_sleep = false;
    }
    else {
      struct sc_shm_endpoint* ep = sin->shm_state->sis_shm_endpoint;
      if( ! sin->ready_to_sleep ) {
        sc_shm_endpoint_notify_sleep(ep);
        sc_timer_expire_after_ns(sin->callback, 1);
        ++sin->stats->sleep_notifies;
        sin->ready_to_sleep = true;
      }
    }
  }

  if( sin->unpack )
    sc_shm_import_unpack_backlog(sin);
}


static int sc_shm_import_prep(struct sc_node* node,
                              const struct sc_node_link*const* links,
                              int n_links)
{
  struct sc_shm_import_state* sin = node->nd_private;

  sin->next_hop = sc_node_prep_get_link_or_free(node, "");
  struct sc_node_link_impl* nl = SC_NODE_LINK_IMPL_FROM_NODE_LINK(sin->next_hop);

  sc_bitmask_set(&nl->nl_pools, sin->shm_state->sis_pkt_pool->pp_id);

  return 0;
}


static int sc_shm_try_return_pkt(struct sc_shm_return_node* srn, struct sc_pkt* pkt)
{
  assert( pkt->sp_pkt_pool_id == srn->import_pp->pp_id );
  assert( pkt->sp_usr.frags != NULL );
  assert( pkt->sp_usr.frags_n == 1 );
  assert( pkt->sp_usr.frags_tail == &(pkt->sp_usr.frags->next) );
  struct sc_pkt* wrapped = SC_PKT_FROM_PACKET(pkt->sp_usr.frags);
  struct sc_pkt_pool* pp = srn->import_pp;
  assert( wrapped->sp_pkt_pool_id == srn->import_pp->pp_id );
  assert( wrapped->sp_ref_count > 0 );
  --wrapped->sp_ref_count;
  if( wrapped != pkt ) {
    /* Current packet is not an outer packet. We can return it to the pool
     * immediately.
     */
    pkt->sp_ref_count = 0;
    pkt->sp_usr.frags = NULL;
    pkt->sp_usr.frags_n = 0;
    pkt->sp_usr.frags_tail = &(pkt->sp_usr.frags);
    sc_pkt_pool_put(pp, pkt);
  }
  if( wrapped->sp_ref_count == 0 ) {
    /* connection_id == -1 implies a tail-drop notification, for which
     * there is no SHM data to free. */
    if( ((struct sc_shm_packet_metadata*)(wrapped->sp_buf))->connection_id == -1 ||
        sc_shm_import_free_packet(srn->shm_state, &wrapped->sp_usr) == 0 ) {
      wrapped->sp_ref_count = 0;
      wrapped->sp_usr.frags = NULL;
      wrapped->sp_usr.frags_n = 0;
      wrapped->sp_usr.frags_tail = &(wrapped->sp_usr.frags);
      sc_pkt_pool_put(pp, wrapped);
    }
    else {
      ++wrapped->sp_ref_count;
      sc_packet_list_push_head(&pp->pp_put_backlog, &wrapped->sp_usr);
      return -1;
    }
  }
  return 0;
}


static void
sc_shm_import_construct_wake_msg(struct sc_shm_import_state* sin,
                                 int connection_id,
                                 struct sc_packet* out_pkt)
{
  struct sc_io_msg_hdr* out_hdr = out_pkt->iov[0].iov_base;
  out_hdr->connection_id = connection_id;
  out_hdr->msg_type = SC_IO_MSG_DATA;
  struct sc_shm_io_message* out_msg = (void*)(out_hdr + 1);
  out_msg->ssio_type = SSIO_TYPE_WAKE;
  out_pkt->iov[0].iov_len = sizeof(*out_hdr) + sizeof(*out_msg);
}


static void sc_shm_import_try_send_wake(struct sc_shm_import_state* sin)
{
  if( sin->shm_state->sis_connection_state != CONN_CONNECTED )
    return;
  struct sc_shm_endpoint* ep = sin->shm_state->sis_shm_endpoint;
  uint64_t remote_sleep_seq =
    sc_shm_endpoint_get_remote_sleep_seq(ep);
  uint64_t msgs_sent =
    sc_shm_endpoint_get_n_sent(ep);
  if( ! (remote_sleep_seq == msgs_sent ||
         sin->last_wake_seq > remote_sleep_seq) ) {
    struct sc_subnode_helper* sh = sc_subnode_helper_from_node(sin->io_node);
    struct sc_packet_list pl;
    __sc_packet_list_init(&pl);
    if( sc_pool_get_packets(&pl, sh->sh_pool, 1, 1) != 1 ) {
      sc_pool_on_threshold(sh->sh_pool, sin->wake_msg_cb, 1);
      return;
    }
    struct sc_packet* pkt = pl.head;
    sc_shm_import_construct_wake_msg(sin, sin->io_connection_id, pkt);
    sin->last_wake_seq = msgs_sent;
    ++sin->stats->wake_msgs;
    sc_forward(sh->sh_node, sh->sh_links[0], pkt);
  }
}


static void sc_shm_import_wake_msg_cb(struct sc_callback* cb, void* event_info)
{
  struct sc_shm_import_state* sin = cb->cb_private;
  sc_shm_import_try_send_wake(sin);
}


static void sc_shm_return_batch(struct sc_callback* cb, void* event_info)
{
  struct sc_shm_return_node* srn = cb->cb_private;
  struct sc_shm_import_endpoint_state* st = srn->shm_state;
  struct sc_pkt_pool* pp = srn->import_pp;
  bool returned = false;
  assert( ! sc_packet_list_is_empty(&(pp->pp_put_backlog)) );
  assert( *(pp->pp_put_backlog.tail) == NULL );

  while( ! sc_packet_list_is_empty(&(pp->pp_put_backlog)) &&
         (sc_shm_try_return_pkt(srn,
                                SC_PKT_FROM_PACKET(sc_packet_list_pop_head(&pp->pp_put_backlog))) == 0 )) {
    returned = true;
  }

  if( returned ) {
    sc_pkt_pool_post_refill(pp);
    sc_shm_import_try_send_wake(st->sis_sin);
    if( st->sis_connection_state == CONN_WAITING_FOR_DISCONNECT )
      sc_shm_import_try_disconnect(st);
  }

  if( ! sc_packet_list_is_empty(&(pp->pp_put_backlog)) )
    sc_timer_expire_after_ns(pp->pp_cb_backlog, 1);
}


static inline void sc_shm_return_pkts(struct sc_node* node,
                                      struct sc_packet_list* pl)
{
  struct sc_shm_return_node* srn = node->nd_private;
  struct sc_pkt_pool* pp = srn->import_pp;
  sc_packet_list_append_list(&(pp->pp_put_backlog), pl);
  sc_timer_expire_after_ns(pp->pp_cb_backlog, 1);
}


const struct sc_node_type sc_shm_return_node_type = {
  .nt_name    = "sc_shm_return",
  .nt_prep_fn = NULL,
  .nt_pkts_fn = sc_shm_return_pkts,
};


static void* sc_shm_return_get_opaque_ptr(struct sc_node* node,
                                      const char* name)
{
  struct sc_object* obj = NULL;
  if( sc_node_init_get_arg_obj(&obj, node, name, SC_OBJ_OPAQUE) < 0 )
    return NULL;
  if( obj == NULL ) {
    sc_node_set_error(node, EINVAL,
                      "%s: ERROR: required arg '%s' missing\n", __func__, name);
    return NULL;
  }
  return sc_opaque_get_ptr(obj);
}


static int sc_shm_return_init(struct sc_node* node, const struct sc_attr* attr,
                              const struct sc_node_factory* factory)
{
  node->nd_type = &sc_shm_return_node_type;

  struct sc_shm_return_node* srn = calloc(1, sizeof(*srn));
  node->nd_private = srn;
  SC_NODE_IMPL_FROM_NODE(node)->ni_stats->is_free_path = 1;

  srn->import_pp = sc_shm_return_get_opaque_ptr(node, "pp_ptr");
  if( srn->import_pp == NULL )
    return -1;

  srn->shm_state = sc_shm_return_get_opaque_ptr(node, "shm_ptr");
  if( srn->shm_state == NULL )
    return -1;

  struct sc_callback* cb = srn->import_pp->pp_cb_backlog;
  cb->cb_private = srn;
  cb->cb_handler_fn = sc_shm_return_batch;

  sc_pool_set_refill_node(&(srn->import_pp->pp_public), node);
  return 0;
}


static const struct sc_node_factory sc_shm_return_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_shm_return",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_shm_return_init,
};


static void
sc_shm_import_construct_close_msg(int connection_id,
                                  struct sc_packet* out_pkt)
{
  struct sc_io_msg_hdr* out_hdr = out_pkt->iov[0].iov_base;
  out_hdr->connection_id = connection_id;
  out_hdr->msg_type = SC_IO_MSG_CLOSE;
  out_pkt->iov[0].iov_len = sizeof(*out_hdr);
}


/* Returns true if pkt is to be freed, false if it is to be forwarded to
 * io_demux
 */
static bool
sc_shm_import_handle_ssio_msg(struct sc_shm_import_state* sin,
                              struct sc_shm_io_message* in_msg,
                              struct sc_packet* pkt, int connection_id)
{
  struct sc_session* tg = sc_thread_get_session(sc_node_get_thread(sin->node));
  switch( in_msg->ssio_type ) {
  case SSIO_TYPE_CONN_RESP:
    {
      sc_trace(tg, "%s: Connection resp from fd=%d\n", __func__, connection_id);
      /* Ignoring if already connected. */
      if( sin->shm_state->sis_endpoint_id != -1 ) {
        sc_warn(tg, "%s: Ignoring connection response - already connected. "
                "connection_id: %d\n", __func__, connection_id);
        return true;
      }
      if( in_msg->ssio_data.ssio_conn_resp.ssio_endpoint_id < 0 ) {
        sc_err(tg, "sc_shm_import: ERROR: Failed to connect (max channels "
               "already connected)\n");
        exit(1);  /* TODO: option to not exit */
      }
      sin->shm_state->sis_buffer_path =
        strdup(in_msg->ssio_data.ssio_conn_resp.ssio_buffer_shm_path);
      sin->shm_state->sis_endpoint_path =
        strdup(in_msg->ssio_data.ssio_conn_resp.ssio_ringbuf_shm_path);
      sin->shm_state->sis_endpoint_id =
        in_msg->ssio_data.ssio_conn_resp.ssio_endpoint_id;
      int rc;
      if( (rc = sc_shm_import_connect(sin->shm_state)) != 0 ) {
        sc_err(tg, "sc_shm_import: ERROR: Failed to connect (%d, %s)\n",
               -rc, strerror(-rc));
        exit(1);  /* TODO: option to not exit */
      }
      sin->shm_state->sis_current_connection =
        (sin->shm_state->sis_current_connection + 1) % CONNECTION_ID_ROLLOVER;
      sin->io_connection_id = connection_id;
      sc_timer_expire_after_ns(sin->callback, 1);
      sin->shm_state->sis_connection_state = CONN_CONNECTED;
      return true;
    }
  case SSIO_TYPE_WAKE: {
    sc_timer_expire_after_ns(sin->callback, 1);
    sin->ready_to_sleep = false;
    return true;
  }
  case SSIO_TYPE_CONN_REQ:
  case SSIO_TYPE_DISCONN_REQ:
  case SSIO_TYPE_DISCONN_RESP:
  default:
    {
      sc_shm_import_construct_close_msg(connection_id, pkt);
      sc_warn(tg, "%s: Invalid message received. fd: %d\n", __func__, connection_id);
      return false;
    }
  }
}


static void sc_shm_import_handle_message(struct sc_subnode_helper* sh)
{
  struct sc_shm_import_state* sin = sh->sh_private;
  if( sc_packet_list_is_empty(&sh->sh_backlog) )
    return;

  if( sin->shm_state->sis_connection_state == CONN_WAITING_FOR_DISCONNECT ) {
    sh->sh_poll_backlog_ns = WAIT_FOR_DISCONNECT_POLL_NS;
    return;
  }
  struct sc_packet* pkt = sc_packet_list_pop_head(&sh->sh_backlog);
  struct sc_session* tg = sc_thread_get_session(sc_node_get_thread(sin->node));
  struct sc_io_msg_hdr* hdr = pkt->iov[0].iov_base;
  SC_TEST(pkt->iov[0].iov_len >= sizeof(*hdr));
  sc_trace(tg, "%s: Message. connection_id: %d\n", __func__, hdr->connection_id);



  struct sc_node_link const* next_hop;
  switch( hdr->msg_type ) {
  case SC_IO_MSG_NEW_CONN:
    {
      sc_trace(tg, "%s: New connection. fd: %d\n", __func__, hdr->connection_id);
      /* Requesting connection from export */
      struct sc_io_msg_hdr* out_hdr = pkt->iov[0].iov_base;
      out_hdr->connection_id = hdr->connection_id;
      out_hdr->msg_type = SC_IO_MSG_DATA;
      struct sc_shm_io_message* out_msg = (void*)(out_hdr + 1);
      out_msg->ssio_type = SSIO_TYPE_CONN_REQ;
      out_msg->ssio_data.ssio_conn_req.ssio_request_reliable = sin->reliable;
      out_msg->ssio_data.ssio_conn_req.ssio_count_drops = sin->broadcast_count_drops;
      pkt->iov[0].iov_len = sizeof(*out_hdr) + sizeof(*out_msg);
      next_hop = sh->sh_links[0];
      break;
    }
  case SC_IO_MSG_DATA:
    {
      struct sc_shm_io_message* in_msg = (void*)(hdr + 1);
      next_hop = ( sc_shm_import_handle_ssio_msg(sin, in_msg, pkt, hdr->connection_id) ) ?
        sh->sh_free_link:
        sh->sh_links[0];
      break;
    }
  case SC_IO_MSG_CLOSE:
    {
      sc_trace(tg, "%s: Connection closed. End of stream. fd: %d\n", __func__,
               hdr->connection_id);
      sin->shm_state->sis_connection_state = CONN_WAITING_FOR_DISCONNECT;
      sc_shm_import_try_disconnect(sin->shm_state);
      sin->io_connection_id = -1;
      if( sin->mode_connect )
        sc_node_link_end_of_stream(sin->node, sin->next_hop);
      next_hop = sh->sh_free_link;
      break;
    }
  default:
    {
      /* Invalid message type. Kill connection. This will cause io_demux to
       * send back an SC_IO_MSG_CLOSE, so no need to duplicate clean up here.
       */
      sc_shm_import_construct_close_msg(hdr->connection_id, pkt);
      next_hop = sh->sh_links[0];
      break;
    }
  }
  sc_forward(sh->sh_node, next_hop, pkt);
}


static int init_io(struct sc_node* node, const struct sc_attr* attr)
{
  struct sc_shm_import_state* sin = node->nd_private;
  struct sc_node* input_node = NULL;

  char* mode = ( sin->mode_connect ) ? "connect" : "listen";

  struct sc_arg io_demux_args[] = {
    SC_ARG_STR(mode, sin->sock),
    SC_ARG_INT("reconnect", 0),
    SC_ARG_STR("error_mode", "exit")
  };

  struct sc_attr* io_attr = sc_attr_dup(attr);
  struct sc_attr* sh_attr = sc_attr_dup(attr);
  sc_attr_set_from_fmt(io_attr, "name", "%s.io_demux", node->nd_name);
  sc_attr_set_from_fmt(sh_attr, "name", "%s.sh", node->nd_name);

  struct sc_arg sh_args[] = {
    SC_ARG_INT("with_pool", 1),
  };

  sin->max_io_message_size = ( attr->buf_size < 0 ) ?
    SC_DMA_PKT_BUF_LEN : attr->buf_size;
  int rc = 0;
  if( sc_node_alloc(&sin->io_demux, io_attr, sc_node_get_thread(node),
                    &sc_io_demux_sc_node_factory, io_demux_args,
                    sizeof(io_demux_args)/sizeof(io_demux_args[0])) < 0 ||
      sc_node_alloc(&input_node, sh_attr, sc_node_get_thread(node),
                    &sc_subnode_helper_sc_node_factory, sh_args,
                    sizeof(sh_args)/sizeof(sh_args[0])) < 0 ||
      sc_node_add_link(sin->io_demux,  "shm_ctl", input_node, "") < 0 ||
      sc_node_add_link(input_node, "", sin->io_demux,  "shm_ctl") < 0 )
    rc = -1;

  sc_attr_free(io_attr);
  sc_attr_free(sh_attr);

  sin->io_node = input_node;
  struct sc_subnode_helper* sh = sc_subnode_helper_from_node(input_node);
  sh->sh_private = sin;
  sh->sh_handle_backlog_fn = sc_shm_import_handle_message;

  return rc;
}


static struct sc_node* sc_shm_import_select_subnode(struct sc_node* node,
                                                  const char* name_opt,
                                                  char** new_name_out)
{
  struct sc_shm_import_state* sin = node->nd_private;
  if( name_opt == NULL || strcmp(name_opt, "") == 0 ) {
    sc_node_set_error(node, EINVAL, "sc_shm_import: ERROR: incoming "
                      "links must have non-empty name\n");
    return NULL;
  }
  *new_name_out = sc_io_link_add_data_prefix(name_opt);
  return sin->io_demux;
}


static int sc_shm_import_add_link(struct sc_node* from_node,
                                  const char* link_name,
                                  struct sc_node* to_node,
                                  const char* to_name_opt)
{
  struct sc_shm_import_state* sin = from_node->nd_private;
  if( !strcmp(link_name, "") )
    return sc_node_add_link(from_node, link_name, to_node, to_name_opt);
  else
    return sc_node_add_link(sin->io_demux,
                            sc_io_link_add_data_prefix(link_name),
                            to_node, to_name_opt);
}


static int sc_shm_import_init(struct sc_node* node, const struct sc_attr* attr,
                              const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_prep_fn = sc_shm_import_prep;
    nt->nt_select_subnode_fn = sc_shm_import_select_subnode;
    nt->nt_add_link_fn = sc_shm_import_add_link;
  }

  struct sc_shm_import_state* sin;
  sin = sc_thread_calloc(sc_node_get_thread(node), sizeof(*sin));
  node->nd_private = sin;
  node->nd_type = nt;
  sin->node = node;

  sc_shm_stats_declare(sc_thread_get_session(sc_node_get_thread(node)));
  sc_node_export_state(node, "sc_shm_stats", sizeof(struct sc_shm_stats),
                       &sin->stats);

  const char* s;
  if( sc_node_init_get_arg_str(&s, node, "path", NULL) < 0 )
    return -1;

  if( s != NULL )
    SC_TEST(asprintf(&sin->sock, "unix:%s_sock", s) >= 0);
  else
    return sc_node_set_error(node, EINVAL, "%s: ERROR: path must be "
                             "provided\n", __func__);

  int mode_connect;
  if( sc_node_init_get_arg_int(&mode_connect, node, "active_connect", 1) < 0 )
    return -1;
  sin->mode_connect = mode_connect;

  int report_drops;
  if( sc_node_init_get_arg_int(&report_drops, node, "report_drops", 0) < 0 )
    return -1;
  sin->report_drops = report_drops;

  int emit_tail_drops;
  if( sc_node_init_get_arg_int(&emit_tail_drops, node, "emit_tail_drops", 0) < 0 )
    return -1;
  sin->emit_tail_drops = emit_tail_drops;

  if( sc_node_init_get_arg_int(&sin->poll_batch, node, "poll_batch", 8) < 0 )
    return -1;

  if( sc_node_init_get_arg_int(&sin->reliable, node, "reliable", 0) < 0 )
    return -1;

  if( sc_node_init_get_arg_int(&sin->broadcast_count_drops, node,
                               "broadcast_count_drops", 1) < 0 )
    return -1;

  SC_TRY(sc_callback_alloc(&sin->callback, attr, sc_node_get_thread(node)));
  sin->callback->cb_private = sin;
  sin->callback->cb_handler_fn = sc_shm_import_poll_callback;

  SC_TRY(sc_callback_alloc(&sin->wake_msg_cb, attr, sc_node_get_thread(node)));
  sin->wake_msg_cb->cb_private = sin;
  sin->wake_msg_cb->cb_handler_fn = sc_shm_import_wake_msg_cb;

  sin->unpack = !! attr->unpack_packed_stream;
  sc_packet_list_init(&sin->unpack_backlog);
  if( init_io(node, attr) < 0 )
    return -1;

  int pool_size = ( attr->pool_n_bufs <= 0 ) ?
    DEFAULT_MAX_PACKETS : attr->pool_n_bufs;
  int buf_size = sizeof(struct sc_shm_packet_metadata);
  if( sin->report_drops )
    buf_size += sizeof(struct sc_shm_import_metadata);
  sin->shm_state = sc_shm_import_alloc(node, pool_size, buf_size);

  sin->io_connection_id = -1;
  if( sin->shm_state == NULL )
    return -1;

  return 0;
}


const struct sc_node_factory sc_shm_import_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_shm_import",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_shm_import_init,
};

/** \endcond NODOC */
