/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \node{sc_shm_broadcast}
 *
 * \brief Export packets or messages to a shared memory channel with
 * multiple consumers.
 *
 * \nodedetails
 * This node is used in conjunction with \noderef{sc_shm_import} to pass
 * packets one or more consumer processes.  Packets delivered to
 * sc_shm_broadcast are forwarded over the channel to one or more
 * \noderef{sc_shm_import} nodes in consumer processes.
 *
 * See also \noderef{sc_shm_export}, which is more suitable when there is
 * only a single consumer, or a reliable channel is needed.
 *
 * \latexonly
 * {
 *   % Enable linebreaking on "_" within this table	 
 *   \renewcommand{\+}{\linebreak[0]}
 * \endlatexonly
 * \nodeargs
 * Argument                        | Optional? | Default  | Type           | Description
 * ------------------------------- | --------- | -------- | -------------- | ----------------------------------------------------------
 * path                            | No        |          | ::SC_PARAM_STR | Prefix of a path in the filesystem used for creating a socket and shared memory files.
 * max_channels                    | Yes       | 1        | ::SC_PARAM_INT | The maximum number of consumers that can connect to this channel.
 * max_in_flight                   | Yes       | "100%"   | ::SC_PARAM_STR | Maximum total amount of buffering that can be in flight at any one time. Specified as a percentage of the incoming pool ('%' suffix), or in bytes ('B', 'KiB', 'MiB' or 'GiB' suffix).
 * max_in_flight_per_channel       | Yes       | "100%"   | ::SC_PARAM_STR | Maximum amount of buffering that can be in flight per consumer. Specified as a percentage of the incoming pool ('%' suffix), or in bytes ('B', 'KiB' or 'GiB' suffix). max_in_flight_per_channel cannot exceed max_in_flight.
 * in_flight_reserved_per_channel  | Yes       | 50% / max_channels | ::SC_PARAM_STR |  Proportion of buffering that is dedicated to each channel.  The remainder is shared and can be used by any channel. This can be specified as a percentage of max_in_flight (with a '%' suffix), or in bytes (with 'B', 'KiB', 'MiB' or 'GiB' suffix).  max_channels * in_flight_reserved cannot exceed max_in_flight.
 * min_connected_reliable_channels | Yes       | 0        | ::SC_PARAM_INT | Packets reaching this node are buffered until at least this many reliable channels are connected.
 * send_retry_ns                   | Yes       | 10000    | ::SC_PARAM_INT | Period for retrying sending packets if ring is full.
 * drop_notification_retry_ns      | Yes       | 10000000 | ::SC_PARAM_INT | Period for retrying drop notifications if ring is full.
 * exit_on_disconnect              | Yes       | 0        | ::SC_PARAM_INT | Exit as soon as a client disconnects. This can only be set if max_channels is set to 1.
 * reliable_mode                   | Yes       | 0        | ::SC_PARAM_INT | If this is set, all connections are treated as reliable.
 * \internal
 * fd                              | Yes       | (null)   | ::SC_PARAM_INT | Use this already-connected unix socket FD for the first consumer.
 * connect_sock                    | Yes       | NULL     | ::SC_PARAM_STR | The socket this node should connect to.
 * listen                          | Yes       | 1        | ::SC_PARAM_INT | Set to 0 to not create a listening socket (only useful in conjunction with connect_sock or fd).
 * \endinternal
 * \latexonly
 *   % End enabling linebreaking
 * } 
 * \endlatexonly
 *
 * \namedinputlinks
 * None
 *
 * \outputlinks
 * Link | Description
 * ---- | -------------------------------------------------------------------
 * ""   | ::sc_packet objects received over the shared memory interface.
 *
 * \nodestatscopy{sc_shm}
 *
 * \cond NODOC
 */

#include "../core/internal.h"
#include <asm/mman.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sc_internal/ef_vi.h>
#include <sc_internal/shm_endpoint.h>
#include <sc_internal/builtin_nodes.h>
#include <sc_internal/io.h>
#include <sc_internal/appliance.h>
#include <limits.h>
#include <ctype.h>
#include <solar_capture/nodes/subnode_helper.h>


#define SC_TYPE_TEMPLATE <sc_shm_types_tmpl.h>
#define SC_DECLARE_TYPES sc_shm_stats_declare
#include <solar_capture/declare_types.h>

/* Attempt to send tail drop notifications every 10ms */
#define DROP_RETRY_NS (10000000ULL)

/* Attempt to send messages every 10us */
#define SEND_RETRY_NS (10000ULL)


enum eos_state {
  EOS_NO,
  EOS_SIGNALLED,
  EOS_HANDLED
};


struct sc_shm_broadcast_state;
const struct sc_node_factory sc_shm_broadcast_io_sc_node_factory;
const struct sc_node_factory sc_shm_broadcast_input_sc_node_factory;


struct sc_shm_broadcast_input {
  struct sc_node*                node;
  struct sc_packet_list          backlog;
  struct sc_node_link const*     next_hop;
  struct sc_shm_broadcast_state* shm_broadcast;
  struct sc_callback*            timed_handle_cb;
  enum eos_state                 eos;
};


struct sc_shm_broadcast_pkt_in_flight {
  struct sc_dlist   if_link;
  struct sc_packet* if_packet;
  struct sc_shm_broadcast_input* if_input;
  /* Bit set for each consumer that has this packet outstanding */
  uint64_t          if_use_mask;
  /* Bit set for each consumer that counted this out as a shared packet */
  uint64_t          if_shared_mask;
  unsigned          if_id;
};


struct sc_shm_broadcast_msg_to_send {
  struct sc_dlist       ms_link;
  struct sc_shm_message ms_msg;
};


struct sc_shm_broadcast_endpoint_state {
  /* fd for socket consumer is connected to. For unused endpoints, this is
   * -1
   */
  int connection_id;
  struct sc_shm_endpoint* ep;
  /* Packets dropped since previous message was sent. */
  uint64_t drops;
  /* Includes packets sent and packets waiting in send_list */
  uint64_t packets_in_flight;
  /* To track wake messages */
  uint64_t last_wake_seq;
  uint64_t reserved_total;
  uint64_t reserved_in_flight;
  uint64_t shared_in_flight;
  /* Free list for constructing shm messages */
  struct sc_dlist msg_to_send_free;
  /* Number of messages available on free list */
  unsigned n_free_msgs;
  /* Messages that are ready to be sent when there is space in the ring */
  struct sc_dlist  send_list;
  bool     reliable;
  bool     count_drops;
  /* There are cases where we need to close an fd to a misbehaving client.
   * Buffering a packet here avoids the complexity of dealing with a possibly
   * empty packet pool at that point.
   */
  struct sc_packet* close_packet;
};


struct sc_shm_broadcast_state {
  struct sc_node*                       node;
  struct sc_shm_endpoints*              endpoints;
  struct sc_node*                       io;
  struct sc_node*                       io_demux_node;
  struct sc_dlist                       if_pkt_free;
  struct sc_dlist                       if_pkt_in_flight;
  struct sc_shm_broadcast_pkt_in_flight*   if_pkts;
  int                                   if_pkts_n;
  char*                                 mmap_fname_tmpl;
  char*                                 buffer_fname;
  char*                                 listen_sock;
  char*                                 connect_sock;
  struct sc_shm_stats*                  stats;
  struct sc_shm_broadcast_input**       inputs;
  struct sc_callback*                   eos_cb;
  struct sc_callback*                   tail_drop_cb;
  struct sc_callback*                   send_msg_cb;
  struct sc_callback*                   drain_cb;
  struct sc_callback*                   wake_msg_cb;
  struct sc_callback*                   post_prep_cb;
  int                                   inputs_n;
  int                                   max_channels;
  int                                   min_reliable_channels;
  struct sc_shm_broadcast_endpoint_state* ep_state;
  uint64_t                              max_in_flight_pkts_shared;
  uint64_t                              max_in_flight_pkts_per_channel;
  char*                                 max_in_flight;
  char*                                 max_in_flight_per_channel;
  char*                                 in_flight_reserved_per_channel;
  int                                   eos_waiting;
  int                                   max_io_message_size;
  int                                   reliable_space;
  uint64_t                              shared_packets_in_flight;
  int                                   exported_pool_id;
  int                                   io_fd;
  bool                                  exit_on_disconnect;
  bool                                  reliable_mode;
  uint64_t                              reliable_mask;
  bool                                  ready_to_sleep;
  int64_t                               send_retry_ns;
  int64_t                               drop_retry_ns;
  int64_t                               drain_retry_ns;
};


static void sc_shm_broadcast_post_prep_cb(struct sc_callback* cb,
                                          void* event_info);


static inline bool only_reliable_user(uint64_t conn_mask,
                                      uint64_t if_use_mask,
                                      uint64_t reliable_mask)
{
  uint64_t without_mask = if_use_mask & ~conn_mask;
  return (if_use_mask & reliable_mask) && ! (without_mask & reliable_mask);
}


/* Across all connected reliable endpoints, get the minimum number of messages
 * that can be created.
 */
static void
sc_shm_broadcast_update_reliable_space(struct sc_shm_broadcast_state* st)
{
  int i;
  /* If there are no reliable connections, there is no limit */
  st->reliable_space = INT_MAX;
  for( i = 0; i < st->max_channels; i++ ) {
    if( st->ep_state[i].connection_id != -1 &&
        st->ep_state[i].reliable ) {
      int space = st->ep_state[i].n_free_msgs;
      if( space < st->reliable_space )
        st->reliable_space = space;
    }
  }
}


/* On successs, returns id of allocated endpoint (id >= 0). On failure, returns
 * -1.
 */
static int sc_shm_broadcast_attach(struct sc_node* node, int connection_id,
                                   bool reliable, bool count_drops)
{
  struct sc_shm_broadcast_state* st = node->nd_private;
  struct sc_subnode_helper* sh = sc_subnode_helper_from_node(st->io);
  int i;

  /* Only allowing one endpoint per socket */
  for( i = 0; i < st->max_channels; i++ )
    if( st->ep_state[i].connection_id == connection_id )
      return -1;

  for( i = 0; i < st->max_channels; i++ ) {
    if( st->ep_state[i].connection_id == -1 ) {
      if( st->ep_state[i].close_packet == NULL ) {
        struct sc_packet_list pl;
        __sc_packet_list_init(&pl);
        if( sc_pool_get_packets(&pl, sh->sh_pool, 1, 1) != 1 )
          return -1;
        st->ep_state[i].close_packet = pl.head;
      }
      SC_TEST(sc_shm_endpoint_activate(st->endpoints, i) == 0);
      st->ep_state[i].connection_id = connection_id;
      st->ep_state[i].reliable = reliable || st->reliable_mode;
      st->ep_state[i].count_drops = count_drops;
      sc_shm_broadcast_update_reliable_space(st);
      if( st->ep_state[i].reliable )
        st->reliable_mask |= (1 << i);
      sc_dlist_init(&st->ep_state[i].send_list);
      return i;
    }
  }
  return -1;
}


static void
sc_shm_broadcast_construct_close_msg(struct sc_shm_broadcast_state* st,
                                     int connection_id,
                                     struct sc_packet* out_pkt)
{
  struct sc_io_msg_hdr* out_hdr = out_pkt->iov[0].iov_base;
  out_hdr->connection_id = connection_id;
  out_hdr->msg_type = SC_IO_MSG_CLOSE;
  out_pkt->iov[0].iov_len = sizeof(*out_hdr);
}


static void
sc_shm_broadcast_free_in_flight_packet(struct sc_shm_broadcast_state* st,
                                       struct sc_shm_broadcast_pkt_in_flight* pif)
{
  sc_dlist_remove(&pif->if_link);
  sc_forward(pif->if_input->node, pif->if_input->next_hop,
             pif->if_packet);
  --st->stats->pkts_in_flight;
  pif->if_packet = NULL;
  assert(pif->if_use_mask == 0);
  assert(pif->if_shared_mask == 0);
  sc_dlist_push_head(&st->if_pkt_free, &pif->if_link);
}


static void
sc_shm_broadcast_construct_wake_msg(struct sc_shm_broadcast_state* st,
                                    int connection_id,
                                    struct sc_packet* out_pkt)
{
  struct sc_io_msg_hdr* out_hdr = out_pkt->iov[0].iov_base;
  out_hdr->connection_id = connection_id;
  out_hdr->msg_type = SC_IO_MSG_DATA;
  struct sc_shm_io_message* out_msg =  (void*)(out_hdr + 1);
  out_msg->ssio_type = SSIO_TYPE_WAKE;
  out_pkt->iov[0].iov_len = sizeof(*out_hdr) + sizeof(*out_msg);
}


static void
sc_shm_broadcast_send_wake_msg_if_needed(struct sc_shm_broadcast_state* st,
                                         int endpoint_id)
{
  int connection_id = st->ep_state[endpoint_id].connection_id;
  if( connection_id == -1 )
    return;
  uint64_t remote_sleep_seq =
    sc_shm_endpoint_get_remote_sleep_seq(st->ep_state[endpoint_id].ep);
  uint64_t msgs_sent =
    sc_shm_endpoint_get_n_sent(st->ep_state[endpoint_id].ep);
  if( ! (remote_sleep_seq == msgs_sent ||
         st->ep_state[endpoint_id].last_wake_seq > remote_sleep_seq) ) {
    struct sc_subnode_helper* sh = sc_subnode_helper_from_node(st->io);
    struct sc_packet_list pl;
    __sc_packet_list_init(&pl);
    if( sc_pool_get_packets(&pl, sh->sh_pool, 1, 1) != 1 ) {
      sc_pool_on_threshold(sh->sh_pool, st->wake_msg_cb, 1);
      return;
    }
    struct sc_packet* pkt = pl.head;
    sc_shm_broadcast_construct_wake_msg(st, connection_id, pkt);
    ++st->stats->wake_msgs;
    st->ep_state[endpoint_id].last_wake_seq = msgs_sent;
    sc_forward(sh->sh_node, sh->sh_links[0], pkt);
  }
}


inline static void
sc_shm_broadcast_cleanup_endpoint(struct sc_shm_broadcast_state* st,
                                  int endpoint_id)
{
  struct sc_shm_broadcast_pkt_in_flight* tmp;
  struct sc_shm_broadcast_pkt_in_flight* pif;
  struct sc_session* tg = sc_thread_get_session(sc_node_get_thread(st->node));
  struct sc_shm_broadcast_endpoint_state* eps = &st->ep_state[endpoint_id];
  if( st->exit_on_disconnect ) {
    /* TODO: Turn this into an EOS and handle in the normal way. */
    sc_info(tg, "%s: exiting due to remote client disconnection\n", __func__);
    exit(0);
  }

  SC_TEST(endpoint_id < st->max_channels);

  sc_trace(tg, "%s: Cleaning up endpoint %d. connection id:%d\n", __func__,
           endpoint_id, eps->connection_id);

  /* If there is a client connected, close connection */
  if( eps->connection_id != -1 ) {
    SC_TEST(eps->close_packet);
    sc_shm_broadcast_construct_close_msg(st, eps->connection_id,
                                         eps->close_packet);
    struct sc_subnode_helper* sh_io = st->io->nd_private;
    sc_forward(sh_io->sh_node, sh_io->sh_links[0], eps->close_packet);
    eps->close_packet = NULL;
  }

  /* Recover packets in flight */
  uint64_t use_mask = 1 << endpoint_id;
  SC_DLIST_FOR_EACH_OBJ_SAFE(&st->if_pkt_in_flight, pif, tmp, if_link) {
    if( only_reliable_user(use_mask, pif->if_use_mask, st->reliable_mask) )
      --st->stats->reliable_pkts_in_flight;
    pif->if_use_mask &= ~use_mask;
    pif->if_shared_mask &= ~use_mask;
    if( pif->if_use_mask == 0 )
      /* No outstanding uses for this packet. We can clean up. */
      sc_shm_broadcast_free_in_flight_packet(st, pif);
  }

  struct sc_shm_broadcast_msg_to_send* msg;
  struct sc_shm_broadcast_msg_to_send* msg_tmp;
  /* Remove messages scheduled for transmission */
  SC_DLIST_FOR_EACH_OBJ_SAFE(&eps->send_list, msg,
                             msg_tmp, ms_link) {
    sc_dlist_remove(&msg->ms_link);
    sc_dlist_push_head(&eps->msg_to_send_free, &msg->ms_link);
    ++eps->n_free_msgs;
  }

  eps->connection_id = -1;
  eps->drops = 0;
  eps->packets_in_flight = 0;
  eps->shared_in_flight = 0;
  eps->reserved_in_flight = 0;
  eps->last_wake_seq = 0;
  sc_shm_endpoint_reset(st->endpoints, endpoint_id);
  st->reliable_mask = st->reliable_mask & ~(1 << endpoint_id);
}


/* Clean up any endpoints associated with the provided connection_id. Returns
 * true if an endpoint was found and an SC_IO_MSG_CLOSE for the fd was
 * forwarded to the io_demux, false otherwise.
 */
static bool
sc_shm_broadcast_cleanup_endpoint_with_connection_id(struct sc_shm_broadcast_state* st,
                                                     int connection_id)
{
  int i;
  assert(connection_id >= 0);
  for( i = 0; i < st->max_channels; i++ )
    /* A given connection_id can have at most one connected endpoint */
    if( st->ep_state[i].connection_id == connection_id ) {
      sc_shm_broadcast_cleanup_endpoint(st, i);
      return true;
    }
  return false;
}


/* Returns true if pkt is to be freed, false if it is to be forwarded to
 * io_demux
 */
static bool
sc_shm_broadcast_handle_ssio_msg(struct sc_shm_broadcast_state* st,
                                 struct sc_shm_io_message* in_msg,
                                 struct sc_packet* pkt, int connection_id)
{
  struct sc_session* tg = sc_thread_get_session(sc_node_get_thread(st->node));
  switch( in_msg->ssio_type ) {
  case SSIO_TYPE_CONN_REQ:
    {
      struct sc_shm_io_message_data_req* req =
        &in_msg->ssio_data.ssio_conn_req;
      sc_trace(tg, "%s: Connection request. connection_id:%d reliable:%d\n",
               __func__, connection_id,
               in_msg->ssio_data.ssio_conn_req.ssio_request_reliable);
      /*  Reusing incoming buffer to send reply */
      struct sc_io_msg_hdr* out_hdr = pkt->iov[0].iov_base;
      int endpoint_id =
        sc_shm_broadcast_attach(st->node, connection_id,
                                req->ssio_request_reliable,
                                req->ssio_count_drops);
      out_hdr->connection_id = connection_id;
      out_hdr->msg_type = SC_IO_MSG_DATA;
      struct sc_shm_io_message* out_msg = (void*)(out_hdr + 1);
      out_msg->ssio_type = SSIO_TYPE_CONN_RESP;
      struct sc_shm_io_message_data_resp* resp =
        &out_msg->ssio_data.ssio_conn_resp;
      resp->ssio_endpoint_id = endpoint_id;
      if( endpoint_id < 0 ) {
        resp->ssio_ringbuf_shm_path[0] = '\0';
        resp->ssio_buffer_shm_path[0]  = '\0';
      }
      else {
        int rc = snprintf(resp->ssio_ringbuf_shm_path,
                          SSIO_MAX_STR_LEN,
			  "%s",
                          sc_shm_endpoint_get_path(st->endpoints, endpoint_id));
        SC_TEST( rc < SSIO_MAX_STR_LEN );
        rc = snprintf(resp->ssio_buffer_shm_path,
                      SSIO_MAX_STR_LEN, "%s",
		      st->buffer_fname);
        SC_TEST( rc < SSIO_MAX_STR_LEN );
      }
      pkt->iov[0].iov_len = sizeof(*out_hdr) + sizeof(*out_msg);
      return false;
    }
  case SSIO_TYPE_WAKE:
    {
      st->ready_to_sleep = false;
      sc_timer_expire_after_ns(st->drain_cb, 1);
      return true;
    }
  case SSIO_TYPE_CONN_RESP:
  case SSIO_TYPE_DISCONN_REQ:
  case SSIO_TYPE_DISCONN_RESP:
  default:
    {
      sc_shm_broadcast_construct_close_msg(st, connection_id, pkt);
      return sc_shm_broadcast_cleanup_endpoint_with_connection_id(st, connection_id);
    }
  }
}


static void
sc_shm_broadcast_handle_message(struct sc_subnode_helper* sh)
{
  struct sc_shm_broadcast_state* st = sh->sh_private;
  struct sc_packet* pkt = sc_packet_list_pop_head(&sh->sh_backlog);
  SC_TEST(pkt->iovlen == 1);
  struct sc_io_msg_hdr* hdr = pkt->iov[0].iov_base;
  struct sc_session* tg = sc_thread_get_session(sc_node_get_thread(st->node));
  struct sc_node_link const* next_hop;
  SC_TEST(pkt->iov[0].iov_len >= sizeof(*hdr));

  switch ( hdr->msg_type ) {
  case SC_IO_MSG_NEW_CONN:
    {
      sc_trace(tg, "%s: New connection. connection_id:%d\n", __func__,
               hdr->connection_id);
      next_hop = sh->sh_free_link;
      break;
    }
  case SC_IO_MSG_DATA:
    {
      struct sc_shm_io_message* in_msg = (void*)(hdr + 1);
      next_hop = ( sc_shm_broadcast_handle_ssio_msg(st, in_msg, pkt,
                                                    hdr->connection_id) ) ?
        sh->sh_free_link:
        sh->sh_links[0];
      break;
    }
  case SC_IO_MSG_CLOSE:
  default:
    {
      sc_shm_broadcast_construct_close_msg(st, hdr->connection_id, pkt);
      next_hop =
        ( sc_shm_broadcast_cleanup_endpoint_with_connection_id(st, hdr->connection_id) ) ?
        sh->sh_free_link : /* Socket killed in cleanup. So free packet. */
        sh->sh_links[0];   /* Kill socket. */
      break;
    }
  }
  sc_forward(sh->sh_node, next_hop, pkt);
}


static bool
sc_shm_broadcast_drain_endpoint(struct sc_shm_broadcast_state* st,
                                int endpoint_id)
{
  struct sc_shm_message sm;
  struct sc_shm_endpoint* ep = st->ep_state[endpoint_id].ep;
  assert(endpoint_id >= 0 && endpoint_id < st->max_channels);
  uint64_t use_mask = 1 << endpoint_id;
  bool msg_seen = false;
  while( sc_shm_endpoint_msg_get(ep, &sm) == 0 ) {
    msg_seen = true;
    if( sm.ssm_message_type != SSM_TYPE_FREE_PACKET ||
        sm.ssm_message.usm_free_packet.usm_packet_id >=
        st->if_pkts_n ) {
      /* Client badness has happened. Disabling the endpoint and closing
       * associated domain socket.
       */
      sc_shm_broadcast_cleanup_endpoint(st, endpoint_id);
      return true;
    }
    struct sc_shm_broadcast_pkt_in_flight* pif =
      &st->if_pkts[sm.ssm_message.usm_free_packet.usm_packet_id];

    if( (pif->if_use_mask & use_mask) == 0 ) {
      sc_shm_broadcast_cleanup_endpoint(st, endpoint_id);
      return true;
    }
    assert(st->ep_state[endpoint_id].packets_in_flight > 0);
    assert(st->ep_state[endpoint_id].reliable ||
           (st->ep_state[endpoint_id].reserved_in_flight +
            st->ep_state[endpoint_id].shared_in_flight ==
            st->ep_state[endpoint_id].packets_in_flight));

    --st->ep_state[endpoint_id].packets_in_flight;
    if( ! st->ep_state[endpoint_id].reliable ) {
      if( pif->if_shared_mask & use_mask )
        --st->ep_state[endpoint_id].shared_in_flight;
      else
        --st->ep_state[endpoint_id].reserved_in_flight;
    }
    if( only_reliable_user(use_mask, pif->if_use_mask, st->reliable_mask) )
      /* This is the last reliable endpoint for this packet. */
      --st->stats->reliable_pkts_in_flight;

    if( pif->if_shared_mask == use_mask )
      --st->shared_packets_in_flight;

    pif->if_use_mask &= ~use_mask;
    pif->if_shared_mask &= ~use_mask;

    if( pif->if_use_mask == 0 )
      /* No outstanding uses for this packet. We can clean up. */
      sc_shm_broadcast_free_in_flight_packet(st, pif);
  }
  return msg_seen;
}


static unsigned get_packet_count(struct sc_packet* pkt)
{
  struct sc_packed_packet* pkt_hdr = pkt->iov[0].iov_base;
  struct sc_appliance_buffer_header* buf_hdr = (void*)(pkt_hdr + 1);
  /* For packed stream buffers with a block header, get the number of
   * encapsulated packets.
   *
   * TODO: Once sensible metadata for packed stream buffers is in place, use
   * that instead.
   */
  if( (pkt->flags & SC_PACKED_STREAM) &&
      (pkt->iov[0].iov_len >= sizeof(*pkt_hdr) + sizeof(*buf_hdr)) &&
      pkt_hdr->ps_pkt_start_offset > sizeof(struct sc_packed_packet) &&
      buf_hdr->hdr.prh_type == SC_PACKED_RECORD_APPLIANCE_BLOCK_HEADER )
    return buf_hdr->data.pkt_count;
  else
    return 1;
}


/* Return true if all outstanding messages have been sent, false otherwise */
static bool
sc_shm_broadcast_send_outstanding_msgs(struct sc_shm_broadcast_state* st,
                                       int endpoint_id)
{
  struct sc_shm_endpoint* ep = st->ep_state[endpoint_id].ep;
  while( ! sc_dlist_is_empty(&st->ep_state[endpoint_id].send_list) ) {
    struct sc_shm_broadcast_msg_to_send* ms =
      SC_CONTAINER(struct sc_shm_broadcast_msg_to_send, ms_link,
                   sc_dlist_pop_head(&st->ep_state[endpoint_id].send_list));
    if( sc_shm_endpoint_msg_send(ep, &ms->ms_msg) == 0 ) {
      sc_dlist_push_head(&st->ep_state[endpoint_id].msg_to_send_free,
                         &ms->ms_link);
      ++st->ep_state[endpoint_id].n_free_msgs;
    }
    else {
      sc_dlist_push_head(&st->ep_state[endpoint_id].send_list, &ms->ms_link);
      return false;
    }
  }

  return true;
}


/* Returns true if there are no outstanding messages left, false otherwise */
static bool
sc_shm_broadcast_send_all_outstanding_msgs(struct sc_shm_broadcast_state* st)
{
  bool all_done = true;
  int i;
  for( i = 0; i < st->max_channels; i++)
    if( st->ep_state[i].connection_id != -1 )
      all_done &= sc_shm_broadcast_send_outstanding_msgs(st, i);
  return all_done;
}


static void sc_shm_broadcast_send_msgs_cb(struct sc_callback* cb, void* event_info)
{
  struct sc_shm_broadcast_state* st = cb->cb_private;
  if( ! sc_shm_broadcast_send_all_outstanding_msgs(st) )
    sc_timer_expire_after_ns(cb, st->send_retry_ns);
}


static void
sc_shm_broadcast_handle_backlog(struct sc_shm_broadcast_input* bis)
{
  struct sc_shm_broadcast_state* st = bis->shm_broadcast;
  struct sc_node* node = st->node;
  struct sc_shm_message sm;
  int i;
  bool msg_seen = false;
  if( __builtin_popcount(st->reliable_mask) < st->min_reliable_channels )
    return;

  for( i = 0; i < st->max_channels; i++)
    msg_seen = msg_seen || sc_shm_broadcast_drain_endpoint(st, i);
  if( st->reliable_space == 0 )
    sc_shm_broadcast_update_reliable_space(st);

  bool drops_outstanding = false;
  while( ! sc_packet_list_is_empty(&bis->backlog) &&
         /* If there are any reliable connections that cannot accept packets,
          * we leave packets on the backlog and stop.
          */
         st->reliable_space > 0 ) {
    struct sc_packet* pkt;
    assert( ! sc_dlist_is_empty(&st->if_pkt_free) );
    pkt = sc_packet_list_pop_head(&bis->backlog);
    struct sc_shm_broadcast_pkt_in_flight* pif =
      SC_CONTAINER(struct sc_shm_broadcast_pkt_in_flight, if_link,
                   sc_dlist_pop_head(&st->if_pkt_free));
    SC_TEST(pif->if_packet == NULL);
    SC_TEST(pif->if_use_mask == 0);
    SC_TEST(pif->if_shared_mask == 0);
    pif->if_packet = pkt;
    pif->if_input  = bis;

    sm.ssm_message_type = SSM_TYPE_STREAM_PACKET;
    sm.ssm_message.usm_stream_packet.usm_buffer_offset =
      sc_pkt_shm_buffer_offset(node, pkt);
    SC_TEST(pkt->iovlen == 1);
    sm.ssm_message.usm_stream_packet.usm_buffer_len = pkt->iov[0].iov_len;
    sm.ssm_message.usm_stream_packet.usm_packet_id = pif->if_id;
    sm.ssm_message.usm_stream_packet.usm_packet_type =
      ( pkt->flags & SC_PACKED_STREAM ) ? SSM_PKT_TYPE_PACKED_STREAM :
      SSM_PKT_TYPE_NORMAL;
    sm.ssm_message.usm_stream_packet.usm_ts_sec = pkt->ts_sec;
    sm.ssm_message.usm_stream_packet.usm_ts_nsec = pkt->ts_nsec;
    for( i = 0; i < st->max_channels; i++ ) {
      if( st->ep_state[i].connection_id != -1 ) {
        sm.ssm_message.usm_stream_packet.usm_drop_count = st->ep_state[i].drops;
        bool channel_space =
          st->ep_state[i].packets_in_flight < st->max_in_flight_pkts_per_channel;
        bool global_space =
          st->shared_packets_in_flight < st->max_in_flight_pkts_shared ||
          st->ep_state[i].reserved_in_flight < st->ep_state[i].reserved_total;

        /* Not applying max_in_flight checks to reliable connections */
        bool has_space =
          st->ep_state[i].reliable || (global_space && channel_space);
        if( has_space ) {
          SC_TEST( ! sc_dlist_is_empty(&st->ep_state[i].msg_to_send_free) );
          struct sc_shm_broadcast_msg_to_send* ms =
            SC_CONTAINER(struct sc_shm_broadcast_msg_to_send, ms_link,
                         sc_dlist_pop_head(&st->ep_state[i].msg_to_send_free));
          --st->ep_state[i].n_free_msgs;
          ms->ms_msg = sm;
          sc_dlist_push_tail(&st->ep_state[i].send_list, &ms->ms_link);
          pif->if_use_mask |= (1 << i);
          ++st->ep_state[i].packets_in_flight;
          if( ! st->ep_state[i].reliable ) {
            if( st->ep_state[i].reserved_in_flight <
                st->ep_state[i].reserved_total ) {
              ++st->ep_state[i].reserved_in_flight;
            }
            else {
              pif->if_shared_mask |= (1 << i);
              ++st->ep_state[i].shared_in_flight;
            }
          }
          st->ep_state[i].drops = 0;
        }
        else {
          unsigned count = get_packet_count(pkt);
          drops_outstanding = true;
          st->ep_state[i].drops += count;
          if( st->ep_state[i].count_drops )
            st->stats->pkts_dropped += count;
        }
      }
    }
    if( pif->if_shared_mask != 0 ) {
      /* At least one consumer has used the shared allocation
       */
      ++st->shared_packets_in_flight;
    }
    if( pif->if_use_mask != 0 ) {
      /* If we've sent the packet out to any consumer, we hold on to it
       * until the consumer frees it.
       */
      sc_dlist_push_head(&st->if_pkt_in_flight, &pif->if_link);
      if( pif->if_use_mask & st->reliable_mask )
        ++st->stats->reliable_pkts_in_flight;
      ++st->stats->pkts_in_flight;
      --st->reliable_space;
    }
    else {
      /* If this packet hasn't gone over the shm, it's fine to forward it
       * immediately.
       */
      pif->if_packet = NULL;
      sc_dlist_push_head(&st->if_pkt_free, &pif->if_link);
      sc_forward(bis->node, bis->next_hop, pkt);
    }
  }

  /* Send any wake messages that are needed */
  for( i = 0; i < st->max_channels; i++ )
    sc_shm_broadcast_send_wake_msg_if_needed(st, i);

  if( msg_seen )
    sc_timer_expire_after_ns(st->drain_cb, 1);

  if( ! sc_shm_broadcast_send_all_outstanding_msgs(st) )
    sc_timer_expire_after_ns(st->send_msg_cb, st->send_retry_ns);

  if( drops_outstanding )
    sc_timer_expire_after_ns(st->tail_drop_cb, st->drop_retry_ns);
}


static void sc_shm_broadcast_wake_msg_cb(struct sc_callback* cb, void* event_info)
{
  int i;
  struct sc_shm_broadcast_state* st = cb->cb_private;
  for( i = 0; i < st->max_channels; i++ )
    sc_shm_broadcast_send_wake_msg_if_needed(st, i);
}


static void sc_shm_broadcast_drain_cb(struct sc_callback* cb, void* event_info)
{
  struct sc_shm_broadcast_state* st = cb->cb_private;
  int i;
  bool msg_seen = false;
  for( i = 0; i < st->max_channels; i++)
    msg_seen = msg_seen || sc_shm_broadcast_drain_endpoint(st, i);

  if( msg_seen ) {
    sc_timer_expire_after_ns(st->drain_cb, 1);
    st->ready_to_sleep = false;
    return;
  }

  if( ! st->ready_to_sleep ) {
    for( i = 0; i < st->max_channels; i++)
      if( st->ep_state[i].connection_id != -1 ) {
        sc_shm_endpoint_notify_sleep(st->ep_state[i].ep);
        ++st->stats->sleep_notifies;
      }
    sc_timer_expire_after_ns(st->drain_cb, 1);
  }
  st->ready_to_sleep = true;
}


static void sc_shm_broadcast_eos_cb(struct sc_callback* cb, void* event_info)
{
  int i;
  bool wait = false;
  struct sc_shm_broadcast_state* st = cb->cb_private;
  for( i = 0; i < st->max_channels; i++ ) {
    if( st->ep_state[i].connection_id != -1 && st->ep_state[i].reliable ) {
      sc_shm_broadcast_drain_endpoint(st, i);
      if( st->ep_state[i].packets_in_flight > 0 )
        wait = true;
      else
        sc_shm_broadcast_cleanup_endpoint(st, i);
    }
  }

  if( wait )
    sc_timer_expire_after_ns(cb, 1);
  else
    for( i = 0; i < st->inputs_n; i++ )
      sc_node_link_end_of_stream(st->inputs[i]->node,
                                 st->inputs[i]->next_hop);
}


static void sc_shm_broadcast_tail_drop_cb(struct sc_callback* cb, void* event_info)
{
  struct sc_shm_broadcast_state* st = cb->cb_private;
  int i;
  struct sc_shm_message sm;
  bool drops_outstanding = false;
  sm.ssm_message_type = SSM_TYPE_DROP_NOTIFICATION;
  for( i = 0; i < st->max_channels; i++ ) {
    if( st->ep_state[i].drops > 0 ) {
      sm.ssm_message.usm_drop_notification.usm_drop_count =
        st->ep_state[i].drops;
      if( sc_shm_endpoint_msg_send(st->ep_state[i].ep, &sm) == 0 )
        st->ep_state[i].drops = 0;
      else
        drops_outstanding = true;
    }
    sc_shm_broadcast_send_wake_msg_if_needed(st, i);
  }
  if( drops_outstanding )
    sc_timer_expire_after_ns(cb, st->drop_retry_ns);
}


void
sc_shm_broadcast_handle_end_of_stream(struct sc_shm_broadcast_input* bis)
{
  struct sc_shm_broadcast_state* st = bis->shm_broadcast;
  SC_TEST( bis->eos == EOS_SIGNALLED );
  SC_TEST( sc_packet_list_is_empty(&(bis->backlog)) );
  bis->eos = EOS_HANDLED;
  SC_TEST( st->eos_waiting > 0 );
  if( --st->eos_waiting == 0 )
    sc_timer_expire_after_ns(st->eos_cb, 1);
}


/* Redirects named incoming links to our sc_io_demux with a 'data:' prefix */
static struct sc_node* sc_shm_broadcast_select_subnode(struct sc_node* node,
                                                       const char* name_opt,
                                                       char** new_name_out)
{
  struct sc_shm_broadcast_state* st = node->nd_private;

  if( name_opt != NULL && strcmp(name_opt, "") ) {
    *new_name_out = sc_io_link_add_data_prefix(name_opt);
    return st->io_demux_node;
  }

  struct sc_attr* attr;
  SC_TRY(sc_attr_alloc(&attr));
  struct sc_node* input_node;
  int rc = sc_node_alloc(&input_node, attr, sc_node_get_thread(node),
                         &sc_shm_broadcast_input_sc_node_factory,
                         NULL, 0);

  sc_attr_free(attr);
  if( rc < 0 ) {
    sc_node_fwd_error(node, rc);
    return NULL;
  }

  struct sc_shm_broadcast_input* bis = input_node->nd_private;
  bis->shm_broadcast = st;

  st->inputs = realloc(st->inputs, sizeof(bis) * (++st->inputs_n));
  st->inputs[st->inputs_n - 1] = bis;

  ++st->eos_waiting;

  return input_node;
}


/* Redirects named outgoing links to our sc_io_demux with a 'data:' prefix */
int sc_shm_broadcast_add_link(struct sc_node* from_node,
                              const char* link_name,
                              struct sc_node* to_node,
                              const char* to_name_opt)
{
  struct sc_shm_broadcast_state* st = from_node->nd_private;
  int i;
  if( strcmp(link_name, "") )
    return sc_node_add_link(st->io_demux_node,
                            sc_io_link_add_data_prefix(link_name),
                            to_node, to_name_opt);

  for( i = 0; i < st->inputs_n; i++ )
    sc_node_add_link(st->inputs[i]->node, link_name, to_node, to_name_opt);
  return 0;
}


static int init_io(struct sc_node* node, const struct sc_attr* attr)
{
  struct sc_shm_broadcast_state* se = node->nd_private;
  struct sc_node* io_demux_node;
  struct sc_node* io_node;

  struct sc_arg io_demux_args[] = {
    SC_ARG_STR("connect", se->connect_sock),
    SC_ARG_STR("listen", se->listen_sock),
    SC_ARG_INT("reconnect", 0),
    SC_ARG_INT("fd", se->io_fd),
    SC_ARG_STR("error_mode", "disconnect"),
  };

  struct sc_arg io_args[] = {
    SC_ARG_INT("with_pool", 1),
  };
  se->max_io_message_size = ( attr->buf_size < 0 ) ?
    SC_DMA_PKT_BUF_LEN : attr->buf_size;

  int rc = 0;
  if( sc_node_alloc(&io_demux_node, attr, sc_node_get_thread(node),
                    &sc_io_demux_sc_node_factory, io_demux_args,
                    sizeof(io_demux_args)/sizeof(io_demux_args[0])) < 0 ||
      sc_node_alloc(&io_node, attr, sc_node_get_thread(node),
                    &sc_subnode_helper_sc_node_factory, io_args,
                    sizeof(io_args)/sizeof(io_args[0])) < 0 ||
      sc_node_add_link(io_demux_node,  "shm_ctl", io_node, "") < 0 ||
      sc_node_add_link(io_node, "", io_demux_node,  "shm_ctl") < 0 )
    rc = -1;

  struct sc_subnode_helper* sh = sc_subnode_helper_from_node(io_node);
  sh->sh_handle_backlog_fn = sc_shm_broadcast_handle_message;
  sh->sh_private = se;

  se->io = io_node;
  se->io_demux_node = io_demux_node;
  return rc;
}


static int parse_percent_string(unsigned* p_val, const char* p_str)
{
 unsigned percent_val;
 char dummy;
 char p;
 int rc = sscanf(p_str, "%u%c%c", &percent_val, &p, &dummy);
 if( rc != 2 || p != '%' || percent_val > 100 )
   return -1;
 *p_val = percent_val;
 return 0;
}


static int64_t convert_to_pkts(struct sc_pkt_pool* pp, const char* conf_str)
{
  int len = strlen(conf_str);
  /* We require either a size or a '%' suffix */
  if( len < 1 || isdigit(conf_str[len - 1]) )
    return -1;
  int64_t pkts;
  unsigned percentage = 0;  /* suppress compiler warning */
  int64_t bytes;
  int rc_size = sc_parse_size_string(&bytes, conf_str);
  int rc_percent = parse_percent_string(&percentage, conf_str);
  /* If pp is not provided, validating only */
  if( pp == NULL )
     pkts = ( rc_size == 0 || rc_percent == 0 ) ? 0 : -1;
  else if( rc_size  == 0 )
    pkts = bytes / pp->pp_buf_size;
  else if( rc_percent == 0 )
    pkts = ( pp->pp_stats->allocated_bufs * (int64_t)percentage ) / 100;
  else
    pkts = -1;

  return pkts;
}


static int parse_in_flight_argument(char** dest, struct sc_node* node,
                                    const char* arg_name,
                                    const char* default_val)
{
  const char* m_str;
  if( sc_node_init_get_arg_str(&m_str, node,
                               arg_name, default_val) < 0 )
    return -1;
  /* Since we don't know the pool size yet, all we can do now is check we can
   * parse the in_flight arguments. Proper validity check is done in the
   * post_prep callback.
   */
  if( convert_to_pkts(NULL, m_str) != 0 )
    return sc_node_set_error(node, EINVAL,
                             "%s: ERROR: invalid value '%s' for argument '%s'\n",
                             __func__, m_str, arg_name);
  *dest = strdup(m_str);
  return 0;
}


static int sc_shm_broadcast_init(struct sc_node* node, const struct sc_attr* attr,
                                 const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_add_link_fn = sc_shm_broadcast_add_link;
    nt->nt_select_subnode_fn = sc_shm_broadcast_select_subnode;
  }

  sc_shm_stats_declare(sc_thread_get_session(sc_node_get_thread(node)));

  struct sc_shm_broadcast_state* st;
  st = sc_thread_calloc(sc_node_get_thread(node), sizeof(*st));
  node->nd_private = st;
  node->nd_type = nt;
  st->node = node;


  if( sc_node_init_get_arg_int(&st->io_fd, node, "fd", -1) < 0 )
    return -1;

  int listen;
  if( sc_node_init_get_arg_int(&listen, node, "listen", 1) < 0 )
    return -1;

  const char* s;
  if( sc_node_init_get_arg_str(&s, node, "connect_sock", NULL) < 0 )
    return -1;

  if( s != NULL )
    st->connect_sock = strdup(s);

  if( sc_node_init_get_arg_str(&s, node, "path", NULL) < 0 )
    return -1;

  if( s != NULL ) {
    /* s must be short enough to append '_ctl_buf_%d' and still fit inside
     * SSIO_MAX_STR_LEN (where %d is an int). */
    if( strlen(s) >= SSIO_MAX_STR_LEN - 18 )
      return sc_node_set_error(node, EINVAL, "%s: ERROR: path is too long\n",
                               __func__);
    if( listen )
      SC_TEST(asprintf(&st->listen_sock, "unix:%s_sock", s) >= 0);
    else if( st->connect_sock == NULL && st->io_fd < 0 )
      return sc_node_set_error(node, EINVAL, "%s: ERROR: you must specify at "
                               "least one of 'listen', 'connect_sock' or 'fd'\n",
                               __func__);
    SC_TEST(asprintf(&st->mmap_fname_tmpl, "%s_ctl_buf", s) >= 0);
    SC_TEST(asprintf(&st->buffer_fname, "%s_data_buf", s) >= 0);
  }
  else {
    return sc_node_set_error(node, EINVAL, "%s: ERROR: missing required "
                             "argument 'path'\n", __func__);
  }

  if( init_io(node, attr) < 0 )
    return -1;

  if( sc_node_init_get_arg_int(&st->max_channels, node, "max_channels", 1) < 0 )
    return -1;
  if( st->max_channels < 1 )
    return sc_node_set_error(node, EINVAL,
                             "%s: ERROR: max_channels must be set to 1 or more\n",
                             __func__);

  if( sc_node_init_get_arg_int64(&st->send_retry_ns, node, "send_retry_ns",
                                 SEND_RETRY_NS) < 0 )
    return -1;

  if( sc_node_init_get_arg_int64(&st->drop_retry_ns, node, "drop_notification_retry_ns",
                                 DROP_RETRY_NS) < 0 )
    return -1;

  sc_dlist_init(&st->if_pkt_free);
  sc_dlist_init(&st->if_pkt_in_flight);

  if( parse_in_flight_argument(&st->max_in_flight, node,
                               "max_in_flight", "100%") != 0 )
    return -1;

  if( parse_in_flight_argument(&st->max_in_flight_per_channel, node,
                               "max_in_flight_per_channel", "100%") != 0 )
    return -1;

  char* default_str;
  if( asprintf(&default_str, "%d%%", 50 / st->max_channels ) < 0 )
    return -1;

  if( parse_in_flight_argument(&st->in_flight_reserved_per_channel, node,
                               "in_flight_reserved_per_channel",
                               default_str) != 0 )
    return -1;
  free(default_str);

  if( sc_node_init_get_arg_int(&st->min_reliable_channels, node,
                               "min_connected_reliable_channels", 0) < 0 )
    return -1;

  st->ep_state =
    sc_thread_calloc(sc_node_get_thread(node),
                     sizeof(struct sc_shm_broadcast_endpoint_state) *
                     st->max_channels);
  int tmp;
  if( sc_node_init_get_arg_int(&tmp, node, "exit_on_disconnect", 0) < 0 )
    return -1;

  st->exit_on_disconnect = !!tmp;

  if( st->exit_on_disconnect && st->max_channels != 1 )
    return sc_node_set_error(node, EINVAL,
                             "%s: ERROR: exit_on_disconnect can only be set if max_channels is 1.\n",
                             __func__);

  if( sc_node_init_get_arg_int(&tmp, node, "reliable_mode", 0) < 0 )
    return -1;
  st->reliable_mode = !!tmp;

  sc_node_export_state(node, "sc_shm_stats", sizeof(struct sc_shm_stats),
                       &st->stats);

  SC_TEST(st->ep_state != NULL);
  SC_TRY(sc_callback_alloc(&st->eos_cb, attr,
                           sc_node_get_thread(node)));
  st->eos_cb->cb_private = st;
  st->eos_cb->cb_handler_fn = sc_shm_broadcast_eos_cb;

  SC_TRY(sc_callback_alloc(&st->tail_drop_cb, attr,
                           sc_node_get_thread(node)));
  st->tail_drop_cb->cb_private = st;
  st->tail_drop_cb->cb_handler_fn = sc_shm_broadcast_tail_drop_cb;

  SC_TRY(sc_callback_alloc(&st->send_msg_cb, attr,
                           sc_node_get_thread(node)));
  st->send_msg_cb->cb_private = st;
  st->send_msg_cb->cb_handler_fn = sc_shm_broadcast_send_msgs_cb;

  SC_TRY(sc_callback_alloc(&st->drain_cb, attr,
                           sc_node_get_thread(node)));
  st->drain_cb->cb_private = st;
  st->drain_cb->cb_handler_fn = sc_shm_broadcast_drain_cb;

  SC_TRY(sc_callback_alloc(&st->wake_msg_cb, attr,
                           sc_node_get_thread(node)));
  st->wake_msg_cb->cb_private = st;
  st->wake_msg_cb->cb_handler_fn = sc_shm_broadcast_wake_msg_cb;

  SC_TRY(sc_callback_alloc(&st->post_prep_cb, attr,
                           sc_node_get_thread(node)));
  st->post_prep_cb->cb_private = st;
  st->post_prep_cb->cb_handler_fn = sc_shm_broadcast_post_prep_cb;

  st->exported_pool_id = -1;
  return 0;
}


const struct sc_node_factory sc_shm_broadcast_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_shm_broadcast",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_shm_broadcast_init,
};


static void
sc_shm_broadcast_input_handle_backlog(struct sc_shm_broadcast_input* bis)
{
  sc_shm_broadcast_handle_backlog(bis);
  if( ! sc_packet_list_is_empty(&bis->backlog) ||
      bis->shm_broadcast->ep_state->packets_in_flight )
    sc_timer_expire_after_ns(bis->timed_handle_cb, 100000);
  else if( bis->eos == EOS_SIGNALLED && sc_packet_list_is_empty(&bis->backlog) )
    sc_shm_broadcast_handle_end_of_stream(bis);
}


static void sc_shm_broadcast_input_pkts(struct sc_node* node,
                                        struct sc_packet_list* pl)
{
  struct sc_shm_broadcast_input* bis = node->nd_private;
  sc_packet_list_append_list(&bis->backlog, pl);
  sc_shm_broadcast_input_handle_backlog(bis);
}


static void
sc_shm_broadcast_input_timed_cb(struct sc_callback* cb,
                                        void* event_info)
{
  struct sc_shm_broadcast_input* bis = cb->cb_private;
  sc_shm_broadcast_input_handle_backlog(bis);
}


static void sc_shm_broadcast_input_eos(struct sc_node* node)
{
  struct sc_shm_broadcast_input* bis = node->nd_private;
  SC_TEST( bis->eos == EOS_NO );
  bis->eos = EOS_SIGNALLED;
  if( sc_packet_list_is_empty(&(bis->backlog)) )
    sc_shm_broadcast_handle_end_of_stream(bis);
}


static void sc_shm_broadcast_post_prep_cb(struct sc_callback* cb,
                                          void* event_info)
{
  struct sc_shm_broadcast_state* st = cb->cb_private;
  SC_TEST(st->exported_pool_id >= 0);
  struct sc_session* tg = sc_thread_get_session(sc_node_get_thread(st->node));
  struct sc_pkt_pool* pp = tg->tg_pkt_pools[st->exported_pool_id];
  struct sc_pkt_pool* buffer_pp = pp;
  /* We can't just store buffer_pp from prep time since we want to look at
   * pp_buf_size for intermediate pools, and that isn't available till after
   * prep.
   */
  while( buffer_pp->pp_linked_pool ) {
    if( buffer_pp->pp_buf_size != 0 )
      sc_warn(tg, "%s: WARNING: Not exporting buffers from wrapping pool(%d). "
              "Only one pool can be exported.", __func__, buffer_pp->pp_id);
    buffer_pp = buffer_pp->pp_linked_pool;
  }
  SC_TEST(buffer_pp->pp_buf_size > 0);
  /* The actual accounting is done in packets, not bytes.  Converting bytes
   * to packets based on buffer size here. We assume that a buffer is
   * consumed per in flight packet. This is not necessarily true if there is
   * unpacking happening upstream. So we might end up imposing a tighter
   * constraint on in flight data than the user has asked for.
   *
   * The alternative approach of counting bytes of packet data is not
   * suitable, since an entire buffer is tied up even if a small amount of
   * data is outstanding.
   *
   * TODO: Figure out how to track this properly when wrapping/unpacking.
   */
  int64_t max_in_flight_pkts = convert_to_pkts(buffer_pp, st->max_in_flight);
  SC_TEST(max_in_flight_pkts >= 0);
  int64_t reserved_per_channel;
  unsigned percentage;
  /* This is specified either as an absolute number, or as a percentage of
   * max_in_flight.
   */
  if( parse_percent_string(&percentage,
                           st->in_flight_reserved_per_channel) == 0 )
    reserved_per_channel = ( ( max_in_flight_pkts ) * percentage ) / 100;
  else
    reserved_per_channel =
      convert_to_pkts(buffer_pp, st->in_flight_reserved_per_channel);
  SC_TEST(reserved_per_channel >= 0);
  /* TODO: Check this earlier. */
  SC_TEST(max_in_flight_pkts >= reserved_per_channel * st->max_channels);
  st->max_in_flight_pkts_shared =
    max_in_flight_pkts - (reserved_per_channel * st->max_channels);
  st->max_in_flight_pkts_per_channel =
    convert_to_pkts(buffer_pp, st->max_in_flight_per_channel);
  /* We make sure we never run out of if_pkts. We can't limit this to
   * max_in_flight_pkts because that limit is not applied to reliable
   * connections.
   */
  st->if_pkts_n = pp->pp_stats->allocated_bufs;
  uint64_t if_pkts_size =
    ALIGN_FWD(sizeof(struct sc_shm_broadcast_pkt_in_flight) *
              st->if_pkts_n, HUGE_PAGE_SZ);
  SC_TEST(posix_memalign((void**)&st->if_pkts, HUGE_PAGE_SZ,
                         if_pkts_size) == 0);
  unsigned i;
  for( i = 0 ; i < st->if_pkts_n ; i++) {
    st->if_pkts[i].if_id = i;
    st->if_pkts[i].if_packet = NULL;
    st->if_pkts[i].if_input = NULL;
    st->if_pkts[i].if_use_mask = 0;
    st->if_pkts[i].if_shared_mask = 0;
    sc_dlist_init(&st->if_pkts[i].if_link);
    sc_dlist_push_head(&st->if_pkt_free, &st->if_pkts[i].if_link);
  }

  /* Making sure we never run out of send_msg entries to queue. At most we
   * can have one per channel per if_pkt.
   *
   * TODO: Experiment with making this smaller. This is probably a lot more
   * than we actually need. When an unreliable connection is established, we
   * need at most max_in_flight_pkts_per_channel (with a bit of fuzz for tail
   * drops?).  If the connection is reliable, there can be more packets in
   * flight, but if we run out of send_msg entries, we just backpressure. So
   * the only risk of reducing this to (max_channels *
   * max_in_flight_pkts_per_channel) is that reliable connections can cause
   * backpressure earlier.
   */
  unsigned n_send_msgs = st->if_pkts_n * st->max_channels;
  unsigned msgs_size =
    ALIGN_FWD(n_send_msgs * sizeof(struct sc_shm_broadcast_msg_to_send),
              HUGE_PAGE_SZ);
  struct sc_shm_broadcast_msg_to_send* msgs;
  SC_TEST( posix_memalign((void**)&msgs, HUGE_PAGE_SZ, msgs_size) == 0 );
  for( i = 0; i < st->max_channels; i++ ) {
    unsigned j;
    st->ep_state[i].connection_id = -1;
    st->ep_state[i].drops = 0;
    st->ep_state[i].ep = sc_shm_endpoint_get(st->endpoints, i);
    st->ep_state[i].reserved_total = reserved_per_channel;
    sc_dlist_init(&st->ep_state[i].msg_to_send_free);
    for( j = 0 ; j < st->if_pkts_n ; j++) {
      struct sc_shm_broadcast_msg_to_send* msg = &msgs[i * st->if_pkts_n + j];
      sc_dlist_init(&msg->ms_link);
      sc_dlist_push_tail(&st->ep_state[i].msg_to_send_free, &msg->ms_link);
      ++st->ep_state[i].n_free_msgs;
    }
  }
}


static int
sc_shm_broadcast_input_prep(struct sc_node* node,
                            const struct sc_node_link*const* links,
                            int n_links)
{
  struct sc_shm_broadcast_input* bis = node->nd_private;
  struct sc_shm_broadcast_state* st = bis->shm_broadcast;
  struct sc_node_impl* ni;

  bis->next_hop = sc_node_prep_get_link_or_free(node, "");
  ni = SC_NODE_IMPL_FROM_NODE(node);
  /* There is exactly one incoming link per input_subnode since a new subnode
   * is created for each incoming link.
   */
  SC_TEST(ni->ni_n_incoming_links == 1);
  int pool_id = sc_bitmask_ffs(&ni->ni_src_pools) - 1;
  /* Only one incoming pool is currently supported. In the future we may
   * support multiple pools.
   */
  if( ! sc_bitmask_is_single_bit(&ni->ni_src_pools, pool_id) )
    return sc_node_set_error(node, EINVAL, "%s: ERROR: Only one buffer pool "
                             "can be exported from sc_shm_broadcast\n",
                             __func__);
  if( st->exported_pool_id == -1 ) {
    st->exported_pool_id = pool_id;
    struct sc_session* tg =
      sc_thread_get_session(sc_node_get_thread(st->node));
    struct sc_pkt_pool* pp = tg->tg_pkt_pools[st->exported_pool_id];
    struct sc_pkt_pool* buffer_pp = pp;
    while( buffer_pp->pp_linked_pool )
      buffer_pp = buffer_pp->pp_linked_pool;
    if( sc_pkt_pool_set_mmap_path(buffer_pp, st->buffer_fname) != 0 ) {
      free(st->buffer_fname);
      SC_TEST(sc_pkt_pool_get_mmap_path(buffer_pp, &st->buffer_fname) == 0);
    }
    st->endpoints = sc_shm_endpoints_create(st->mmap_fname_tmpl,
                                            st->max_channels);
    if( st->endpoints == NULL )
      return sc_node_set_error(st->node, EINVAL,
                               "%s: ERROR: could not create shared memory export at %s\n",
                               __func__, st->mmap_fname_tmpl);
    /* The buffer size may not be available yet, so we have to defer any work
     * that relies on that.
     */
    sc_callback_at_safe_time(st->post_prep_cb);
  }
  else if( st->exported_pool_id != pool_id ) {
    return sc_node_set_error(node, EINVAL, "%s: ERROR: Only one buffer pool "
                             "can be exported from sc_shm_broadcast\n",
                             __func__);
  }
  return 0;
}


static int
sc_shm_broadcast_input_init(struct sc_node* node,
                            const struct sc_attr* attr,
                            const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_pkts_fn = sc_shm_broadcast_input_pkts;
    nt->nt_prep_fn = sc_shm_broadcast_input_prep;
    nt->nt_end_of_stream_fn = sc_shm_broadcast_input_eos;
  }
  struct sc_shm_broadcast_input* bis;
  bis = sc_thread_calloc(sc_node_get_thread(node), sizeof(*bis));
  node->nd_private = bis;
  node->nd_type = nt;
  bis->node = node;
  SC_TRY(sc_callback_alloc(&bis->timed_handle_cb, attr,
                           sc_node_get_thread(node)));
  bis->timed_handle_cb->cb_private = bis;
  bis->timed_handle_cb->cb_handler_fn =
    sc_shm_broadcast_input_timed_cb;

  sc_packet_list_init(&bis->backlog);
  bis->eos = EOS_NO;
  return 0;
}


const struct sc_node_factory sc_shm_broadcast_input_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_shm_broadcast_input",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_shm_broadcast_input_init,
};

/** \endcond NODOC */
