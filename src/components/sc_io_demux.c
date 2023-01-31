/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \internal
 * \node{sc_io_demux}
 *
 * \brief This node can be used to create and send messages over Unix domain
 * sockets.
 *
 * \nodedetails
 * This node can be used to create and send messages over Unix domain
 * sockets. Messages sent and received over sockets are converted into
 * specially formatted ::sc_packet objects for use by other solar capture nodes.
 *
 * Messages sent over the socket consist of a uint32_t number specifying the
 * length of the message followed by a 16 byte field for the link name the message
 * was received on and then finally the message. If the number of characters in
 * the link name is less than 16 this field will be padded with nul characters.
 *
 * Messages can be sent and received from \noderef{sc_io_demux} using ::sc_packet objects.
 * This can be done in RAW or DATA modes. Edges prefixed with "data:" expect and
 * send packets with a single iov containing the data to send and no message header.
 * In this mode all data is sent out of the first connected socket to \noderef{sc_io_demux}.
 *
 * In RAW mode packets must be formatted using the ::sc_io_msg_hdr
 * struct. Packets coming in and out a RAW edge must all have a single iov, containing
 * a struct ::sc_io_msg_hdr, maybe followed by data. The header specifies a unique
 * id identifying the socket the message applies to, and the message
 * type which is one of:
 *
 * - SC_IO_MSG_NEW_CONN: The node outputs a message of this type each time a new
 *   connection is established (either active or passive). Users must not inject
 *   messages of this type.
 *
 *  - SC_IO_MSG_DATA: Data to/from a socket. The node outputs these when data is
 *  received; users may inject them to send data. This is the only message type
 *  which can be followed by data.
 *
 *  - SC_IO_MSG_CLOSE: The node outputs this when the remote side closes a
 *  socket; users may inject them to trigger a local close.
 *
 * \nodeargs
 * Argument           | Optional? | Default    | Type           | Description
 * ------------------ | --------- | ---------- | -------------- | ----------------------------------------------------------------------------------------------------
 * reconnect          | Yes       | 1          | ::SC_PARAM_INT | Specifies if on disconnection from a socket if the node should attempt to reconnect. If set to try and reconnect this will be attempted indefinitely
 * listen             | Yes       | NULL       | ::SC_PARAM_STR | A socket this node should create and listen for connections on.
 * connect            | Yes       | NULL       | ::SC_PARAM_STR | An existing socket this node should connect to.
 * fd                 | Yes       | -1         | ::SC_PARAM_INT | Send/recv data on this existing FD
 * error_mode         | Yes       | disconnect | ::SC_PARAM_STR | Behaviour of the node on connection error, can be "disconnect" or "exit".
 *
 * NOTE: At least one of connect and listen must be defined.
 *
 * \namedinputlinks
 * None
 *
 * \outputlinks
 * Link | Description
 * ---- |----------------------------------------------------------------------------
 * ""   | All packets received on the listen socket are sent down this link in the format outlined above.
 *
 * \cond NODOC
 */

#include <sc_internal.h>
#include <sc_internal/builtin_nodes.h>
#include <sc_internal/io.h>
#include <solar_capture/nodes/subnode_helper.h>
#include <solar_capture/pkt_pool.h>
#include <errno.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <inttypes.h>


#define RECONNECT_TIMER 1000000000ULL
#define TIMEOUT 3

enum error_mode {DISCONNECT, EXIT};


struct sc_io_demux_conn {
  bool                   used;
  struct sc_node*        node;
  int                    fd;
  int                    connection_id;
  struct sc_callback*    cb;
  char*                  buffer;
  int                    buffer_fill;
  char*                  path;
  bool                   listen;
  bool                   reconnect;

  /* epoll events we want callbacks for */
  int                    desired_events;

  /* epoll events that are safe when pool is low */
  int                    event_mask;

  /* epoll events we're actually getting callbacks for.
   *   When pool full, equal to desired_events
   *   When pool low, equal to (desired_events & event_mask) */
  int                    current_events;

  struct sc_packet_list  send_backlog;
  int                    send_offset;
  bool                   close_pending;
  struct socket_msg      msg_header;
};


struct sc_io_link_pair;


struct sc_io_demux {
  struct sc_node*            node;

  struct sc_io_link_pair*    pairs;
  int                        pairs_n;

  int                        max_msg_size;
  int                        reconnect;
  char                       delimiter;

  struct sc_pool*            pool;
  struct sc_attr*            pool_attr;
  struct sc_callback*        pool_cb;

  struct sc_io_demux_conn**  conns;
  int                        conns_n;
  bool                       pool_low;
  int                        last_conn_uid;

  enum error_mode            error_mode;
};


enum link_type {DATA, RAW};


struct sc_io_link_pair {
  struct sc_subnode_helper*   sh;
  struct sc_io_demux*         dm;
  char                        link_name[LINKMAX + 1]; /* space for nul */
  const struct sc_node_link*  out_link;
  enum link_type              type;
};

static void sc_io_demux_conn_drain_buffer(struct sc_io_demux_conn* conn);
static void sc_io_demux_try_connect(struct sc_callback* cb, void* event_info);
static void sc_io_demux_conn_close(struct sc_io_demux_conn* conn, char* reason);
static void sc_io_demux_epoll_check_pool(struct sc_io_demux* dm);
static void sc_io_demux_conn_epoll_set_events(struct sc_io_demux_conn*, int);

/******************************************************************************
 * Helper functions
 *****************************************************************************/

/* Helper function to extract a socket path from node argument */
static int get_conn_string(struct sc_node* node, const char* key,
                           const char** target)
{
  const char* prefix = "unix:";
  unsigned int prefix_len = strlen(prefix);
  const char* conn_string;

  if( sc_node_init_get_arg_str(&conn_string, node, key, NULL) < 0 )
    return -1;
  if( conn_string == NULL ) {
    *target = NULL;
    return 0;
  }

  if( strncmp(prefix, conn_string, prefix_len) != 0 ||
      strlen(conn_string) <= prefix_len )
    return sc_node_set_error(node, EINVAL,
                             "%s: ERROR: Bad connection string '%s'\n",
                             __func__, conn_string);
  *target = conn_string + prefix_len;
  return 0;
}


/* Helper function to populate a sockaddr to which we can bind a socket */
static void populate_sockaddr(const char* path, struct sockaddr_un* addr)
{
  SC_TEST(strlen(path) < sizeof(addr->sun_path));
  memset(addr, 0, sizeof(*addr));
  strncpy(addr->sun_path, path, sizeof(addr->sun_path) - 1);
  addr->sun_family = AF_UNIX;
}


/* Helper function to find a pair with the specified link name */
static struct sc_io_link_pair* find_pair(struct sc_io_demux* dm,
                                         const char* link_name)
{
  int i;
  for( i = 0; i < dm->pairs_n; ++i )
    if( !strcmp(dm->pairs[i].link_name, link_name) )
      return &dm->pairs[i];
  return NULL;
}


/* Helper function to strip a link type prefix from a link name */
static enum link_type strip_proto(const char* name, const char** no_proto_name)
{
  *no_proto_name = name;
  if( !strncmp(name, SC_IO_LINK_DATA_PREFIX, strlen(SC_IO_LINK_DATA_PREFIX)) ) {
    *no_proto_name += strlen(SC_IO_LINK_DATA_PREFIX);
    return DATA;
  }
  return RAW;
}


/* Helper function to parse the error mode requested by the user */
static int get_error_mode(const char* error_mode)
{
  if( !strcmp("exit", error_mode) )
    return EXIT;
  if( !strcmp("disconnect", error_mode) )
    return DISCONNECT;
  return -1;
}


/******************************************************************************
 * sc_io_demux message and packet processing functions
 *****************************************************************************/

/* Forwards a data or control message on an outgoing link.
 * Data messages are sent in response to data arriving on the socket
 * Control messages are sent in response to sockets opening or closing */
static void sc_io_demux_forward(struct sc_io_demux* dm, struct sc_packet* pkt,
                                int connection_id, enum sc_io_msg_type msg_type,
                                struct sc_io_link_pair* pair, void* data,
                                int data_len)
{
  struct sc_session* tg = sc_thread_get_session(sc_node_get_thread(dm->node));
  sc_trace(tg, "%s: link=%s connection_id=%d type=%d len=%d msg='%.*s'\n", __func__,
           pair->link_name, connection_id, msg_type, data_len, data_len, (char*)data);

  uint8_t* data_ptr = pkt->iov[0].iov_base;
  pkt->iov[0].iov_len = data_len;
  if( pair->type == RAW ) {
    struct sc_io_msg_hdr* hdr = pkt->iov[0].iov_base;
    hdr->connection_id = connection_id;
    hdr->msg_type = msg_type;
    data_ptr += sizeof(*hdr);
    pkt->iov[0].iov_len += sizeof(*hdr);
  }
  pkt->frame_len = pkt->iov[0].iov_len;

  if( data_len )
    memcpy(data_ptr, data, data_len);
  sc_forward(dm->node, pair->out_link, pkt);
}


/* Pulls a packet from the pool. It is an error to call this
 * without first checking that the pool has buffers available. */
static struct sc_packet* sc_io_demux_get_pkt(struct sc_io_demux* dm)
{
  struct sc_packet_list pl;
  __sc_packet_list_init(&pl);
  SC_TEST( sc_pool_get_packets(&pl, dm->pool, 1, 1) == 1 );
  return pl.head;
}


/* Returns True if the pool fill level is too low to handle one
 * epoll callback. */
static inline int sc_io_demux_pool_low(struct sc_io_demux* dm)
{
  /* The worst case pool usage is when we have to broadcast a
   * connect or disconnect message on all outgoing links */
  return sc_pool_available_bufs(dm->pool) < dm->pairs_n;
}


static inline void __sc_io_demux_schedule_pool_cb(struct sc_io_demux* dm)
{
  sc_pool_on_threshold(dm->pool, dm->pool_cb, dm->pairs_n);
}

/* Disables epoll callbacks and schedules a callback once the pool
 * fill level has recovered. */
static inline void sc_io_demux_schedule_pool_cb(struct sc_io_demux* dm)
{
  sc_io_demux_epoll_check_pool(dm);
  __sc_io_demux_schedule_pool_cb(dm);
}


/* Called when the pool fills up after getting low. */
static void sc_io_demux_pool_cb(struct sc_callback* cb, void* event_info)
{
  struct sc_io_demux* dm = cb->cb_private;
  struct sc_session* tg = sc_thread_get_session(sc_node_get_thread(dm->node));
  int i;
  sc_trace(tg, "%s\n", __func__);

  for( i = 0; i < dm->conns_n; ++i ) {
    struct sc_io_demux_conn* conn = dm->conns[i];
    if( conn->close_pending && sc_packet_list_is_empty(&conn->send_backlog) ) {
      sc_io_demux_conn_close(conn, "local close requested");
      if( sc_io_demux_pool_low(dm) )
        return; /* pool low again! */
    }
    sc_io_demux_conn_drain_buffer(conn);
    if( sc_io_demux_pool_low(dm) )
      return; /* pool low again! */
  }

  sc_io_demux_epoll_check_pool(dm);
}


/* Attempts to drain a connection's receive buffer.
 * Will return with data still in the buffer if:
 *   1. There is an incomplete message in the buffer
 *   2. The pool runs dry while draining the buffer
 *
 * If it finds an invalid message (overlength or bad link name)
 * this function will either exit() or close the socket based on
 * the node's error_mode.
 */
static void sc_io_demux_conn_drain_buffer(struct sc_io_demux_conn* conn)
{
  struct sc_io_demux* dm = conn->node->nd_private;
  struct sc_session* tg = sc_thread_get_session(sc_node_get_thread(dm->node));
  char* msg = conn->buffer;
  char* error = NULL;
  struct socket_msg* hdr;
  char link_name[LINKMAX + 1];

  while( conn->buffer_fill > 0) {
    if( sc_io_demux_pool_low(dm) )
      break;

    hdr = (void*) msg;

    if( conn->buffer_fill < sizeof(*hdr) )
      break; /* Incomplete header */

    strncpy(link_name, hdr->link_name, LINKMAX);
    link_name[LINKMAX] = '\0';
    struct sc_io_link_pair* pair = find_pair(dm, link_name);
    if( pair == NULL ) {
      error = "Bad link name";
      break;
    }

    int msg_len = sizeof(*hdr) + hdr->msg_length;
    if( msg_len > conn->buffer_fill ) {
      if( msg_len > dm->max_msg_size )
        error = "Overlength message";
      break; /* Incomplete payload */
    }

    struct sc_packet* pkt = sc_io_demux_get_pkt(dm);

    sc_io_demux_forward(dm, pkt, conn->connection_id, SC_IO_MSG_DATA,
                        pair, hdr->msg, hdr->msg_length);
    msg += msg_len;
    conn->buffer_fill -= msg_len;
  }

  if( error ) {
    if( dm->error_mode == EXIT ) {
            sc_err(tg, "%s: ERROR: %s (link_name='%s' msg_length=%d)\n",
                   __func__, error, link_name, hdr->msg_length);
      exit(1);
    }
    sc_io_demux_conn_close(conn, error);
  }
  else {
    memmove(conn->buffer, msg, conn->buffer_fill);
  }
  if( sc_io_demux_pool_low(dm) )
    sc_io_demux_schedule_pool_cb(dm);
}


/* Called when epoll indicates that a connected socket has become
 * readable. This indicates that either there is data waiting, or
 * the socket has been closed.
 */
static void sc_io_demux_do_recv(struct sc_io_demux_conn* conn)
{
  struct sc_io_demux* dm = conn->node->nd_private;
  struct sc_session* tg = sc_thread_get_session(sc_node_get_thread(dm->node));
  char* buf = conn->buffer + conn->buffer_fill;

  SC_TEST(dm->max_msg_size - conn->buffer_fill > 0);
  ssize_t n_bytes = recv(conn->fd, buf, dm->max_msg_size - conn->buffer_fill,
                     MSG_DONTWAIT);
  sc_trace(tg, "%s: recv(fd=%d) rc=%zd\n", __func__, conn->fd, n_bytes);
  if( n_bytes <= 0 ) {
    char reason[13] = "remote close";
    if( n_bytes < 0 )
      snprintf(reason, 13, "errno=%d", errno);
    sc_trace(tg, "%s: Closing connection recv(fd=%d) rc=%zd errno=%d\n",
         __func__, conn->fd, n_bytes, errno);
    sc_io_demux_conn_close(conn, reason);
    return;
  }
  conn->buffer_fill += n_bytes;
  sc_io_demux_conn_drain_buffer(conn);
}


/* Called when epoll indicates that a socket has become writable. */
static void sc_io_demux_do_send(struct sc_io_demux_conn* conn)
{
  struct sc_session* tg = sc_thread_get_session(sc_node_get_thread(conn->node));
  struct sc_packet* pkt = conn->send_backlog.head;
  size_t send_len;
  char* send_base;
  /* send_offset starts at -header_len; once we've sent the header it is 0;
   * once we've sent the payload it is pkt->iov[0].iov_len */
  if( conn->send_offset < 0 ) { /* sending header */
    struct socket_msg* hdr = &conn->msg_header;
    send_base = (char*)(hdr + 1);
    send_len = -conn->send_offset;
  }
  else { /* sending payload */
    send_base = (char*) pkt->iov[0].iov_base;
    send_len = pkt->iov[0].iov_len - conn->send_offset;
  }
  int n_bytes = send(conn->fd, send_base + conn->send_offset, send_len, 0);
  if( n_bytes < 0 ) { /* signal or closed socket; do_recv handles the latter */
    if( errno != EINTR && errno != EPIPE && errno != ECONNRESET )
      sc_info(tg, "%s: send rc=%d errno=%d\n", __func__, n_bytes, errno);
    SC_TEST( errno == EINTR || errno == EPIPE || errno == ECONNRESET );
    sc_trace(tg, "%s: rc=%d errno=%d\n", __func__, n_bytes, errno);
  }
  else {
    conn->send_offset += n_bytes;
    if( conn->send_offset == pkt->iov[0].iov_len ) {
      struct sc_io_link_pair* pair = (void*) pkt->metadata;
      sc_forward(pair->sh->sh_node, pair->sh->sh_free_link,
                 sc_packet_list_pop_head(&conn->send_backlog));
      if( sc_packet_list_is_empty(&conn->send_backlog) ) {
        sc_io_demux_conn_epoll_set_events(conn, EPOLLIN);
      }
      else {
        conn->send_offset = -((int) sizeof(conn->msg_header));
        pair = (void*) conn->send_backlog.head->metadata;
        conn->msg_header.msg_length = conn->send_backlog.head->iov[0].iov_len;
        memcpy(conn->msg_header.link_name, pair->link_name,
               sizeof(conn->msg_header.link_name));
      }
    }
  }
}


/* Called when a connected socket becomes readable or writable*/
static void sc_io_demux_data_cb(struct sc_callback* cb, void* event_info)
{
  struct sc_io_demux_conn* conn = cb->cb_private;
  struct sc_io_demux* dm = conn->node->nd_private;
  uintptr_t events = (uintptr_t) event_info;

  if( events & EPOLLIN && ! conn->close_pending ) {
    sc_io_demux_do_recv(conn);
    if( conn->fd < 0 ) /* We closed the connection inside do_recv */
      return;
  }

  if( events & EPOLLOUT )
    sc_io_demux_do_send(conn);

  if( conn->close_pending && sc_packet_list_is_empty(&conn->send_backlog) &&
      ! sc_io_demux_pool_low(dm) )
    sc_io_demux_conn_close(conn, "local close requested");
}


/******************************************************************************
 * sc_io_demux epoll setup
 *****************************************************************************/


static void sc_io_demux_conn_epoll_set_events(struct sc_io_demux_conn* conn,
                                              int events)
{
  struct sc_io_demux* dm = conn->node->nd_private;
  conn->desired_events = events;

  if( dm->pool_low )
    events &= conn->event_mask;

  if( conn->current_events == events )
    return;

  int op = conn->current_events
    ? (events ? EPOLL_CTL_MOD : EPOLL_CTL_DEL)
    : EPOLL_CTL_ADD;

  conn->current_events = events;

  SC_TRY( sc_epoll_ctl(sc_node_get_thread(dm->node), op,
                       conn->fd, events, conn->cb) );
}


/* Checks the pool fill level and enables or disables
 * any epoll callbacks that need a non-low pool */
static void sc_io_demux_epoll_check_pool(struct sc_io_demux* dm)
{
  int i;
  dm->pool_low = sc_io_demux_pool_low(dm);

  for( i = 0; i < dm->conns_n; ++i )
    sc_io_demux_conn_epoll_set_events(dm->conns[i],
                                      dm->conns[i]->desired_events);
}


/******************************************************************************
 * sc_io_demux connection management
 ******************************************************************************/

/* Forwards a control message on every outgoing link, with the
 * exception of data-only links which do not expect to receive
 * control messages.
 *
 * It is an error to call this function if the pool is low
 * (as reported by sc_io_demux_pool_low).
 */
static void sc_io_demux_broadcast_conn_msg(struct sc_io_demux_conn* conn,
                                           enum sc_io_msg_type msg_type,
                                           void* data, int data_len)
{
  struct sc_io_demux* dm = conn->node->nd_private;
  int i;

  for( i = 0; i < dm->pairs_n; ++i)
    if( dm->pairs[i].type == RAW )
      sc_io_demux_forward(dm, sc_io_demux_get_pkt(dm), conn->connection_id,
                          msg_type, &dm->pairs[i], data, data_len);

  if( sc_io_demux_pool_low(dm) )
    sc_io_demux_schedule_pool_cb(dm);
}


/* Allocate a struct to hold the state of a new connection */
static struct sc_io_demux_conn* sc_io_demux_conn_alloc(struct sc_io_demux* dm)
{
  int i;
  struct sc_io_demux_conn* conn = NULL;
  for( i = 0; i < dm->conns_n; ++i ) {
    if( ! dm->conns[i]->used ) {
      conn = dm->conns[i];
      break;
    }
  }
  if( conn == NULL ) {
    dm->conns = realloc(dm->conns, sizeof(*conn) * ++dm->conns_n);
    conn = calloc(1, sizeof(*conn));
    dm->conns[dm->conns_n - 1] = conn;
    conn->fd = -1;
    conn->node = dm->node;

    struct sc_attr* attr;
    SC_TRY(sc_attr_alloc(&attr));
    SC_TRY(sc_callback_alloc(&conn->cb, attr, sc_node_get_thread(conn->node)));
    sc_attr_free(attr);
    conn->cb->cb_private = conn;
    if( dm->max_msg_size > 0 )
      conn->buffer = malloc(dm->max_msg_size);
  }
  conn->used = true;
  conn->connection_id = ++dm->last_conn_uid;
  sc_packet_list_init(&conn->send_backlog);
  sc_trace(sc_thread_get_session(sc_node_get_thread(dm->node)),
      "%s: new connection alloc with id %d\n", __func__, conn->connection_id);
  return conn;
}


/* Helper function to locate the connection with this ID */
static struct sc_io_demux_conn* sc_io_demux_conn_find(struct sc_io_demux* dm,
                                                      int connection_id)
{
  /* NOTE: This approach is slow; for now we don't care about
   * performance but should handle this better if we ever do
   */
  int i;
  for( i = 0; i < dm->conns_n; ++i )
    if( dm->conns[i]->connection_id == connection_id && dm->conns[i]->used )
      return dm->conns[i];
  return NULL;
}


/* Helper function to locate any connection which is ready to send/recv data*/
static struct sc_io_demux_conn* sc_io_demux_conn_find_any(struct sc_io_demux* dm)
{
  /* NOTE: This approach is slow; for now we don't care about
   * performance but should handle this better if we ever do
   */
  int i;
  for( i = 0; i < dm->conns_n; ++i ) {
    struct sc_io_demux_conn* conn = dm->conns[i];
    if( conn->used && conn->cb->cb_handler_fn == sc_io_demux_data_cb )
      return conn;
  }
  return NULL;
}


/* Frees a connection object returned by sc_io_demux_conn_alloc */
static void sc_io_demux_conn_free(struct sc_io_demux_conn* conn)
{
  SC_TEST(conn->fd < 0);
  SC_TEST(conn->desired_events == 0);
  conn->used = false;
  conn->listen = false;
  conn->reconnect = false;
  if( conn->path != NULL )
    free(conn->path);
}


/* Called once a connection has closed; frees or reinitialises
 * it depending on whether the user requested reconnection */
static void sc_io_demux_conn_lost(struct sc_io_demux_conn* conn)
{
  SC_TEST(conn->fd >= 0);
  sc_io_demux_conn_epoll_set_events(conn, 0);
  conn->event_mask = 0;
  close(conn->fd);
  while( ! sc_packet_list_is_empty(&conn->send_backlog) ) {
    struct sc_packet* pkt = sc_packet_list_pop_head(&conn->send_backlog);
    struct sc_io_link_pair* pair = (void*) pkt->metadata;
    sc_forward(pair->sh->sh_node, pair->sh->sh_free_link, pkt);
  }
  conn->buffer_fill = 0;
  conn->close_pending = false;
  conn->fd = -1;
  if( conn->reconnect ) {
    conn->cb->cb_handler_fn = sc_io_demux_try_connect;
    sc_timer_expire_after_ns(conn->cb, RECONNECT_TIMER);
  }
  else {
    sc_io_demux_conn_free(conn);
  }
}


/* Closes an open connection. The other end of the connection may or
 * may not have already closed its end. */
static void sc_io_demux_conn_close(struct sc_io_demux_conn* conn, char* reason)
{
  struct sc_io_demux* dm = conn->node->nd_private;
  struct sc_session* tg = sc_thread_get_session(sc_node_get_thread(dm->node));
  SC_TEST(conn->fd >= 0);
  sc_io_demux_broadcast_conn_msg(conn, SC_IO_MSG_CLOSE, reason, strlen(reason));
  sc_io_demux_conn_epoll_set_events(conn, 0);
  sc_trace(tg, "%s: closed fd=%d (reason='%s')\n", __func__, conn->fd, reason);
  sc_io_demux_conn_lost(conn);
}


/* Called when a connection is ready to send/receive data */
static void sc_io_demux_conn_ready(struct sc_io_demux_conn* conn)
{
  struct sc_io_demux* dm = conn->node->nd_private;
  conn->cb->cb_handler_fn = sc_io_demux_data_cb;
  conn->event_mask = EPOLLOUT; /* We can send but not recv when pool is low */
  sc_io_demux_conn_epoll_set_events(conn, EPOLLIN);
  sc_io_demux_broadcast_conn_msg(conn, SC_IO_MSG_NEW_CONN, NULL, 0);
  int i;
  for( i = 0; i < dm->pairs_n; ++i) {
    struct sc_io_link_pair* pair = &dm->pairs[i];
    if( ! sc_packet_list_is_empty(&pair->sh->sh_backlog) )
      pair->sh->sh_handle_backlog_fn(pair->sh);
  }
}


/* Called when a listening socket becomes readable */
static void sc_io_demux_accept_cb(struct sc_callback* cb, void* event_info)
{
  struct sc_io_demux_conn* conn = cb->cb_private;
  struct sc_io_demux* dm = conn->node->nd_private;
  struct sc_session* tg = sc_thread_get_session(sc_node_get_thread(dm->node));

  int fd = accept(conn->fd, NULL, NULL);
  sc_trace(tg, "%s: accept(listen_fd=%d, path=%s) fd=%d errno=%d\n",
           __func__, conn->fd, conn->path, fd, errno);
  if( fd < 0 )
    return;

  struct sc_io_demux_conn* new_conn = sc_io_demux_conn_alloc(dm);
  new_conn->fd = fd;
  sc_io_demux_conn_ready(new_conn);
}

/* Called when a socket becomes writable after a nonblocking connect */
static void sc_io_demux_connect_cb(struct sc_callback* cb, void* event_info)
{
  struct sc_io_demux_conn* conn = cb->cb_private;
  struct sc_io_demux* dm = conn->node->nd_private;
  struct sc_session* tg = sc_thread_get_session(sc_node_get_thread(dm->node));
  int rc, result;
  socklen_t result_len = sizeof(result);

  rc = getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &result, &result_len);
  sc_trace(tg, "%s: getsockopt(fd=%d, path=%s, connection_id=%d) rc=%d errno=%d result=%d\n",
           __func__, conn->fd, conn->path, conn->connection_id, rc, errno, result);
  if( rc < 0 || result != 0 )
    sc_io_demux_conn_lost(conn);
  else
    sc_io_demux_conn_ready(conn);
}


/* Called at start of day to connect to a socket, or later to reconnect after
 * being disconnected or failing to connect */
static void sc_io_demux_try_connect(struct sc_callback* cb, void* event_info)
{
  struct sc_io_demux_conn* conn = cb->cb_private;
  struct sc_io_demux* dm = conn->node->nd_private;
  struct sc_session* tg = sc_thread_get_session(sc_node_get_thread(dm->node));
  if( conn->fd < 0 ) {
    conn->fd = socket(AF_UNIX, SOCK_STREAM, 0);
    SC_TEST(conn->fd >= 0);
    int flags = fcntl(conn->fd, F_GETFL);
    SC_TEST(flags >= 0);
    SC_TEST(fcntl(conn->fd, F_SETFL, flags | O_NONBLOCK) >= 0);
  }

  struct sockaddr_un addr;
  populate_sockaddr(conn->path, &addr);

  int rc = connect(conn->fd, (struct sockaddr*) &addr, sizeof(addr));
  sc_trace(tg, "%s: connect(fd=%d path=%s) rc=%d errno=%d\n",
           __func__, conn->fd, conn->path, rc, errno);

  if( rc == 0 || errno == EINPROGRESS ) {
    /* NOTE: we could skip this step in the immediate success
     * case but it would complicate the code for little gain */
    sc_io_demux_conn_epoll_set_events(conn, EPOLLOUT);
    conn->cb->cb_handler_fn = sc_io_demux_connect_cb;
  }
  else if( errno == EAGAIN ) {
    sc_info(tg, "INFO: %s: %s busy, retrying\n", __func__, conn->path);
    sc_timer_expire_after_ns(conn->cb, RECONNECT_TIMER);
  }
  else {
    if( dm->error_mode == EXIT )
      sc_err(tg, "ERROR: %s: Failed to connect to %s (%d, %s)\n", __func__,
             conn->path, errno, strerror(errno));
    else
      sc_warn(tg, "WARNING: %s: Failed to connect to %s (%d, %s)\n", __func__,
                 conn->path, errno, strerror(errno));

    sc_io_demux_conn_lost(conn);

    if( dm->error_mode == EXIT )
      exit(1);
  }
}

/* Called at start of day to set up a listening socket */
static void sc_io_demux_try_listen(struct sc_callback* cb, void* event_info)
{
  struct sc_io_demux_conn* conn = cb->cb_private;
  struct sc_io_demux* dm = conn->node->nd_private;
  struct sc_session* tg = sc_thread_get_session(sc_node_get_thread(dm->node));
  struct sockaddr_un addr;

  SC_TEST(conn->fd < 0);
  conn->fd = socket(AF_UNIX, SOCK_STREAM, 0);
  SC_TEST(conn->fd >= 0);
  populate_sockaddr(conn->path, &addr);

  if( unlink(conn->path) < 0 && errno != ENOENT ) {
    sc_trace(tg, "%s: Failed to unlink '%s' (errno=%d)\n",
             __func__, conn->path, errno);
    sc_io_demux_conn_lost(conn);
    return;
  }

  if( bind(conn->fd, (struct sockaddr*) &addr, sizeof(addr)) < 0 ) {
    sc_trace(tg, "%s: Failed to bind to '%s' (fd=%d errno=%d)\n",
             __func__, conn->path, conn->fd, errno);
    sc_io_demux_conn_lost(conn);
    return;
  }

  if( listen(conn->fd, 5) < 0 ) {
    sc_trace(tg, "%s: Failed to listen on '%s' (fd=%d, errno=%d)\n",
             __func__, conn->path, conn->fd, errno);
    sc_io_demux_conn_lost(conn);
    return;
  }

  conn->cb->cb_handler_fn = sc_io_demux_accept_cb;
  sc_io_demux_conn_epoll_set_events(conn, EPOLLIN);
}


/* Called at start of day when a connected FD is passed into the node. */
static void sc_io_demux_register_fd(struct sc_callback* cb,  void* event_info)
{
  sc_io_demux_conn_ready(cb->cb_private);
}


/******************************************************************************
 * Incoming packet handler
 *****************************************************************************/

/* Queues up a packet to be sent up over this socket when possible. */
static inline void sc_io_demux_queue_send(struct sc_io_demux_conn* conn,
                                          struct sc_io_link_pair* pair,
                                          struct sc_packet* pkt)
{
  pkt->metadata = (void*) pair;
  if( sc_packet_list_is_empty(&conn->send_backlog) ) {
    conn->send_offset = -((int) sizeof(conn->msg_header));
    conn->msg_header.msg_length = pkt->iov[0].iov_len;
    memcpy(conn->msg_header.link_name, pair->link_name,
           sizeof(conn->msg_header.link_name));
    sc_io_demux_conn_epoll_set_events(conn, EPOLLIN | EPOLLOUT);
  }
  sc_packet_list_append(&conn->send_backlog, pkt);
}


/* Called when packet(s) arrive on a data-only link */
static void sc_io_demux_data_only_pkt_handler(struct sc_subnode_helper* sh)
{
  struct sc_io_link_pair* pair = sh->sh_private;
  struct sc_thread* thread = sc_node_get_thread(pair->dm->node);
  struct sc_session* tg = sc_thread_get_session(thread);

  struct sc_io_demux_conn* conn = sc_io_demux_conn_find_any(pair->dm);
  if( conn == NULL || conn->close_pending )
    return; /* sc_io_demux_conn_ready will call us back */

  while( ! sc_packet_list_is_empty(&sh->sh_backlog) ) {
    struct sc_packet* pkt = sc_packet_list_pop_head(&sh->sh_backlog);
    SC_TEST( pkt->iovlen == 1);
    sc_trace(tg, "%s: fd=%d len=%ld link=%s\n", __func__, conn->fd,
             pkt->iov[0].iov_len, pair->link_name);
    sc_io_demux_queue_send(conn, pair, pkt);
  }
}


/* Called when packet(s) arrive on a regular (raw) link */
static void sc_io_demux_pkt_handler(struct sc_subnode_helper* sh)
{
  struct sc_io_link_pair* pair = sh->sh_private;
  struct sc_thread* thread = sc_node_get_thread(pair->dm->node);
  struct sc_session* tg = sc_thread_get_session(thread);
  struct sc_packet* pkt;
  struct sc_io_demux_conn* conn;

  while( ! sc_packet_list_is_empty(&sh->sh_backlog) ) {
    pkt = sc_packet_list_pop_head(&sh->sh_backlog);
    struct sc_io_msg_hdr* hdr = pkt->iov[0].iov_base;
    int data_len = pkt->iov[0].iov_len - sizeof(*hdr);

    if( data_len < 0 ) {
      sc_trace(tg, "%s: Undersized msg header len=%ld\n",
               __func__, pkt->iov[0].iov_len);
      sc_forward(pair->sh->sh_node, sh->sh_free_link, pkt);
      continue;
    }

    conn = sc_io_demux_conn_find(pair->dm, hdr->connection_id);
    if( conn == NULL ) {
      sc_trace(tg, "%s: Unknown connection_id=%d\n", __func__,
               hdr->connection_id);
      sc_forward(pair->sh->sh_node, sh->sh_free_link, pkt);
      continue;
    }

    if( conn->close_pending) {
      sc_trace(tg, "%s: Discarding packet to close-pending connection %d\n",
               __func__, conn->connection_id);
      sc_forward(pair->sh->sh_node, sh->sh_free_link, pkt);
      continue;
    }

    if( hdr->msg_type == SC_IO_MSG_DATA ) {
      /* Update iov_base to skip msg hdr, which doesn't go over the socket */
      pkt->iov[0].iov_base = (void*)(hdr + 1);
      pkt->iov[0].iov_len -= sizeof(*hdr);
      sc_io_demux_queue_send(conn, pair, pkt);
      sc_trace(tg, "%s: connection_id=%d type=%d len=%d link=%s\n", __func__,
               hdr->connection_id, hdr->msg_type, data_len, pair->link_name);
    }

    else if( hdr->msg_type == SC_IO_MSG_CLOSE ) {
      conn->close_pending = true;
      if( sc_packet_list_is_empty(&conn->send_backlog) )
        __sc_io_demux_schedule_pool_cb(pair->dm);
      sc_forward(pair->sh->sh_node, sh->sh_free_link, pkt);
    }

    else {
      sc_trace(tg, "%s: Invalid msg header type=%d len=%ld\n",
               __func__, hdr->msg_type, pkt->iov[0].iov_len);
      sc_forward(pair->sh->sh_node, sh->sh_free_link, pkt);
    }
  }
}


/******************************************************************************
 * sc_io_demux start of day
 *****************************************************************************/

static struct sc_node* sc_io_demux_select_subnode(struct sc_node* node,
                                                  const char* name,
                                                  char** new_name_out)
{
  if( name == NULL )
    name = "";

  if( strlen(name) > LINKMAX )
  {
    sc_node_set_error(node, EINVAL, "%s: ERROR: Link name %s > %d characters", __func__, name, LINKMAX);
    return NULL;
  }

  struct sc_io_demux* dm = node->nd_private;

  /* strip data: from name for searching */
  const char* no_proto_name;
  enum link_type type = strip_proto(name, &no_proto_name);
  struct sc_io_link_pair* pair = find_pair(dm, no_proto_name);
  if( pair == NULL ) {
    int i;
    dm->pairs = realloc(dm->pairs, sizeof(*dm->pairs) * ++dm->pairs_n);
    for( i = 0; i < dm->pairs_n - 1; ++i ) /* realloc breaks sh pointers */
      dm->pairs[i].sh->sh_private = &dm->pairs[i];
    pair = &dm->pairs[dm->pairs_n - 1];
    struct sc_attr* attr;
    struct sc_node* subnode;
    SC_TRY(sc_attr_alloc(&attr));
    sc_attr_set_from_fmt(attr, "name", "%s.%s", node->nd_name, name);
    int rc = sc_node_alloc(&subnode, attr, sc_node_get_thread(node),
                           &sc_subnode_helper_sc_node_factory, NULL, 0);
    sc_attr_free(attr);
    if( rc < 0 ) {
      sc_node_fwd_error(node, rc);
      return NULL;
    }
    pair->sh = sc_subnode_helper_from_node(subnode);
    pair->sh->sh_private = pair;
    strcpy(pair->link_name, no_proto_name);
    pair->dm = dm;
    pair->out_link = NULL;
    pair->type = type;
    if( pair->type == DATA )
      pair->sh->sh_handle_backlog_fn = sc_io_demux_data_only_pkt_handler;
    else
      pair->sh->sh_handle_backlog_fn = sc_io_demux_pkt_handler;
  }
  else {
    if( pair->type != type ) {
      sc_node_set_error(node, EINVAL ,"ERROR: %s: Cannot have data: and raw links"
                        " with the same node (link name %s)\n", __func__, no_proto_name);
      return NULL;
    }
  }
  return pair->sh->sh_node;
}


static int sc_io_demux_prep(struct sc_node* node,
                            const struct sc_node_link*const* links, int n_links)
{
  struct sc_io_demux* dm = node->nd_private;
  struct sc_io_link_pair* pair;
  int i;
  const char* no_proto_name;
  enum link_type type;
  for( i = 0; i < n_links; ++i ) {
    type = strip_proto(links[i]->name, &no_proto_name);
    if( (pair = find_pair(dm, no_proto_name)) == NULL )
      return sc_node_set_error(node, EINVAL, "%s: ERROR: Do not have input "
                               "link %s\n", __func__, links[i]->name);
    if( pair->type != type ) {
      return sc_node_set_error(node, EINVAL, "%s: ERROR: Cannot have duplicate "
                               "output links with different protocol types"
                               "(link name %s)\n", __func__, no_proto_name);
    }
    pair->out_link = links[i];
  }

  int rc = sc_node_prep_get_pool(&dm->pool, dm->pool_attr, node, NULL, 0);
  if( rc < 0 )
    return sc_node_fwd_error(node, rc);

  for( i = 0; i < dm->pairs_n; ++i ) {
    pair = &dm->pairs[i];
    if( pair->out_link == NULL )
      return sc_node_set_error(node, EINVAL, "%s: ERROR: Do not have output "
                               "link %s\n", __func__, pair->link_name);
  }
  SC_TEST(n_links == dm->pairs_n);

  uint64_t buf_size = sc_pool_get_buffer_size(dm->pool);
  dm->max_msg_size = buf_size - sizeof(struct sc_io_msg_hdr);

  for( i = 0; i < dm->conns_n; ++i ) {
    dm->conns[i]->buffer = malloc(dm->max_msg_size);
    sc_callback_at_safe_time(dm->conns[i]->cb);
  }
  return 0;
}


static int sc_io_demux_init(struct sc_node* node, const struct sc_attr* attr,
                          const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_prep_fn = sc_io_demux_prep;
    nt->nt_select_subnode_fn = sc_io_demux_select_subnode;
  }
  node->nd_type = nt;
  struct sc_thread* thread = sc_node_get_thread(node);

  struct sc_io_demux* dm;
  dm = sc_thread_calloc(thread, sizeof(*dm));
  node->nd_private = dm;
  dm->node = node;
  dm->pool_attr = sc_attr_dup(attr);
  dm->pool_attr->private_pool = 1;
  sc_attr_set_from_fmt(dm->pool_attr, "name", "%s.pool", node->nd_name);
  dm->last_conn_uid = 0;

  if( sc_node_init_get_arg_int(&dm->reconnect, node, "reconnect", 1) < 0 )
    return -1;

  const char* error_mode;
  if( sc_node_init_get_arg_str(&error_mode, node, "error_mode", "disconnect") < 0 )
    return -1;
  int mode = get_error_mode(error_mode);
  if( mode == -1 ) {
    sc_node_set_error(node, EINVAL, "%s: ERROR: Unknown error mode %s", __func__,
        error_mode);
    return -1;
  }
  dm->error_mode = mode;

  const char* tmp;
  if( get_conn_string(node, "listen", &tmp) < 0 )
    return -1;
  if( tmp != NULL ) {
    struct sc_io_demux_conn* conn = sc_io_demux_conn_alloc(dm);
    conn->path = strdup(tmp);
    conn->cb->cb_handler_fn = sc_io_demux_try_listen;
    conn->listen = true;
  }

  if( get_conn_string(node, "connect", &tmp) < 0 )
    return -1;
  if( tmp != NULL ) {
    struct sc_io_demux_conn* conn = sc_io_demux_conn_alloc(dm);
    conn->path = strdup(tmp);
    conn->cb->cb_handler_fn = sc_io_demux_try_connect;
    conn->reconnect = dm->reconnect;
  }

  int fd;
  if( sc_node_init_get_arg_int(&fd, node, "fd", -1) < 0 )
    return -1;
  if( fd >= 0 ) {
    struct sc_io_demux_conn* conn = sc_io_demux_conn_alloc(dm);
    conn->fd = fd;
    conn->cb->cb_handler_fn = sc_io_demux_register_fd;
  }

  SC_TRY(sc_callback_alloc(&dm->pool_cb, attr, thread));
  dm->pool_cb->cb_private = dm;
  dm->pool_cb->cb_handler_fn = sc_io_demux_pool_cb;

  return 0;
}


const struct sc_node_factory sc_io_demux_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_io_demux",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_io_demux_init,
};


/** \endcond NODOC */
