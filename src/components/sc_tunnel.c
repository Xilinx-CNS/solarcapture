/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \node{sc_tunnel}
 *
 * \brief A node used to pass ::sc_packet objects between two SolarCapture
 *        sessions via a TCP socket.
 *
 * \nodedetails
 * This node establishes a TCP connection between two SolarCapture node
 * graphs so that you can pass packets between them.  Packets arriving on
 * an input link are forwarded over the connection to an output link on the
 * other side that has the same name.  Each sc_tunnel can support multiple
 * input and output links, so that multiple separate channels are created.
 *
 * \nodeargs
 * Argument         | Optional? | Default | Type           | Description
 * ---------------- | --------- | ------- | -------------- | -----------------------------------------------------------------------------------------------------
 * connect_to       | Yes       |         | ::SC_PARAM_STR | Connect to specified "host:port".
 * server_name      | Yes       |         | ::SC_PARAM_STR | Hostname or IP address of the server interface to connect to if active, or to bind to if passive.
 * server_port      | Yes       |         | ::SC_PARAM_STR | The TCP port number of the server to connect to if active, or to bind to if passive.
 * socket_fd        | Yes       |         | ::SC_PARAM_INT | A file descriptor that is a connected stream socket (in which case server_name, server_port, passive_open and connect_to are not used).
 * remote_args      | Yes       |         | ::SC_PARAM_STR | Opaque message to send to remote side prior to starting sc_tunnel protocol.
 * passive_open     | Yes       |         | ::SC_PARAM_INT | Should this node be opened in passive mode?  Defaults to passive mode unless connect_to is set.
 * recv_buf_size    | Yes       | 32k     | ::SC_PARAM_INT | Socket receive buffer size (note: does not constrain message size)
 * max_msg_size     | Yes       | > 1514  | ::SC_PARAM_INT | Maximum supported message size; by default is large enough ot hold any non-jumbo frame
 *
 * To make an active connection: Set connect_to=host:port or set
 * passive_open=0, server_name=host and server_port=port.
 *
 * To make a passive connection: Set server_port=port and optionally
 * server_host=host if you want to bind to a specific IP interface.
 *
 * The `remote_args` feature is typically used on the client side when
 * connecting to a server process.  The specified message (not including
 * nul) is sent to the server immediately after the connection is
 * established, preceded by its length encoded as a 32-bit integer in
 * network byte order.  It can be used to give information to the server
 * about the service required, which the server can then use when setting
 * up the node graph that the client will interact with.  Note that
 * sc_tunnel does not itself consume this message: It must be consumed by
 * the application prior to passing the socket to an sc_tunnel instance
 * using the socket_fd argument.
 *
 * \namedinputlinks
 * Packets arriving on an input link named "foo" are forwarded to an output
 * link named "foo" on the other side.
 *
 * \outputlinks
 *
 * Link    | Description
 * ------- | -----------------------------------------------------------------------------------------------------------------------------
 * "#exit" | Receives an end-of-stream indication once end of stream is signalled on all inputs and outputs and outstanding data is sent.
 *
 * \cond NODOC
 */

#define _GNU_SOURCE  /* for certain GAI_ codes */
#include <sc_internal.h>
#include <sc_internal/builtin_nodes.h>
#include <solar_capture/nodes/subnode_helper.h>

#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <limits.h>
#include <netdb.h>


#define DEFAULT_RECV_BUF_SIZE 32768


#pragma pack(push, 1)
/* Tunnel wire protocol.
 *
 * All multi-byte fields are little-endian.  All messages are prefixed with
 * sc_tunmsg_hdr.
 *
 * 1) Active sends HANDSHAKE, passive replies with HANDSHAKE_ACK.
 * 2) Passive sends HANDSHAKE, active replies with HANDSHAKE_ACK.
 * 3) Active sends zero or more LINK followed by END_OF_LINKS.
 * 4) Passive sends zero or more LINK followed by END_OF_LINKS.
 * 5) Then packets start flowing.
 * 6) EOS sent after last packet for a given link.
 */

enum sc_tunmsg_type {
  /* Messages that must not be ignored. */
  TUNMSG_HANDSHAKE     = 0,
  TUNMSG_HANDSHAKE_ACK = 1,
  TUNMSG_LINK          = 2,
  TUNMSG_END_OF_LINKS  = 3,
  TUNMSG_PACKET        = 4,
  TUNMSG_EOS           = 5,

  /* Messages with types >= 128 can safely be ignored by the receiver. */
  TUNMSG_MAY_IGNORE    = 128,
};


/* All messages are prefixed with the following header. */
struct sc_tunmsg_hdr {
  uint8_t  tmh_type;
  uint32_t tmh_msg_length;
  char     tmh_msg[];
};


struct sc_tunmsg_handshake {
  /* Contains the string "sc_tunnel\0".  This just gives a hint if you're
   * looking at a network trace, and helps avoid confusion if someone
   * thinks they are connecting to a different protocol!
   */
  char     tmhs_sc_tunnel[10];
  /* In request: Protocol versions supported.  Up to 4 versions can be
   * given.  Unused entries contain 0.
   *
   * In reply: First octet gives version selected.
   */
  uint8_t  tmhs_ver[4];
  /* "Compulsory" options.  Indicates protocol extensions.  If any are set
   * that the receiver does not understand, they must give up.
   */
  uint32_t tmhs_required_flags;
  /* "Optional" options.  Receiver may ignore if not supported. */
  uint32_t tmhs_optional_flags;
};


struct sc_tunmsg_handshake_ack {
  /* Zero if all is good.  Otherwise an errno code indicating reason for
   * unhappiness.
   */
  uint32_t tmha_errno;
  /* A human-readable nul-terminated message indicating reason handshake
   * failed.  Only initialised when tmha_errno!=0.
   */
  char     tmha_msg[128];
};


struct sc_tunmsg_link {
  uint16_t             tmlk_namelen;     /* includes terminating nul */
  uint16_t             tmlk_stream_id;
  /* Reserved fields: Sender must set to zero.  If/when we start using
   * these we should set a flag in sc_tunmsg_handshake so receiver knows
   * they are set.
   */
  uint32_t             tmlk_reserved1;
  uint64_t             tmlk_reserved2;
  uint64_t             tmlk_reserved3;
  char                 tmlk_name[];
};


struct sc_tunmsg_packet {
  uint64_t tmpk_ts_sec;           /* sc_packet::ts_sec */
  uint32_t tmpk_ts_nsec;          /* sc_packet::ts_nsec */
  uint16_t tmpk_stream_id;
  uint16_t tmpk_flags;            /* sc_packet::flags */
  uint16_t tmpk_frame_len;        /* sc_packet::frame_len */
  uint16_t tmpk_payload_offset;   /* offset of payload from tmh_msg */
  /* Packet "data" follows.  NB. The packet payload may not be at the
   * beginning of this blob of data, but will extend to the end of the
   * message.  The length of the payload is (tmh_msg_length -
   * tmpk_payload_offset).  This will allow us to add further fields and
   * meta-data into packet messages in future.
   */
};


struct sc_tunmsg_eos {
  uint16_t             tmes_stream_id;
};


struct sc_tunmsg {
  struct sc_tunmsg_hdr             hdr;
  union {
    struct sc_tunmsg_handshake     hs;
    struct sc_tunmsg_handshake_ack hsa;
    struct sc_tunmsg_link          link;
    struct sc_tunmsg_packet        pkt;
    struct sc_tunmsg_eos           eos;
  };
};
#pragma pack(pop)


struct sc_tunnel_state;


struct tunnel_input {
  struct sc_tunnel_state*    st;
  struct sc_node*            node;
  const struct sc_node_link* free_hop;
  struct sc_packet_list      backlog;
  char*                      name;
  int                        stream_id;
  bool                       eos_pending;
  struct sc_dlist            link;
};


struct tunnel_output {
  struct sc_tunnel_state*    st;
  struct sc_subnode_helper*  subnode;
  char*                      name;
  bool                       eos_seen;
  bool                       connected;
  ssize_t                    max_msg_size;
};


struct sc_tunnel_state {
  struct sc_node*            node;
  struct sc_thread*          thread;
  struct sc_attr*            attr;
  int                        passive_open;
  char*                      server_name;
  char*                      server_port;
  char*                      remote_args;
  struct sc_subnode_helper*  exit;
  struct sc_callback*        sock_cb;
  uint32_t                   epoll_evt;
  int                        sock_fd;
  struct sc_callback*        pool_cb;
  int                        eos_input_wait;
  int                        eos_output_wait;

  struct tunnel_output**     outputs;
  int                        outputs_n;
  struct tunnel_output**     stream_to_output;
  unsigned                   stream_to_output_len;
  size_t                     recv_n;
  size_t                     recv_max;
  size_t                     recv_rc;
  char*                      recv_buf;
  char*                      recv_read;
  char*                      recv_fill;
  size_t                     recv_buf_size;
  struct sc_packet*          recv_pkt;
  struct tunnel_output*      recv_output;

  struct tunnel_input**      inputs;
  int                        inputs_n;
  struct sc_dlist            inputs_ready;
  struct sc_tunmsg           send_hdr;
  struct msghdr              send_msg;
  size_t                     send_msg_len;
  struct iovec               send_iov[SC_PKT_MAX_IOVS + 1];
};


static const struct sc_node_factory sc_tunnel_input_factory;


#define tun_tracefp(st, ...) sc_tracefp(st_scs(st), __VA_ARGS__)
#define tun_trace(st, ...)   sc_trace(st_scs(st), __VA_ARGS__)
#define tun_err(st, ...)     sc_err(st_scs(st), __VA_ARGS__)
#define tun_warn(st, ...)    sc_warn(st_scs(st), __VA_ARGS__)


static inline struct sc_session* st_scs(const struct sc_tunnel_state* st)
{
  return sc_thread_get_session(st->thread);
}


static inline int st_id(const struct sc_tunnel_state* st)
{
  return SC_NODE_IMPL_FROM_NODE(st->node)->ni_id;
}


static inline struct tunnel_input* tunnel_input_from_link(struct sc_dlist* l)
{
  return SC_CONTAINER(struct tunnel_input, link, l);
}


static void htole_handshake(struct sc_tunmsg_handshake* tmhs)
{
  tmhs->tmhs_required_flags = htole32(tmhs->tmhs_required_flags);
  tmhs->tmhs_optional_flags = htole32(tmhs->tmhs_optional_flags);
}


static void letoh_handshake(struct sc_tunmsg_handshake* tmhs)
{
  tmhs->tmhs_required_flags = le32toh(tmhs->tmhs_required_flags);
  tmhs->tmhs_optional_flags = le32toh(tmhs->tmhs_optional_flags);
}


static void letoh_handshake_ack(struct sc_tunmsg_handshake_ack* tmha)
{
  tmha->tmha_errno = le32toh(tmha->tmha_errno);
}


static void htole_link(struct sc_tunmsg_link* tmlk)
{
  tmlk->tmlk_namelen = htole16(tmlk->tmlk_namelen);
  tmlk->tmlk_stream_id = htole16(tmlk->tmlk_stream_id);
}


static void letoh_link(struct sc_tunmsg_link* tmlk)
{
  tmlk->tmlk_namelen = le16toh(tmlk->tmlk_namelen);
  tmlk->tmlk_stream_id = le16toh(tmlk->tmlk_stream_id);
}


static void htole_eos(struct sc_tunmsg_eos* eos)
{
  eos->tmes_stream_id = htole32(eos->tmes_stream_id);
}


static void letoh_eos(struct sc_tunmsg_eos* eos)
{
  eos->tmes_stream_id = le32toh(eos->tmes_stream_id);
}


static void htole_packet(struct sc_tunmsg_packet* tmpk)
{
  tmpk->tmpk_ts_sec         = htole64(tmpk->tmpk_ts_sec);
  tmpk->tmpk_ts_nsec        = htole32(tmpk->tmpk_ts_nsec);
  tmpk->tmpk_stream_id      = htole32(tmpk->tmpk_stream_id);
  tmpk->tmpk_flags          = htole16(tmpk->tmpk_flags);
  tmpk->tmpk_frame_len      = htole16(tmpk->tmpk_frame_len);
  tmpk->tmpk_payload_offset = htole32(tmpk->tmpk_payload_offset);
}


static int recvall(int sock, void* buf, size_t len)
{
  /* Receive whole message.  Return 0 on success, or -1 on error. */
  size_t got = 0;
  do {
    int rc = recv(sock, (char*) buf + got, len - got, MSG_WAITALL);
    if( rc < 0 ) {
      if( errno == EINTR )
        continue;
      return -1;
    }
    else if( rc == 0 ) {
      errno = ECONNABORTED;
      return -1;
    }
    got += rc;
  } while( got < len );
  return 0;
}


static int sendall(int sock, void* buf, size_t len)
{
  /* Send whole message.  Return 0 on success, or -1 on error. */
  size_t done = 0;
  do {
    int rc = send(sock, (char*) buf + done, len - done, MSG_NOSIGNAL);
    if( rc < 0 ) {
      if( errno == EINTR )
        continue;
      return -1;
    }
    done += rc;
  } while( done < len );
  return 0;
}


static int sendallv(int sock, const struct iovec* iovec, int iovlen)
{
  /* Send whole message.  Return 0 on success, or -1 on error. */
  int i, rc;
  for( i = 0; i < iovlen; ++i )
    if( (rc = sendall(sock, iovec[i].iov_base, iovec[i].iov_len)) < 0 )
      return -1;
  return 0;
}


static int sendall_or_set_err(struct sc_tunnel_state* st, void* buf, size_t len,
                              const char* fmt, ...)
  __attribute__((format(printf,4,5)));

static int sendall_or_set_err(struct sc_tunnel_state* st, void* buf, size_t len,
                              const char* fmt, ...)
{
  int rc = sendall(st->sock_fd, buf, len);
  if( rc < 0 ) {
    va_list va;
    va_start(va, fmt);
    sc_node_set_errorv(st->node, errno, fmt, va);
    va_end(va);
  }
  return rc;
}


static void sc_tunnel_all_stop(struct sc_tunnel_state* st)
{
  tun_trace(st, "%s(%d):\n", __func__, st_id(st));

  assert( st->eos_input_wait == 0 );
  assert( st->eos_output_wait == 0 );
  assert( sc_dlist_is_empty(&(st->inputs_ready)) );

  close(st->sock_fd);
  st->sock_fd = -1;
  if( st->exit )
    sc_node_link_end_of_stream2(st->exit->sh_links[0]);
}


static void sc_tunnel_abort(struct sc_tunnel_state* st)
{
  tun_trace(st, "%s(%d):\n", __func__, st_id(st));

  close(st->sock_fd);
  st->sock_fd = -1;
  sc_callback_remove(st->pool_cb);

  /* We're not going to receive any more messages, so indicate
   * end-of-stream on outputs.
   */
  unsigned i;
  for( i = 0; i < st->outputs_n; ++i )
    if( ! st->outputs[i]->eos_seen ) {
      sc_node_link_end_of_stream2(st->outputs[i]->subnode->sh_links[0]);
      st->outputs[i]->eos_seen = true;
    }

  /* Incoming packets are left on the backlog and not forwarded, so
   * indicate end-of-stream on inputs.
   */
  for( i = 0; i < st->inputs_n; i++ )
    sc_node_link_end_of_stream2(st->inputs[i]->free_hop);

  if( st->exit )
    sc_node_link_end_of_stream2(st->exit->sh_links[0]);
}


static inline void sc_tunmsg_hdr_init(struct sc_tunmsg_hdr* tmh,
                                      int type, int msg_len)
{
  tmh->tmh_type = type;
  tmh->tmh_msg_length = htole32(msg_len);
}


static int sc_tunnel_send_handshake(struct sc_tunnel_state* st)
{
  tun_trace(st, "%s(%d):\n", __func__, st_id(st));
  struct sc_tunmsg_hdr* tmh = &(st->send_hdr.hdr);
  struct sc_tunmsg_handshake* tmhs = (void*) tmh->tmh_msg;
  sc_tunmsg_hdr_init(tmh, TUNMSG_HANDSHAKE, sizeof(*tmhs));
  SC_TEST( snprintf(tmhs->tmhs_sc_tunnel, sizeof(tmhs->tmhs_sc_tunnel),
                    "sc_tunnel") == sizeof(tmhs->tmhs_sc_tunnel) - 1 );
  memset(tmhs->tmhs_ver, 0, sizeof(tmhs->tmhs_ver));
  tmhs->tmhs_ver[0] = 1;
  tmhs->tmhs_required_flags = 0;
  tmhs->tmhs_optional_flags = 0;
  htole_handshake(tmhs);
  return sendall_or_set_err(st, tmh, sizeof(*tmh) + sizeof(*tmhs),
                            "sc_tunnel(%d): ERROR: Send error during "
                            "handshake\n", st_id(st));
}


static int sc_tunnel_send_handshake_ack(struct sc_tunnel_state* st,
                                        int err, const char* fmt, ...)
  __attribute__((format(printf,3,4)));

static int sc_tunnel_send_handshake_ack(struct sc_tunnel_state* st,
                                        int err, const char* fmt, ...)
{
  tun_trace(st, "%s(%d): err=%d\n", __func__, st_id(st), err);
  struct sc_tunmsg_hdr* tmh = &(st->send_hdr.hdr);
  struct sc_tunmsg_handshake_ack* tmha = (void*) tmh->tmh_msg;
  sc_tunmsg_hdr_init(tmh, TUNMSG_HANDSHAKE_ACK, sizeof(*tmha));
  tmha->tmha_errno = htole32(err);
  if( fmt ) {
    va_list va;
    va_start(va, fmt);
    vsnprintf(tmha->tmha_msg, sizeof(tmha->tmha_msg), fmt, va);
    va_end(va);
  }
  else {
    tmha->tmha_msg[0] = '\0';
  }
  return sendall_or_set_err(st, tmh, sizeof(*tmh) + sizeof(*tmha),
                            "sc_tunnel(%d): ERROR: Send error during "
                            "handshake ack\n", st_id(st));
}


static int sc_tunnel_recv_handshake(struct sc_tunnel_state* st)
{
  tun_trace(st, "%s(%d):\n", __func__, st_id(st));
  struct sc_tunmsg_hdr tmh;
  if( recvall(st->sock_fd, &tmh, sizeof(tmh)) < 0 )
    return sc_node_set_error(st->node, errno, "sc_tunnel(%d): ERROR: Receive "
                             "error during handshake\n", st_id(st));
  if( tmh.tmh_type != TUNMSG_HANDSHAKE )
    return sc_node_set_error(st->node, errno, "sc_tunnel(%d): ERROR: Received "
                             "%d instead of handshake\n", st_id(st),
                             (int) tmh.tmh_type);
  unsigned msg_len = le32toh(tmh.tmh_msg_length);
  struct sc_tunmsg_handshake* tmhs = (void*) st->recv_buf;
  if( msg_len > st->recv_buf_size || msg_len < sizeof(*tmhs) )
    return sc_node_set_error(st->node, errno, "sc_tunnel(%d): ERROR: Handshake "
                             "message size bad (%zu <= %u <= %zu)\n",
                             st_id(st), sizeof(*tmhs), msg_len,
                             st->recv_buf_size);
  if( recvall(st->sock_fd, tmhs, msg_len) < 0 )
    return sc_node_set_error(st->node, errno, "sc_tunnel(%d): ERROR: Receive "
                             "error during handshake\n", st_id(st));
  letoh_handshake(tmhs);
  if( memcmp(tmhs->tmhs_sc_tunnel, "sc_tunnel", strlen("sc_tunnel")) )
    return sc_node_set_error(st->node, ENOPROTOOPT, "sc_tunnel(%d): ERROR: "
                             "Handshake does not contain magic string\n",
                             st_id(st));
  int i;
  for( i = 0; i < 4; ++i )
    if( tmhs->tmhs_ver[i] == 1 )
      break;
  if( i == 4 ) {
    sc_tunnel_send_handshake_ack(st, ENOPROTOOPT, "incompatible version");
    return sc_node_set_error(st->node, ENOPROTOOPT, "sc_tunnel(%d): ERROR: "
                             "Remote sc_tunnel incompatible (protocol "
                             "version)\n", st_id(st));
  }
  uint32_t accepted_flags = 0;
  uint32_t bad_flags = tmhs->tmhs_required_flags & ~accepted_flags;
  if( bad_flags ) {
    sc_tunnel_send_handshake_ack(st, ENOPROTOOPT, "unacceptable flags=%x",
                                 bad_flags);
    return sc_node_set_error(st->node, ENOPROTOOPT, "sc_tunnel(%d): ERROR: "
                             "Remote sc_tunnel incompatible (required_flags="
                             "%x unacceptable=%x)\n", st_id(st),
                             tmhs->tmhs_required_flags, bad_flags);
  }
  return 0;
}


static int sc_tunnel_recv_handshake_ack(struct sc_tunnel_state* st)
{
  tun_trace(st, "%s(%d):\n", __func__, st_id(st));
  struct sc_tunmsg_hdr tmh;
  if( recvall(st->sock_fd, &tmh, sizeof(tmh)) < 0 )
    return sc_node_set_error(st->node, errno, "sc_tunnel(%d): ERROR: Receive "
                             "error waiting for handshake ack\n", st_id(st));
  if( tmh.tmh_type != TUNMSG_HANDSHAKE_ACK )
    return sc_node_set_error(st->node, errno, "sc_tunnel(%d): ERROR: Received "
                             "%d instead of handshake ack\n", st_id(st),
                             (int) tmh.tmh_type);
  unsigned msg_len = le32toh(tmh.tmh_msg_length);
  struct sc_tunmsg_handshake_ack* tmha = (void*) st->recv_buf;
  if( msg_len > st->recv_buf_size || msg_len < sizeof(*tmha) )
    return sc_node_set_error(st->node, errno, "sc_tunnel(%d): ERROR: Handshake "
                             "message size bad (%zu <= %u <= %zu)\n",
                             st_id(st), sizeof(*tmha), msg_len,
                             st->recv_buf_size);
  if( recvall(st->sock_fd, tmha, msg_len) < 0 )
    return sc_node_set_error(st->node, errno, "sc_tunnel(%d): ERROR: Receive "
                             "error during handshake ack\n", st_id(st));
  letoh_handshake_ack(tmha);
  if( tmha->tmha_errno ) {
    tmha->tmha_msg[sizeof(tmha->tmha_msg) - 1] = '\0';
    return sc_node_set_error(st->node, tmha->tmha_errno,
                             "sc_tunnel(%d): ERROR: Handshake failed (%s)\n",
                             st_id(st), tmha->tmha_msg);
  }
  return 0;
}


static int sc_tunnel_send_link(struct sc_tunnel_state* st, const char* name,
                               unsigned stream_id)
{
  size_t namelen = strlen(name);
  int msg_len = sizeof(struct sc_tunmsg_link) + namelen + 1;
  char buf[sizeof(struct sc_tunmsg_hdr) + msg_len];
  struct sc_tunmsg_hdr* tmh = (void*) buf;
  sc_tunmsg_hdr_init(tmh, TUNMSG_LINK, msg_len);
  struct sc_tunmsg_link* tmlk = (void*) tmh->tmh_msg;
  memset(tmlk, 0, sizeof(*tmlk));  /* zero the reserved fields */
  tmlk->tmlk_namelen = namelen + 1;
  tmlk->tmlk_stream_id = stream_id;
  htole_link(tmlk);
  memcpy(tmlk->tmlk_name, name, namelen + 1);
  return sendall_or_set_err(st, tmh, sizeof(*tmh) + msg_len, "sc_tunnel(%d): "
                            "ERROR: Send error while exchanging links\n",
                            st_id(st));
}


static int sc_tunnel_send_links(struct sc_tunnel_state* st)
{
  tun_trace(st, "%s(%d):\n", __func__, st_id(st));
  int i;
  for( i = 0; i < st->inputs_n; ++i ) {
    struct tunnel_input* tunin = st->inputs[i];
    tun_trace(st, "%s(%d): stream_id=%d name=%s\n", __func__, st_id(st),
              i, tunin->name);
    if( sc_tunnel_send_link(st, tunin->name, i) < 0 )
      return -1;
  }
  struct sc_tunmsg_hdr tmh;
  sc_tunmsg_hdr_init(&tmh, TUNMSG_END_OF_LINKS, 0);
  return sendall_or_set_err(st, &tmh, sizeof(tmh), "sc_tunnel(%d): ERROR: Send "
                            "error while exchanging links\n", st_id(st));
}


static int handle_msg_link(struct sc_tunnel_state* st,
                           const struct sc_tunmsg_link* tmlk)
{
  int i;
  for( i = 0; i < st->outputs_n; ++i )
    if( ! strcmp(tmlk->tmlk_name, st->outputs[i]->name) )
      break;
  if( i == st->outputs_n )
    return sc_node_set_error(st->node, EDOM, "sc_tunnel(%d): ERROR: Incoming "
                             "link '%s' not connected on this side\n",
                             st_id(st), tmlk->tmlk_name);
  struct tunnel_output* tunout = st->outputs[i];
  if( tmlk->tmlk_stream_id >= st->stream_to_output_len ) {
    st->stream_to_output_len = tmlk->tmlk_stream_id + 1;
    SC_REALLOC(&(st->stream_to_output), st->stream_to_output_len);
  }
  tun_trace(st, "%s(%d): stream_id=%u name=%s\n", __func__, st_id(st),
            tmlk->tmlk_stream_id, tmlk->tmlk_name);
  st->stream_to_output[tmlk->tmlk_stream_id] = tunout;
  tunout->connected = true;
  return 0;
}


static int sc_tunnel_recv_links(struct sc_tunnel_state* st)
{
  tun_trace(st, "%s(%d):\n", __func__, st_id(st));
  struct sc_tunmsg_hdr msg;

  while( 1 ) {
    if( recvall(st->sock_fd, &msg, sizeof(msg)) < 0 )
      return sc_node_set_error(st->node, errno, "sc_tunnel(%d): ERROR: Receive"
                               " error fetching link\n", st_id(st));
    if( msg.tmh_type != TUNMSG_LINK )
      break;
    uint32_t msg_len = le32toh(msg.tmh_msg_length);
    if( msg_len > st->recv_buf_size )
      return sc_node_set_error(st->node, errno, "sc_tunnel(%d): ERROR: LINK "
                               "message too big (%u > %zu)\n", st_id(st),
                               msg_len, st->recv_buf_size);
    if( recvall(st->sock_fd, st->recv_buf, msg_len) < 0 )
      return sc_node_set_error(st->node, errno, "sc_tunnel(%d): ERROR: Receive"
                               " error fetching link\n", st_id(st));
    struct sc_tunmsg_link* tmlk = (void*) st->recv_buf;
    letoh_link(tmlk);
    if( sizeof(*tmlk) + tmlk->tmlk_namelen > msg_len )
      return sc_node_set_error(st->node, errno, "sc_tunnel(%d): ERROR: Protocol"
                               " error: Bad namelen in LINK\n", st_id(st));
    tmlk->tmlk_name[tmlk->tmlk_namelen - 1] = '\0';
    handle_msg_link(st, tmlk);
  }

  if( msg.tmh_type != TUNMSG_END_OF_LINKS )
    return sc_node_set_error(st->node, errno, "sc_tunnel(%d): ERROR: Protocol "
                             "error: got %d while waiting for links\n",
                             st_id(st), (int) msg.tmh_type);

  int i;
  for( i = 0; i < st->outputs_n; ++i )
    if( ! st->outputs[i]->connected )
      return sc_node_set_error(st->node, EDOM, "sc_tunnel(%d): ERROR: Local "
                               "output '%s' not connected at other side\n",
                               st_id(st), st->outputs[i]->name);
  return 0;
}


static int do_active_handshake(struct sc_tunnel_state* st)
{
  sc_info(st_scs(st), "sc_tunnel(%d): Start handshake\n", st_id(st));
  if( sc_tunnel_send_handshake(st)              < 0 ||
      sc_tunnel_recv_handshake_ack(st)          < 0 ||
      sc_tunnel_recv_handshake(st)              < 0 ||
      sc_tunnel_send_handshake_ack(st, 0, NULL) < 0 ||
      sc_tunnel_send_links(st)                  < 0 ||
      sc_tunnel_recv_links(st)                  < 0  )
    return -1;
  return 0;
}


static int do_passive_handshake(struct sc_tunnel_state* st)
{
  sc_info(st_scs(st), "sc_tunnel(%d): Wait for handshake\n", st_id(st));
  if( sc_tunnel_recv_handshake(st)              < 0 ||
      sc_tunnel_send_handshake_ack(st, 0, NULL) < 0 ||
      sc_tunnel_send_handshake(st)              < 0 ||
      sc_tunnel_recv_handshake_ack(st)          < 0 ||
      sc_tunnel_recv_links(st)                  < 0 ||
      sc_tunnel_send_links(st)                  < 0  )
    return -1;
  return 0;
}


static void sc_tunnel_send_prep_pkt(struct sc_tunnel_state* st,
                                    struct tunnel_input* tunin)
{
  struct sc_packet* pkt = tunin->backlog.head;
  unsigned pay_len = sc_packet_bytes(pkt);
  tun_tracefp(st, "%s(%d,%s): pay_len=%u\n", __func__, st_id(st), tunin->name,
              pay_len);

  struct sc_tunmsg_hdr* tmh = &(st->send_hdr.hdr);
  struct sc_tunmsg_packet* tmpk = (void*) tmh->tmh_msg;
  sc_tunmsg_hdr_init(tmh, TUNMSG_PACKET, sizeof(*tmpk) + pay_len);
  tmpk->tmpk_ts_sec = pkt->ts_sec;
  tmpk->tmpk_ts_nsec = pkt->ts_nsec;
  tmpk->tmpk_stream_id = tunin->stream_id;
  tmpk->tmpk_flags = pkt->flags;
  tmpk->tmpk_frame_len = pkt->frame_len;
  tmpk->tmpk_payload_offset = sizeof(*tmpk);
  htole_packet(tmpk);

  st->send_iov[0].iov_base = tmh;
  st->send_iov[0].iov_len = sizeof(*tmh) + sizeof(*tmpk);
  assert( pkt->iovlen <= SC_PKT_MAX_IOVS );
  memcpy(st->send_iov + 1, pkt->iov, pkt->iovlen * sizeof(st->send_iov[0]));
  st->send_msg.msg_controllen = 0;
  st->send_msg.msg_namelen = 0;
  st->send_msg.msg_iov = st->send_iov;
  st->send_msg.msg_iovlen = pkt->iovlen + 1;
  st->send_msg_len = sizeof(*tmh) + sizeof(*tmpk) + pay_len;
}


static void sc_tunnel_send_prep_eos(struct sc_tunnel_state* st,
                                    struct tunnel_input* tunin)
{
  tun_trace(st, "%s(%d,%s):\n", __func__, st_id(st), tunin->name);
  SC_TEST( tunin->eos_pending );

  struct sc_tunmsg_hdr* tmh = &(st->send_hdr.hdr);
  struct sc_tunmsg_eos* tmes = (void*) tmh->tmh_msg;
  sc_tunmsg_hdr_init(tmh, TUNMSG_EOS, sizeof(*tmes));
  tmes->tmes_stream_id = tunin->stream_id;
  htole_eos(tmes);

  st->send_iov[0].iov_base = tmh;
  st->send_iov[0].iov_len = sizeof(*tmh) + sizeof(*tmes);
  st->send_msg.msg_controllen = 0;
  st->send_msg.msg_namelen = 0;
  st->send_msg.msg_iov = st->send_iov;
  st->send_msg.msg_iovlen = 1;
  st->send_msg_len = st->send_iov[0].iov_len;
}


static bool sc_tunnel_send_send(struct sc_tunnel_state* st)
{
  /* Progress the send path by pushing data to the wire.  Returns true if
   * we're now ready to push another packet, or false if not (ie. still
   * sending or in error state).
   */
  assert( ! sc_dlist_is_empty(&(st->inputs_ready)) );

  ssize_t rc = sendmsg(st->sock_fd, &(st->send_msg),
                       MSG_DONTWAIT | MSG_NOSIGNAL);
  tun_tracefp(st, "%s(%d): send(%zu) => %zd\n",
              __func__, st_id(st), st->send_msg_len, rc);

  if( rc == st->send_msg_len ) {
    /* We've sent the whole message. */
    struct tunnel_input* tunin;
    tunin = tunnel_input_from_link(sc_dlist_pop_head(&(st->inputs_ready)));
    if( ! sc_packet_list_is_empty(&(tunin->backlog)) ) {
      struct sc_packet* pkt = sc_packet_list_pop_head(&(tunin->backlog));
      sc_forward2(tunin->free_hop, pkt);
      if( ! sc_packet_list_is_empty(&(tunin->backlog)) || tunin->eos_pending )
        sc_dlist_push_tail(&(st->inputs_ready), &(tunin->link));
    }
    else {
      tun_trace(st, "%s(%d,%s): EOS sent\n", __func__, st_id(st), tunin->name);
      SC_TEST( tunin->eos_pending );
      tunin->eos_pending = false;
      sc_node_link_end_of_stream2(tunin->free_hop);
      SC_TEST( st->eos_input_wait > 0 );
      if( --(st->eos_input_wait) == 0 && st->eos_output_wait == 0 )
        sc_tunnel_all_stop(st);
    }
    return true;
  }
  else if( rc >= 0 ) {
    /* Made some progress, but more to send. */
    while( 1 ) {
      assert( st->send_msg.msg_iovlen > 0 );
      if( rc >= st->send_msg.msg_iov[0].iov_len ) {
        st->send_msg_len -= st->send_msg.msg_iov[0].iov_len;
        rc -= st->send_msg.msg_iov[0].iov_len;
        ++(st->send_msg.msg_iov);
        --(st->send_msg.msg_iovlen);
        assert( st->send_msg.msg_iovlen >= 1 );
        if( rc == 0 )
          break;
      }
      else {
        st->send_msg_len -= rc;
        st->send_msg.msg_iov[0].iov_base =
          (char*) st->send_msg.msg_iov[0].iov_base + rc;
        st->send_msg.msg_iov[0].iov_len -= rc;
        break;
      }
    }
    goto need_EPOLLOUT;
  }
  else {
    /* Badness happened. */
    switch( errno ) {
    case EAGAIN:
    case EINTR:
      goto need_EPOLLOUT;
    default:
      tun_warn(st, "sc_tunnel(%d): WARNING: send() failed (%d %s)\n",
               st_id(st), errno, strerror(errno));
      sc_tunnel_abort(st);
      break;
    }
  }
  return false;  /* not ready to send another message */


 need_EPOLLOUT:
  if( ! (st->epoll_evt & EPOLLOUT) ) {
    st->epoll_evt |= EPOLLOUT;
    sc_epoll_ctl(st->thread, EPOLL_CTL_MOD, st->sock_fd,
                 st->epoll_evt, st->sock_cb);
  }
  return false;  /* not ready to send another message */
}


static void sc_tunnel_send_drain(struct sc_tunnel_state* st)
{
  tun_tracefp(st, "%s(%d):\n", __func__, st_id(st));

  while( ! sc_dlist_is_empty(&(st->inputs_ready)) ) {
    struct tunnel_input* tunin = tunnel_input_from_link(st->inputs_ready.next);
    if( ! sc_packet_list_is_empty(&(tunin->backlog)) )
      sc_tunnel_send_prep_pkt(st, tunin);
    else
      sc_tunnel_send_prep_eos(st, tunin);
    if( ! sc_tunnel_send_send(st) )
      break;
  }
}


static ssize_t sc_tunnel_recv_handle_packet(struct sc_tunnel_state* st,
                                            struct sc_tunmsg_hdr* msg,
                                            size_t buf_len)
{
  /* Returns:
   *   >0  if we've consumed a message
   *    0  if need more data
   *   -1  if waiting for buffers or packet payload
   *   -2  on error
   */
  struct sc_tunmsg_packet* tmpk;
  if( buf_len < sizeof(*msg) + sizeof(*tmpk) )
    return 0;

  tmpk = (void*) msg->tmh_msg;
  ssize_t pay_off = le16toh(tmpk->tmpk_payload_offset);
  tun_tracefp(st, "%s(%d): buf_len=%zu pay_off=%zu padding=%zu\n",
              __func__, st_id(st), buf_len, pay_off, pay_off - sizeof(*tmpk));
  /* We treat any padding between tmpk and the payload as part of tmpk.
   * (We accept such padding for forward compatibility).
   */
  if( buf_len < sizeof(*msg) + pay_off )
    return 0;
  uint32_t msg_len = le32toh(msg->tmh_msg_length);
  ssize_t pay_len = (int) msg_len - (int) pay_off;
  if( pay_len < 0 )
    goto err_too_short;
  unsigned stream_id = le32toh(tmpk->tmpk_stream_id);
  if( stream_id >= st->stream_to_output_len )
    goto err_bad_stream_id;
  struct tunnel_output* tunout = st->stream_to_output[stream_id];
  if( tunout == NULL )
    goto err_bad_stream_id;
  if( tunout->eos_seen )
    goto err_eos;
  if( pay_len > tunout->max_msg_size )
    goto err_too_long;

  struct sc_packet_list pl;
  __sc_packet_list_init(&pl);
  if( sc_pool_get_packets(&pl, tunout->subnode->sh_pool, 1, 1) != 1 ) {
    sc_pool_on_threshold(tunout->subnode->sh_pool, st->pool_cb, 1);
    st->epoll_evt &= ~EPOLLIN;
    return -1;
  }

  struct sc_packet* pkt = pl.head;
  pkt->ts_sec = le64toh(tmpk->tmpk_ts_sec);
  pkt->ts_nsec = le32toh(tmpk->tmpk_ts_nsec);
  pkt->flags = le16toh(tmpk->tmpk_flags);
  pkt->frame_len = le16toh(tmpk->tmpk_frame_len);
  buf_len -= sizeof(*msg) + pay_off;
  if( pay_len <= buf_len ) {
    /* We have whole message payload in the receive buffer. */
    memcpy(pkt->iov[0].iov_base, (char*) tmpk + pay_off, pay_len);
    buf_len -= pay_len;
    pkt->iov[0].iov_len = pay_len;
    sc_forward2(tunout->subnode->sh_links[0], pkt);
    tun_tracefp(st, "%s(%d,%s): got whole pkt from recv_buf\n",
                __func__, st_id(st), tunout->name);
    return sizeof(*msg) + sizeof(*tmpk) + pay_len;
  }
  else {
    /* Some message not yet received. */
    memcpy(pkt->iov[0].iov_base, (char*) tmpk + pay_off, buf_len);
    pkt->iov[0].iov_len = buf_len;
    st->recv_pkt = pkt;
    st->recv_output = tunout;
    st->recv_fill = (char*) pkt->iov[0].iov_base + pkt->iov[0].iov_len;
    st->recv_max = pay_len - buf_len;
    st->epoll_evt |= EPOLLIN;
    tun_tracefp(st, "%s(%d,%s): zc recv left=%zu\n", __func__,
                st_id(st), tunout->name, st->recv_max);
    return -1;
  }


 err_too_short:
  tun_err(st, "sc_tunnel(%d): ERROR: Protocol error: msg_length too small "
          "(msg_len=%u payload_off=%u)\n",
          st_id(st), msg_len, (unsigned) pay_off);
  return -2;
 err_too_long:
  tun_err(st, "sc_tunnel(%d,%s): ERROR: Received over-length message "
          "(%zd > %zd).  Hint: Set max_msg_size argument\n", st_id(st),
          tunout->name, pay_len, tunout->max_msg_size);
  return -2;
 err_bad_stream_id:
  tun_err(st, "sc_tunnel(%d): ERROR: Protocol error: bad stream ID=%u\n",
          st_id(st), stream_id);
  return -2;
 err_eos:
  tun_err(st, "sc_tunnel(%d,%s): ERROR: Protocol error: packet after EOS\n",
          st_id(st), tunout->name);
  return -2;
}


static int sc_tunnel_recv_handle_eos(struct sc_tunnel_state* st,
                                     struct sc_tunmsg_hdr* msg,
                                     unsigned msg_body_len)
{
  struct sc_tunmsg_eos* tmes = (void*) msg->tmh_msg;
  if( msg_body_len < sizeof(*tmes) )
    goto err_too_short;
  letoh_eos(tmes);
  unsigned stream_id = tmes->tmes_stream_id;
  if( stream_id >= st->stream_to_output_len )
    goto err_bad_stream_id;
  struct tunnel_output* tunout = st->stream_to_output[stream_id];
  if( tunout == NULL )
    goto err_bad_stream_id;
  if( tunout->eos_seen )
    goto err_eos;
  tun_trace(st, "%s(%d,%s): Received EOS\n",
            __func__, st_id(st), tunout->name);
  sc_node_link_end_of_stream2(tunout->subnode->sh_links[0]);
  tunout->eos_seen = true;
  if( --(st->eos_output_wait) == 0 && st->eos_input_wait == 0 )
    sc_tunnel_all_stop(st);
  return sizeof(*msg) + msg_body_len;


 err_too_short:
  tun_err(st, "sc_tunnel(%d): ERROR: Protocol error: msg_length too small "
          "(msg_len=%u expected=%zu)\n",
          st_id(st), msg_body_len, sizeof(*tmes));
  return -1;
 err_bad_stream_id:
  tun_err(st, "sc_tunnel(%d): ERROR: Protocol error: bad stream ID=%u in EOS\n",
          st_id(st), stream_id);
  return -1;
 err_eos:
  tun_err(st, "sc_tunnel(%d,%s): ERROR: Protocol error: EOS after EOS\n",
          st_id(st), tunout->name);
  return -1;
}


static int sc_tunnel_recv_handle_other(struct sc_tunnel_state* st,
                                       struct sc_tunmsg_hdr* msg,
                                       unsigned msg_body_len)
{
  switch( msg->tmh_type ) {
  case TUNMSG_EOS:;
    return sc_tunnel_recv_handle_eos(st, msg, msg_body_len);

  default:
    if( msg->tmh_type >= TUNMSG_MAY_IGNORE )
      /* Don't get upset -- ruins forwards compatibility! */
      break;
    tun_err(st, "sc_tunnel(%d): Received unexpected msg_type=%d\n",
            st_id(st), (int) msg->tmh_type);
    return -1;
  }

  return sizeof(*msg) + msg_body_len;
}


static void sc_tunnel_recv_drain(struct sc_tunnel_state* st)
{
  struct sc_tunmsg_hdr* msg;
  size_t buf_len;
  ssize_t rc;

  while( (buf_len = st->recv_fill - st->recv_read) >= sizeof(*msg) ) {
    tun_tracefp(st, "%s(%d): left=%zu\n", __func__, st_id(st), buf_len);
    msg = (void*) st->recv_read;
    if( msg->tmh_type == TUNMSG_PACKET ) {
      /* TUNMSG_PACKET is handled specially because message size can exceed
       * receive buffer length, and we sometimes want to receive directly
       * into the sc_packet buffer.
       */
      if( (rc = sc_tunnel_recv_handle_packet(st, msg, buf_len)) > 0 ) {
        st->recv_read += rc;
        continue;
      }
      else if( rc == 0 ) {
        /* Waiting for more data. */
        break;
      }
      else if( rc == -1 ) {
        /* Waiting for buffers. */
        return;
      }
      else if( rc == -2 ) {
        goto err_shutdown;
      }
      else {
        /* Impossible. */
        SC_TEST(0);
      }
    }

    /* Other message types should fit within the receive buffer. */
    size_t msg_body_len = le32toh(msg->tmh_msg_length);
    if( msg_body_len + sizeof(*msg) > st->recv_buf_size ) {
      tun_err(st, "sc_tunnel(%d): ERROR: Protocol error: Message type=%d "
              "too long (%zu) for recv buf (%zu)\n", st_id(st),
              (int) msg->tmh_type, msg_body_len, st->recv_buf_size);
      goto err_shutdown;
    }
    if( buf_len < sizeof(*msg) + msg_body_len )
      break;
    if( (rc = sc_tunnel_recv_handle_other(st, msg, msg_body_len)) > 0 ) {
      st->recv_read += rc;
      continue;
    }
    else {
      tun_err(st, "sc_tunnel(%d): ERROR: Protocol error handling message %d\n",
              st_id(st), (int) msg->tmh_type);
      goto err_shutdown;
    }
  }

  /* Waiting for more data or next message.  Move remaing data to start of
   * recv_buf so we can do a nice big recv.  (Will be at most a few bytes
   * of header).
   */
  buf_len = st->recv_fill - st->recv_read;
  if( buf_len && st->recv_read != st->recv_buf ) {
    memmove(st->recv_buf, st->recv_read, buf_len);
    st->recv_read = st->recv_buf;
    st->recv_fill = st->recv_buf + buf_len;
  }
  st->recv_max = st->recv_buf + st->recv_buf_size - st->recv_fill;
  st->epoll_evt |= EPOLLIN;
  tun_tracefp(st, "%s(%d): left=%zu recv_max=%zu\n",
              __func__, st_id(st), buf_len, st->recv_max);
  return;


 err_shutdown:
  sc_tunnel_abort(st);
}


static void sc_tunnel_recv_handle_pkt_data(struct sc_tunnel_state* st)
{
  assert( st->recv_pkt );
  struct sc_packet* pkt = st->recv_pkt;
  pkt->iov[0].iov_len += st->recv_rc;
  if( st->recv_rc == st->recv_max ) {
    tun_tracefp(st, "%s(%d): zc recv complete len=%zu\n",
                __func__, st_id(st), pkt->iov[0].iov_len);
    sc_forward2(st->recv_output->subnode->sh_links[0], pkt);
    st->recv_pkt = NULL;
    st->recv_fill = st->recv_buf;
    st->recv_read = st->recv_buf;
    st->recv_max = st->recv_buf_size;
  }
  else {
    st->recv_max -= st->recv_rc;
    tun_tracefp(st, "%s(%d): zc recv continues len=%zu left=%zu\n",
                __func__, st_id(st), pkt->iov[0].iov_len, st->recv_max);
  }
}


static void sc_tunnel_sock_cb(struct sc_callback* cb, void* event_info)
{
  struct sc_tunnel_state* st = cb->cb_private;

  tun_tracefp(st, "%s(%d,%p): Begin\n", __func__, st_id(st), event_info);

  unsigned epoll_evt_before = st->epoll_evt;

  if( (uintptr_t) event_info & EPOLLIN ) {
    assert( ! sc_callback_is_active(st->pool_cb) );
    ssize_t rc = recv(st->sock_fd, st->recv_fill, st->recv_max, MSG_DONTWAIT);
    if( rc > 0 ) {
      st->recv_fill += rc;
      st->recv_rc = rc;
      if( st->recv_pkt == NULL )
        sc_tunnel_recv_drain(st);
      else
        sc_tunnel_recv_handle_pkt_data(st);
    }
    else if( rc == 0 ) {
      tun_trace(st, "%s(%d): got EOF from wire\n", __func__, st_id(st));
      if( st->recv_pkt || st->recv_fill > st->recv_buf )
        tun_warn(st, "sc_tunnel(%d): WARNING: EOF in middle of a message\n",
                 st_id(st));
      goto shutdown;
    }
    else {
      switch( errno ) {
      case EAGAIN:
      case EINTR:
        break;
      default:
        tun_warn(st, "sc_tunnel(%d): WARNING: recv() failed (%d %s)\n",
                 st_id(st), errno, strerror(errno));
        goto shutdown;
      }
    }
  }

  if( (uintptr_t) event_info & EPOLLOUT ) {
    assert( ! sc_dlist_is_empty(&(st->inputs_ready)) );
    assert( st->epoll_evt & EPOLLOUT );
    if( sc_tunnel_send_send(st) )
      sc_tunnel_send_drain(st);
    if( sc_dlist_is_empty(&(st->inputs_ready)) ) {
      assert( st->epoll_evt & EPOLLOUT );
      st->epoll_evt &= ~EPOLLOUT;
    }
  }

  if( st->epoll_evt != epoll_evt_before && st->sock_fd >= 0 )
    sc_epoll_ctl(st->thread, EPOLL_CTL_MOD, st->sock_fd,
                 st->epoll_evt, st->sock_cb);

  tun_tracefp(st, "%s(%d): End\n", __func__, st_id(st));
  return;


 shutdown:
  if( st->recv_pkt ) {
    struct sc_packet_list pl;
    __sc_packet_list_init(&pl);
    sc_packet_list_append(&pl, st->recv_pkt);
    sc_pool_return_packets(st->recv_output->subnode->sh_pool, &pl);
    st->recv_pkt = NULL;
  }
  sc_tunnel_abort(st);
  st->epoll_evt &= ~EPOLLIN;
}


static void sc_tunnel_pool_cb(struct sc_callback* cb, void* event_info)
{
  struct sc_tunnel_state* st = cb->cb_private;
  tun_tracefp(st, "%s(%d): Begin\n", __func__, st_id(st));

  assert( ! (st->epoll_evt & EPOLLIN) );
  assert( st->recv_pkt == NULL );

  sc_tunnel_recv_drain(st);

  if( (st->epoll_evt & EPOLLIN) && st->sock_fd >= 0 )
    sc_epoll_ctl(sc_node_get_thread(st->node), EPOLL_CTL_MOD, st->sock_fd,
                 st->epoll_evt, st->sock_cb);

  tun_tracefp(st, "%s(%d): End\n", __func__, st_id(st));
}


static struct sc_node* sc_tunnel_select_subnode(struct sc_node* node,
                                                const char* name,
                                                char** new_name_out)
{
  if( name == NULL )
    name = "";

  struct sc_tunnel_state* st = node->nd_private;

  unsigned i;
  for( i = 0; i < st->inputs_n; i++ )
    if( strcmp(st->inputs[i]->name, name) == 0 )
      return st->inputs[i]->node;

  struct sc_node* subnode;
  int rc = sc_node_alloc(&subnode, st->attr, sc_node_get_thread(node),
                         &sc_tunnel_input_factory, NULL, 0);
  if( rc < 0 ) {
    sc_node_fwd_error(node, rc);
    return NULL;
  }

  struct tunnel_input* tunin = subnode->nd_private;
  tunin->st = st;
  SC_TEST( tunin->name = strdup(name) );
  sc_node_add_info_str(subnode, "sc_tunnel_input", tunin->name);

  int stream_id = (st->inputs_n)++;
  SC_REALLOC(&(st->inputs), st->inputs_n);
  st->inputs[stream_id] = tunin;
  tunin->stream_id = stream_id;

  ++st->eos_input_wait;

  return subnode;
}


static int sc_tunnel_add_link(struct sc_node* from_node, const char* link_name,
                              struct sc_node* to_node, const char* to_name_opt)
{
  struct sc_tunnel_state* st = from_node->nd_private;

  unsigned i;
  for( i = 0; i < st->outputs_n; i++ )
    if( strcmp(st->outputs[i]->name, link_name) == 0 )
      return sc_node_set_error(from_node, EINVAL, "sc_tunnel: ERROR: duplicate"
                               " outgoing link '%s'\n", link_name);

  struct sc_arg output_args[] = {
    SC_ARG_INT("with_pool", 1),
  };
  struct sc_node* subnode;
  int rc = sc_node_alloc(&subnode, st->attr, sc_node_get_thread(from_node),
                         &sc_subnode_helper_sc_node_factory, output_args,
                         sizeof(output_args)/sizeof(output_args[0]));
  if( rc < 0 ) {
    sc_node_fwd_error(from_node, rc);
    return rc;
  }

  struct sc_subnode_helper* sh = sc_subnode_helper_from_node(subnode);

  if( strcmp(link_name, "#exit") != 0 ) {
    struct tunnel_output* tunout;
    SC_TEST( tunout = calloc(1, sizeof(*tunout)) );
    tunout->st = st;
    tunout->subnode = sh;
    SC_TEST( tunout->name = strdup(link_name) );
    /* tunout->eos_seen = false; */
    /* tunout->connected = false; */
    sc_node_add_info_str(subnode, "sc_tunnel_output", tunout->name);

    ++(st->outputs_n);
    SC_REALLOC(&(st->outputs), st->outputs_n);
    st->outputs[st->outputs_n - 1] = tunout;
    sh->sh_private = tunout;

    sc_node_add_link(tunout->subnode->sh_node, "", to_node, to_name_opt);
    ++st->eos_output_wait;
  }
  else {
    st->exit = sh;
    sc_node_add_link(st->exit->sh_node, "", to_node, to_name_opt);
  }

  return 0;
}


static int gai_to_errno(int gai)
{
  /* Convert return value from getaddrinfo() to errno value. */
  switch( gai ) {
  case EAI_SOCKTYPE:
  case EAI_FAMILY:
  case EAI_BADFLAGS:
    /* These imply we've abused the API. */
    SC_TEST( 0 );

  case EAI_ADDRFAMILY:
    return ENOPROTOOPT;
  case EAI_AGAIN:
    return EAGAIN;
  case EAI_FAIL:
    return EREMOTEIO;
  case EAI_MEMORY:
    return ENOMEM;
  case EAI_SERVICE:
  case EAI_NODATA:
    return ENODATA;
  case EAI_NONAME:
    return EADDRNOTAVAIL;
  case EAI_SYSTEM:
    return errno;
  default:
    return ENAVAIL;
  }
}


static int sc_tunnel_open_sock(struct sc_tunnel_state* st, int passive_open,
                               const char* server_name,
                               const char* server_port)
{
  tun_trace(st, "%s(%d): %s server=%s port=%s\n", __func__, st_id(st),
            passive_open ? "passive" : "active", server_name, server_port);

  struct addrinfo hints, *ai;
  memset(&hints, 0, sizeof(hints));
  hints.ai_flags = AI_ADDRCONFIG;
  hints.ai_family = AF_INET;
  if( passive_open )
    hints.ai_flags |= AI_PASSIVE;
  int rc = getaddrinfo(server_name, server_port, &hints, &ai);
  if( rc != 0 )
    return sc_node_set_error(st->node, gai_to_errno(rc), "sc_tunnel: ERROR: "
                             "Unable to resolve %s:%s (passive=%d rc=%d %s)\n",
                             server_name ? server_name : "",
                             server_port ? server_port : "",
                             passive_open, rc, gai_strerror(rc));

  int sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
  if( sock < 0 ) {
    freeaddrinfo(ai);
    return sc_node_set_error(st->node, errno, "sc_tunnel: ERROR: "
                             "socket(%d, %d, %d) failed\n", ai->ai_family,
                             ai->ai_socktype, ai->ai_protocol);
  }

  if( ! passive_open ) {
    rc = connect(sock, ai->ai_addr, ai->ai_addrlen);
    freeaddrinfo(ai);
    if( rc < 0 ) {
      close(sock);
      return sc_node_set_error(st->node, errno, "sc_tunnel: ERROR: "
                               "connect(%s, %s) failed\n", server_name,
                               server_port);
    }
    return sock;
  }

  int one = 1;
  SC_TRY( setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) );

  rc = bind(sock, ai->ai_addr, ai->ai_addrlen);
  freeaddrinfo(ai);
  if( rc < 0 ) {
    close(sock);
    return sc_node_set_error(st->node, errno, "sc_tunnel: ERROR: "
                             "bind(%s, %s) failed\n",
                             server_name ? server_name : "INADDR_ANY",
                             server_port);
  }

  SC_TRY( listen(sock, 1) );

  struct sockaddr_storage sas;
  socklen_t sas_len = sizeof(sas);
  int conn;
  do
    conn = accept(sock, (void*) &sas, &sas_len);
  while( conn < 0 && errno == EINTR );
  close(sock);
  if( conn < 0 )
    return sc_node_set_error(st->node, errno,
                             "sc_tunnel: ERROR: accept() failed\n");

  return conn;
}


static void sc_tunnel_prep_done_cb(struct sc_callback* cb, void* event_info)
{
  struct sc_tunnel_state* st = cb->cb_private;
  sc_callback_free(cb);

  int i;
  for( i = 0; i < st->outputs_n; ++i ) {
    struct sc_pkt_pool* pool;
    pool = SC_PKT_POOL_FROM_POOL(st->outputs[i]->subnode->sh_pool);
    st->outputs[i]->max_msg_size = pool->pp_buf_size;
  }

  /* Start receive handling. */
  st->recv_fill = st->recv_buf;
  st->recv_read = st->recv_buf;
  st->recv_max = st->recv_buf_size;
  st->epoll_evt |= EPOLLIN;
  sc_epoll_ctl(sc_node_get_thread(st->node), EPOLL_CTL_ADD, st->sock_fd,
               st->epoll_evt, st->sock_cb);
}


static int sc_tunnel_prep(struct sc_node* node,
                          const struct sc_node_link*const* links, int n_links)
{
  struct sc_tunnel_state* st = node->nd_private;

  if( st->sock_fd < 0 ) {
    st->sock_fd = sc_tunnel_open_sock(st, st->passive_open,
                                      st->server_name, st->server_port);
    if( st->sock_fd < 0 )
      return -1;
  }
  if( st->remote_args ) {
    uint32_t remote_args_len = strlen(st->remote_args);
    uint32_t remote_args_len_ne = htonl(remote_args_len);
    struct iovec iov[] = {
      { &remote_args_len_ne, sizeof(remote_args_len_ne) },
      { st->remote_args,     remote_args_len            },
    };
    if( sendallv(st->sock_fd, iov, sizeof(iov) / sizeof(iov[0])) < 0 ) {
      close(st->sock_fd);
      st->sock_fd = -1;
      return sc_node_set_error(node, errno, "sc_tunnel: ERROR: Send error "
                               "while sending remote args\n");
    }
  }

  int rc;
  if( st->passive_open )
    rc = do_passive_handshake(st);
  else
    rc = do_active_handshake(st);
  if( rc < 0 ) {
    close(st->sock_fd);
    st->sock_fd = -1;
    return -1;
  }

  struct sc_callback* prep_done_cb;
  SC_TRY( sc_callback_alloc(&prep_done_cb, st->attr, st->thread) );
  prep_done_cb->cb_private = st;
  prep_done_cb->cb_handler_fn = sc_tunnel_prep_done_cb;
  sc_timer_expire_after_ns(prep_done_cb, 0);
  return 0;
}


static int sc_tunnel_init(struct sc_node* node, const struct sc_attr* attr,
                          const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_prep_fn = sc_tunnel_prep;
    nt->nt_add_link_fn = sc_tunnel_add_link;
    nt->nt_select_subnode_fn = sc_tunnel_select_subnode;
  }
  node->nd_type = nt;

  int passive_open, sock_fd, recv_buf_size, max_msg_size;
  const char *server_name, *server_port, *connect_to, *remote_args;

  if( sc_node_init_get_arg_int(&passive_open, node, "passive_open", -1) < 0 ||
      sc_node_init_get_arg_str(&server_name, node, "server_name", NULL) < 0 ||
      sc_node_init_get_arg_str(&server_port, node, "server_port", NULL) < 0 ||
      sc_node_init_get_arg_str(&connect_to, node, "connect_to", NULL)   < 0 ||
      sc_node_init_get_arg_int(&sock_fd, node, "socket_fd", -1)         < 0 ||
      sc_node_init_get_arg_str(&remote_args, node, "remote_args", NULL) < 0 ||
      sc_node_init_get_arg_int(&max_msg_size, node, "max_msg_size", 0)  < 0 ||
      sc_node_init_get_arg_int(&recv_buf_size, node,
                               "recv_buf_size", DEFAULT_RECV_BUF_SIZE)  < 0 )
    return -1;

  if( connect_to != NULL ) {
    if( passive_open > 0 )
      return sc_node_set_error(node, EINVAL, "sc_tunnel: ERROR: Invalid "
                               "combination of connect_to and passive_open\n");
    if( ! strrchr(connect_to, ':') )
      return sc_node_set_error(node, EINVAL, "sc_tunnel: ERROR: Bad "
                               "'connect_to' arg; expected HOST:PORT\n");
    passive_open = 0;
  }
  if( passive_open < 0 )
    passive_open = 1;

  if( sock_fd < 0 ) {
    if( passive_open ) {
      if( ! server_port )
        return sc_node_set_error(node, EINVAL, "sc_tunnel: ERROR: Must set "
                                 "server_port or socket_fd\n");
    }
    else {
      if( ! (connect_to || (server_name && server_port)) )
        return sc_node_set_error(node, EINVAL, "sc_tunnel: ERROR: Must set "
                                 "connect_to or server_name and server_port "
                                 "for active open\n");
    }
  }

  /* Allocate tunnel state */
  struct sc_tunnel_state* st;
  st = sc_thread_calloc(sc_node_get_thread(node), sizeof(*st));
  node->nd_private = st;
  st->node = node;
  st->thread = sc_node_get_thread(node);
  st->recv_buf_size = recv_buf_size;
  SC_TEST( st->recv_buf = malloc(st->recv_buf_size) );
  st->passive_open = passive_open;
  st->sock_fd = sock_fd;
  if( connect_to ) {
    /* NB. We already checked ':' was present in the string. */
    const char* colon = strrchr(connect_to, ':');
    asprintf(&(st->server_name), "%.*s", (int)(colon - connect_to), connect_to);
    st->server_port = strdup(colon + 1);
  }
  else {
    st->server_name = server_name ? strdup(server_name) : NULL;
    st->server_port = server_port ? strdup(server_port) : NULL;
  }
  st->remote_args = remote_args ? strdup(remote_args) : NULL;
  sc_dlist_init(&(st->inputs_ready));

  /* Install callbacks */
  SC_TRY(sc_callback_alloc(&st->sock_cb, attr, sc_node_get_thread(node)));
  st->sock_cb->cb_private = st;
  st->sock_cb->cb_handler_fn = sc_tunnel_sock_cb;
  SC_TRY(sc_callback_alloc(&st->pool_cb, attr, sc_node_get_thread(node)));
  st->pool_cb->cb_private = st;
  st->pool_cb->cb_handler_fn = sc_tunnel_pool_cb;

  st->attr = sc_attr_dup(attr);
  if( max_msg_size > 0 )
    sc_attr_set_int(st->attr, "buf_size", max_msg_size);
  SC_TRY(sc_attr_set_int(st->attr, "private_pool", 1));
  return 0;
}


const struct sc_node_factory sc_tunnel_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_tunnel",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_tunnel_init,
};

/**********************************************************************
 * tunnel_input
 */

static void sc_tunnel_input_pkts(struct sc_node* node,
                                 struct sc_packet_list* pl)
{
  struct tunnel_input* tunin = node->nd_private;
  struct sc_tunnel_state* st = tunin->st;

  tun_tracefp(st, "%s(%d,%s):\n", __func__, st_id(st), tunin->name);

  assert( ! tunin->eos_pending );
  bool was_empty = sc_packet_list_is_empty(&(tunin->backlog));
  sc_packet_list_append_list(&(tunin->backlog), pl);
  if( ! was_empty )
    return;

  was_empty = sc_dlist_is_empty(&(st->inputs_ready));
  sc_dlist_push_tail(&(st->inputs_ready), &(tunin->link));
  if( ! was_empty ) {
    /* We're in the middle of sending something already. */
    assert( st->epoll_evt & EPOLLOUT );
    return;
  }
  if( st->sock_fd < 0 )
    /* Connection has been shutdown. */
    return;

  sc_tunnel_send_prep_pkt(st, tunin);
  if( sc_tunnel_send_send(st) )
    sc_tunnel_send_drain(st);
  tun_tracefp(st, "%s(%d): End\n", __func__, st_id(st));
}


static void sc_tunnel_input_end_of_stream(struct sc_node* node)
{
  struct tunnel_input* tunin = node->nd_private;
  struct sc_tunnel_state* st = tunin->st;

  tun_trace(st, "%s(%d,%s):\n", __func__, st_id(st), tunin->name);

  SC_TEST( ! tunin->eos_pending );
  tunin->eos_pending = true;
  if( ! sc_packet_list_is_empty(&(tunin->backlog)) )
    return;

  bool was_empty = sc_dlist_is_empty(&(st->inputs_ready));
  sc_dlist_push_tail(&(st->inputs_ready), &(tunin->link));
  if( ! was_empty ) {
    /* We're in the middle of sending something already. */
    assert( st->epoll_evt & EPOLLOUT );
    return;
  }
  if( st->sock_fd < 0 )
    /* Connection has been shutdown. */
    return;

  sc_tunnel_send_prep_eos(st, tunin);
  sc_tunnel_send_send(st);
  /* There are no other sends in progress, so there can't be anything else
   * to do here.  ie. No need to call send_drain().
   */
}


static int sc_tunnel_input_prep(struct sc_node* node,
                                const struct sc_node_link*const* links,
                                int n_links)
{
  struct tunnel_input* tunin = node->nd_private;
  tunin->free_hop = sc_node_prep_get_link_or_free(node, "");
  return sc_node_prep_check_links(node);
}


static int sc_tunnel_input_init(struct sc_node* node,
                                const struct sc_attr* attr,
                                const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_pkts_fn = sc_tunnel_input_pkts;
    nt->nt_end_of_stream_fn = sc_tunnel_input_end_of_stream;
    nt->nt_prep_fn = sc_tunnel_input_prep;
  }
  node->nd_type = nt;

  struct tunnel_input* tunin;
  SC_TEST( tunin = calloc(1, sizeof(*tunin)) );
  node->nd_private = tunin;
  tunin->node = node;
  __sc_packet_list_init(&tunin->backlog);
  /* tunin->eos_pending = false; */
  tunin->stream_id = -1;
  return 0;
}


static const struct sc_node_factory sc_tunnel_input_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_tunnel_input",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_tunnel_input_init,
};

/** \endcond NODOC */
