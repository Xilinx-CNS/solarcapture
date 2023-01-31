/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#include <sc_internal.h>

#define SC_TYPE_TEMPLATE  <../test/nodes/sct_tickler_types_tmpl.h>
#define SC_DECLARE_TYPES  sct_tickler_stats_declare
#include <solar_capture/declare_types.h>

#include "sct.h"
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <assert.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <limits.h>
#include <netdb.h>


struct sc_ip4_hdr {
  uint8_t   ihl_ver;
  uint8_t   tos;
  uint16_t  tot_len;
  uint16_t  id;
  uint16_t  frag_off;
  uint8_t   ttl;
  uint8_t   protocol;
  uint16_t  check;
  uint32_t  saddr;
  uint32_t  daddr;
};


#define SC_IP4_HDR_LEN(ip)           (((ip)->ihl_ver & 0xf) << 2u)


struct sc_tcp_hdr {
  uint16_t  source;
  uint16_t  dest;
  uint32_t  seq;
  uint32_t  ack;
  uint8_t   hdr_len;
  uint8_t   flags;
  uint16_t  window;
  uint16_t  check;
  uint16_t  urg_ptr;
};


#define SC_TCP_HDR_LEN(tcp)      (((tcp)->hdr_len & 0xf0) >> 2u)

#define SC_TCP_FLAG_FIN          0x01
#define SC_TCP_FLAG_SYN          0x02
#define SC_TCP_FLAG_RST          0x04
#define SC_TCP_FLAG_PSH          0x08
#define SC_TCP_FLAG_ACK          0x10
#define SC_TCP_FLAG_URG          0x20


#define SC_TCP_FLAGS_FMT         "%s%s%s%s%s%s"
#define SC_TCP_FLAGS_ARG(f)                     \
  ((f) & SC_TCP_FLAG_FIN) ? "Fin":"",           \
  ((f) & SC_TCP_FLAG_SYN) ? "Syn":"",           \
  ((f) & SC_TCP_FLAG_RST) ? "Rst":"",           \
  ((f) & SC_TCP_FLAG_PSH) ? "Psh":"",           \
  ((f) & SC_TCP_FLAG_ACK) ? "Ack":"",           \
  ((f) & SC_TCP_FLAG_URG) ? "Urg":""


static const struct sc_node_factory tickler_ctl_sc_node_factory;


/**********************************************************************
 * Stuff common to client and server.
 */

struct tickler_common {
  struct sc_node*            node;
  struct sc_thread*          thread;
  const struct sc_node_link* next_hop_rx_consumed;
  const struct sc_node_link* next_hop_rx_not_for_me;
  const struct sc_node_link* next_hop_tx;
  struct sc_callback*        pool_cb;
  struct sc_pool*            pool;
  uint8_t                    lmac[6];
  int                        log;
  struct sct_tickler_stats*  stats;
  const void*                msg;
  int                        msg_len;

  struct sc_packet_list      free_bufs;
  struct sc_packet_list      rx_backlog;
};


static inline unsigned ts_to_ticks(const struct timespec* ts)
{
  return ((uint64_t) ts->tv_sec * 1000000000 + ts->tv_nsec) >> 10u;
}


static int init_tcp_pkt(struct tickler_common* tc, void* frame_buf,
                        const void* rmac,
                        unsigned lhost_ne, unsigned lport_ne,
                        unsigned rhost_ne, unsigned rport_ne,
                        unsigned seq_ne, unsigned ack_ne, unsigned tcp_flags,
                        const void* payload_src, int payload_len)
{
  struct ether_header* eth = frame_buf;
  memcpy(eth->ether_dhost, rmac, 6);
  memcpy(eth->ether_shost, tc->lmac, 6);
  eth->ether_type = htons(ETHERTYPE_IP);

  struct sc_ip4_hdr* ip = (void*) (eth + 1);
  struct sc_tcp_hdr* tcp = (void*) (ip + 1);
  uint8_t* payload_buf = (void*) (tcp + 1);
  if( tcp_flags & SC_TCP_FLAG_SYN )
    payload_buf += 4;  /* mss option */
  uint8_t* payload_end = payload_buf + payload_len;

  ip->ihl_ver = (4u << 4u) | (sizeof(*ip) >> 2u);
  ip->tos = 0;
  ip->tot_len = (uint8_t*) payload_end - (uint8_t*) ip;
  ip->tot_len = htons(ip->tot_len);
  ip->id = 0;
  ip->frag_off = 0;
  ip->ttl = 0;  /* limit potential damage! */
  ip->protocol = IPPROTO_TCP;
  ip->check = 0;
  ip->saddr = lhost_ne;
  ip->daddr = rhost_ne;

  tcp->source = lport_ne;
  tcp->dest = rport_ne;
  tcp->seq = seq_ne;
  tcp->ack = ack_ne;
  tcp->hdr_len = (payload_buf - (uint8_t*) tcp) << 2u;
  tcp->flags = tcp_flags;
  tcp->window = htons(5840);
  tcp->check = 0;
  tcp->urg_ptr = 0;

  if( tcp_flags & SC_TCP_FLAG_SYN ) {
    struct mss {
      uint8_t kind;
      uint8_t len;
      uint16_t mss;
    };
    struct mss* mss = (void*) (tcp + 1);
    mss->kind = 2;
    mss->len = 4;
    mss->mss = htons(1460);
  }

  memcpy(payload_buf, payload_src, payload_len);

  if( tc->log )
    fprintf(stderr, "[%s] TX %u:%d "SC_TCP_FLAGS_FMT" plen=%d flen=%d "
            "%08x,%08x\n", tc->node->nd_name, ntohl(lhost_ne), ntohs(lport_ne),
            SC_TCP_FLAGS_ARG(tcp_flags), payload_len,
            (int) ((uint8_t*) payload_end - (uint8_t*) eth),
            ntohl(seq_ne), ntohl(ack_ne));
  return (uint8_t*) payload_end - (uint8_t*) eth;
}


static int init_reply(struct tickler_common* tc,
                      const struct ether_header* eth,
                      const struct sc_ip4_hdr* ip,
                      const struct sc_tcp_hdr* tcp,
                      unsigned tcp_flags, int ack_bytes,
                      const void* payload, int payload_len)
{
  unsigned ack = ntohl(tcp->seq) + ack_bytes;
  return init_tcp_pkt(tc, tc->free_bufs.head->iov[0].iov_base,
                      eth->ether_shost,
                      ip->daddr, tcp->dest, ip->saddr, tcp->source,
                      tcp->ack, htonl(ack), tcp_flags, payload, payload_len);
}


static void do_send(struct tickler_common* tc, int len)
{
  struct sc_packet* pkt = __sc_packet_list_pop_head(&tc->free_bufs);
  pkt->frame_len = len;
  pkt->iov[0].iov_len = len;
  sc_forward(tc->node, tc->next_hop_tx, pkt);
}


static void send_reply(struct tickler_common* tc,
                       const struct ether_header* eth,
                       const struct sc_ip4_hdr* ip,
                       const struct sc_tcp_hdr* tcp,
                       unsigned tcp_flags, int ack_bytes,
                       const void* payload, int payload_len)
{
  int len;
  len = init_reply(tc, eth, ip, tcp, tcp_flags,
                   ack_bytes, payload, payload_len);
  do_send(tc, len);
}


static int get_buf(struct tickler_common* tc)
{
  if( sc_packet_list_is_empty(&tc->free_bufs) ) {
    __sc_packet_list_init(&tc->free_bufs);
    if( sc_pool_get_packets(&tc->free_bufs, tc->pool, 1, 32) < 0 ) {
      sc_pool_on_threshold(tc->pool, tc->pool_cb, 16);
      return 0;
    }
  }
  return 1;
}


static int common_prep(struct tickler_common* tc,
                       const struct sc_node_link*const* links, int n_links)
{
  struct sc_node* node = tc->node;
  tc->next_hop_rx_consumed = sc_node_prep_get_link_or_free(node, "consumed");
  tc->next_hop_rx_not_for_me = sc_node_prep_get_link_or_free(node, "");
  tc->next_hop_tx = sc_node_prep_get_link_or_free(node, "tx");
  if( sc_node_prep_check_links(node) < 0 )
    return -1;

  struct sc_attr* attr;
  SC_TRY(sc_attr_alloc(&attr));
  SC_TRY(sc_attr_set_int(attr, "private_pool", 1));
  SC_TRY(sc_node_prep_get_pool(&tc->pool, attr, node, &tc->next_hop_tx, 1));
  sc_attr_free(attr);

  sc_node_prep_does_not_forward(node);
  sc_node_prep_link_forwards_from_node(node, tc->next_hop_rx_consumed, node);
  sc_node_prep_link_forwards_from_node(node, tc->next_hop_rx_not_for_me, node);
  return 0;
}


/**********************************************************************
 * Client implementation.
 */

struct tickler_client {
  struct tickler_common      c;
  struct sc_node*            ctl_node;
  uint8_t                    rmac[6];
  unsigned                   rhost_ne;
  uint16_t                   rport_ne;
  double                     alpha;
  uint64_t*                  rq_map;

  unsigned                   first_ip;
  unsigned                   last_ip;
  unsigned                   current_ip;
  int                        first_port;
  int                        last_port;
  int                        current_port;
  unsigned                   isn;
  unsigned                   syn_backlog;
};


struct tickler_ctl {
  struct tickler_client*     tickler;
  const struct sc_node_link* next_hop;
};


static int init_syn(struct tickler_client* st)
{
  return init_tcp_pkt(&st->c, st->c.free_bufs.head->iov[0].iov_base,
                      st->rmac, htonl(st->current_ip), htons(st->current_port),
                      st->rhost_ne, st->rport_ne,
                      st->isn, 0, SC_TCP_FLAG_SYN, NULL, 0);
}


static void client_recv(struct tickler_client* st,
                        struct sc_packet* recv_frame)
{
  const struct ether_header* eth = recv_frame->iov[0].iov_base;
  /* NB. No vlan support yet. */
  if( eth->ether_type != htons(ETHERTYPE_IP) )
    goto not_for_me;

  const struct sc_ip4_hdr* ip = (void*) (eth + 1);
  if( ip->protocol != IPPROTO_TCP )
    goto not_for_me;
  if( ip->saddr != st->rhost_ne )
    goto not_for_me;
  unsigned laddr = ntohl(ip->daddr);
  if( laddr < st->first_ip || laddr > st->last_ip )
    goto not_for_me;

  TEST(SC_IP4_HDR_LEN(ip) == sizeof(*ip));
  const struct sc_tcp_hdr* tcp = (void*) (ip + 1);
  if( tcp->source != st->rport_ne )
    goto not_for_me;
  int lport = ntohs(tcp->dest);
  if( lport < st->first_port || lport > st->last_port )
    goto not_for_me;

  const uint8_t* payload = (void*) ((uint8_t*) tcp + SC_TCP_HDR_LEN(tcp));
  const uint8_t* payload_end = (void*) ((uint8_t*) ip + ntohs(ip->tot_len));

  if( st->c.log )
    fprintf(stderr, "[%s] RX %u:%d "SC_TCP_FLAGS_FMT" plen=%d flen=%d "
            "%08x,%08x\n", st->c.node->nd_name, laddr, lport,
            SC_TCP_FLAGS_ARG(tcp->flags),
            (int) (payload_end - payload), recv_frame->frame_len,
            ntohl(tcp->seq), ntohl(tcp->ack));

  if( tcp->flags == (SC_TCP_FLAG_SYN | SC_TCP_FLAG_ACK) ) {
    /* Ack the SYNACK, send request, FIN. */
    send_reply(&st->c, eth, ip, tcp,
               SC_TCP_FLAG_ACK | SC_TCP_FLAG_PSH | SC_TCP_FLAG_FIN,
               1, st->c.msg, st->c.msg_len);
    ++(st->c.stats->tx_msg);
    sc_forward(st->c.node, st->c.next_hop_rx_consumed, recv_frame);
    return;
  }

  int payload_len = payload_end - payload;
  int ack_bytes = payload_len + !!(tcp->flags & SC_TCP_FLAG_FIN);

  if( (tcp->flags & (SC_TCP_FLAG_PSH | SC_TCP_FLAG_FIN)) && ack_bytes ) {
  //if( tcp->flags & SC_TCP_FLAG_FIN ) {
    send_reply(&st->c, eth, ip, tcp, SC_TCP_FLAG_ACK, ack_bytes, NULL, 0);
    ++(st->c.stats->tx_ack);
  }
  if( payload_len ) {
    ++(st->c.stats->rx_msg);
    st->c.stats->rx_bytes += payload_len;
    if( tcp->flags & SC_TCP_FLAG_PSH ) {
      unsigned rq_id = (laddr << 16) | lport;
      if( ! (st->rq_map[rq_id >> 6u] & (1llu << (rq_id & 63u))) ) {
        st->rq_map[rq_id >> 6u] |= 1llu << (rq_id & 63u);
        ++(st->c.stats->rx_msg_psh);
        struct timespec ts;
        sc_thread_get_time(st->c.thread, &ts);
        uint64_t now_ns = (uint64_t) ts.tv_sec * 1000000000 + ts.tv_nsec;
        unsigned isn = ntohl(tcp->ack) - 1/*syn*/ - st->c.msg_len - 1/*fin*/;
        isn = htonl(isn);
        unsigned latency_ns = (unsigned) ((now_ns >> 10) - isn) << 10u;
        st->c.stats->latency = st->alpha * latency_ns * 1e-9 +    \
          (1.0 - st->alpha) * st->c.stats->latency;
        if( st->c.log )
          fprintf(stderr, "[%s] RX rq_id=%x isn=%08x latency=%uus\n",
                  st->c.node->nd_name, rq_id, ntohl(isn), latency_ns / 1000);
      }
      else {
        ++(st->c.stats->rx_msg_dup);
        if( st->c.log )
          fprintf(stderr, "[%s] !!DUP!! rq_id=%x\n",
                  st->c.node->nd_name, rq_id);
      }
    }
  }
  sc_forward(st->c.node, st->c.next_hop_rx_consumed, recv_frame);
  return;

 not_for_me:
  ++(st->c.stats->not_for_me);
  sc_forward(st->c.node, st->c.next_hop_rx_not_for_me, recv_frame);
}


static void client_new_connection(struct tickler_client* st)
{
  if( 1 ) {
    struct timespec ts;
    sc_thread_get_time(st->c.thread, &ts);
    st->isn = ts_to_ticks(&ts);
  }
  else {
    st->isn = rand();
  }
  do_send(&st->c, init_syn(st));
  if( st->current_port == st->last_port ) {
    st->current_port = st->first_port;
    if( st->current_ip == st->last_ip )
      st->current_ip = st->first_ip;
    else
      ++(st->current_ip);
  }
  else {
    ++(st->current_port);
  }
  ++(st->c.stats->tx_syn);
}


static void client_go(struct tickler_client* st)
{
  if( sc_callback_is_active(st->c.pool_cb) )
    return;

  while( ! sc_packet_list_is_empty(&st->c.rx_backlog) ) {
    if( ! get_buf(&st->c) )
      return;
    client_recv(st, sc_packet_list_pop_head(&st->c.rx_backlog));
  }

  while( st->syn_backlog ) {
    if( ! get_buf(&st->c) )
      return;
    client_new_connection(st);
    --st->syn_backlog;
  }
}


static void client_pool_not_empty(struct sc_callback* cb, void* event_info)
{
  struct tickler_client* st = cb->cb_private;
  client_go(st);
}


static void client_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct tickler_client* st = node->nd_private;
  sc_packet_list_append_list(&st->c.rx_backlog, pl);
  client_go(st);
}


static int client_prep(struct sc_node* node,
                       const struct sc_node_link*const* links, int n_links)
{
  struct tickler_client* st = node->nd_private;
  return common_prep(&st->c, links, n_links);
}


static struct sc_node* tickler_select_subnode(struct sc_node* node,
                                                 const char* name,
                                                 char** new_name_out)
{
  struct tickler_client* st = node->nd_private;
  if( name != NULL && ! strcmp(name, "trigger") )
    return st->ctl_node;
  else
    return node;
}


static int parse_mac(uint8_t* mac, const char* s)
{
  unsigned u[6];
  int i;
  if( sscanf(s, "%x:%x:%x:%x:%x:%x",
             &u[0], &u[1], &u[2], &u[3], &u[4], &u[5]) != 6 )
    return -1;
  for( i = 0; i < 6; ++i )
    mac[i] = u[i];
  return 0;
}


static int parse_ip(uint32_t* pip, const char* s)
{
  struct addrinfo hints, *ai;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  int rc = getaddrinfo(s, NULL, &hints, &ai);
  if( rc != 0 )
    return rc;
  const struct sockaddr_in* sin = (void*) ai->ai_addr;
  *pip = sin->sin_addr.s_addr;
  return 0;
}


static int parse_port(uint16_t* pport, const char* s)
{
  struct addrinfo hints, *ai;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  int rc = getaddrinfo(NULL, s, &hints, &ai);
  if( rc != 0 )
    return rc;
  const struct sockaddr_in* sin = (void*) ai->ai_addr;
  *pport = sin->sin_port;
  return 0;
}


static int common_init(struct tickler_common* tc, struct sc_node* node,
                       const struct sc_attr* attr, int is_client)
{
  const char* s;

  tc->node = node;
  tc->thread = sc_node_get_thread(node);
  sc_packet_list_init(&tc->rx_backlog);
  __sc_packet_list_init(&tc->free_bufs);

  if( sc_node_init_get_arg_str(&s, node, "local_mac", NULL) != 0 )
    return sc_node_set_error(node, EINVAL, "sct_tickler: required arg "
                             "'local_mac' missing\n");
  if( parse_mac(tc->lmac, s) != 0 )
    return sc_node_set_error(node, EINVAL,
                             "sct_tickler: bad local_mac=%s\n", s);

  if( sc_node_init_get_arg_int(&tc->log, node, "log", 0) < 0 )
    return sc_node_set_error(node, EINVAL, "sct_tickler: bad arg 'log'\n");

  s = is_client ? "request" : "response";
  if( sc_node_init_get_arg_str(&s, node, s, NULL) != 0 )
    return sc_node_set_error(node, EINVAL, "sct_tickler: required arg "
                             "'request' missing\n");
  tc->msg = strdup(s);
  tc->msg_len = strlen(tc->msg);


  sct_tickler_stats_declare(sc_thread_get_session(tc->thread));
  sc_node_export_state(node, "sct_tickler_stats",
                       sizeof(struct sct_tickler_stats), &tc->stats);

  return 0;
}


static int client_init(struct sc_node* node, const struct sc_attr* attr)
{
  struct sc_thread* thread = sc_node_get_thread(node);
  const char* s;
  int rc;

  struct sc_node_type* nt = (struct sc_node_type*) node->nd_type;
  nt->nt_prep_fn = client_prep;
  nt->nt_pkts_fn = client_pkts;
  nt->nt_select_subnode_fn = tickler_select_subnode;

  struct tickler_client* st;
  st = sc_thread_calloc(thread, sizeof(*st));
  node->nd_private = st;
  if( (rc = common_init(&st->c, node, attr, 1)) < 0 )
    return rc;

  if( sc_node_init_get_arg_str(&s, node, "server_mac", NULL) != 0 ) {
    sc_node_set_error(node, EINVAL, "sct_tickler: required arg 'server_mac' "
                      "missing\n");
    goto error;
  }
  if( parse_mac(st->rmac, s) != 0 ) {
    sc_node_set_error(node, EINVAL, "sct_tickler: bad server_mac=%s\n", s);
    goto error;
  }

  const char *rhost, *rport;
  if( sc_node_init_get_arg_str(&rhost, node, "server", NULL) != 0 ) {
    sc_node_set_error(node, EINVAL, "sct_tickler: required arg 'server' "
                      "missing\n");
    goto error;
  }
  if( parse_ip(&st->rhost_ne, rhost) != 0 ) {
    sc_node_set_error(node, EINVAL, "sct_tickler: bad server=%s\n", rhost);
    goto error;
  }

  if( sc_node_init_get_arg_str(&rport, node, "server_port", "http") < 0 ) {
    sc_node_set_error(node, EINVAL, "sct_tickler: bad arg 'server_port'\n");
    goto error;
  }
  if( parse_port(&st->rport_ne, rport) != 0 ) {
    sc_node_set_error(node, EINVAL, "sct_tickler: bad server_port=%s\n", rport);
    goto error;
  }

  if( sc_node_init_get_arg_dbl(&st->alpha, node, "latency_alpha", 0.001) < 0 ) {
    sc_node_set_error(node, EINVAL, "sct_tickler: bad arg "
                      "'latency_alpha'\n");
    goto error;
  }

  if( sc_node_init_get_arg_str(&s, node, "local_ips", NULL) != 0 ) {
    sc_node_set_error(node, EINVAL, "sct_tickler: required arg 'local_ips' "
                      "missing\n");
    goto error;
  }
  if( strchr(s, '-') ) {
    char* tmp = strdup(s);
    char* tmp2 = strchr(tmp, '-');
    *tmp2++ = '\0';
    st->first_ip = ntohl(inet_addr(tmp));
    st->last_ip = ntohl(inet_addr(tmp2));
    free(tmp);
  }
  else {
    st->first_ip = ntohl(inet_addr(s));
    st->last_ip = st->first_ip;
  }

  if( sc_node_init_get_arg_str(&s, node, "local_ports", NULL) != 0 ) {
    sc_node_set_error(node, EINVAL, "sct_tickler: required arg "
                      "'local_ports' missing\n");
    goto error;
  }
  char dummy;
  if( sscanf(s, "%d-%d%c", &st->first_port, &st->last_port, &dummy) != 2 ) {
    sc_node_set_error(node, EINVAL, "sct_tickler: bad local_ports=%s; "
                      "expected <first_port>-<last_port>\n", s);
    goto error;
  }

  TEST(sc_callback_alloc(&st->c.pool_cb, attr, thread) == 0);
  st->c.pool_cb->cb_private = st;
  st->c.pool_cb->cb_handler_fn = client_pool_not_empty;
  st->current_ip = st->first_ip;
  st->current_port = st->first_port;
  st->rq_map = calloc(1u << (32u - 6u), sizeof(uint64_t));
  TEST(st->rq_map != NULL);

  { /* Allocate the 'ctl' node. */
    struct sc_attr* attr;
    SC_TRY(sc_attr_alloc(&attr));
    int rc = sc_node_alloc(&st->ctl_node, attr, thread,
                           &tickler_ctl_sc_node_factory, NULL, 0);
    sc_attr_free(attr);
    if( rc < 0 ) {
      sc_node_fwd_error(node, rc);
      goto error;
    }
    struct tickler_ctl* ctl = st->ctl_node->nd_private;
    ctl->tickler = st;
  }

  return 0;

 error:
  sc_thread_mfree(thread, st);
  return -1;
}


/**********************************************************************
 * Server implementation.
 */

struct tickler_server {
  struct tickler_common      c;
  struct sct_tickler_stats*  stats;
  unsigned                   lhost_ne;
  uint16_t                   lport_ne;
  int                        keepalive;
};


static void server_recv(struct tickler_server* svr,
                        struct sc_packet* recv_frame)
{
  const struct ether_header* eth = recv_frame->iov[0].iov_base;
  /* NB. No vlan support yet. */
  if( eth->ether_type != htons(ETHERTYPE_IP) )
    goto not_for_me;

  const struct sc_ip4_hdr* ip = (void*) (eth + 1);
  if( ip->protocol != IPPROTO_TCP )
    goto not_for_me;
  if( ip->daddr != svr->lhost_ne )
    goto not_for_me;

  TEST(SC_IP4_HDR_LEN(ip) == sizeof(*ip));
  const struct sc_tcp_hdr* tcp = (void*) (ip + 1);
  if( tcp->dest != svr->lport_ne )
    goto not_for_me;

  const uint8_t* payload = (void*) ((uint8_t*) tcp + SC_TCP_HDR_LEN(tcp));
  const uint8_t* payload_end = (void*) ((uint8_t*) ip + ntohs(ip->tot_len));

  if( svr->c.log )
    fprintf(stderr, "[%s] RX %u:%d "SC_TCP_FLAGS_FMT" plen=%d flen=%d "
            "%08x,%08x\n", svr->c.node->nd_name, ntohl(ip->saddr),
            ntohs(tcp->source), SC_TCP_FLAGS_ARG(tcp->flags),
            (int) (payload_end - payload), recv_frame->frame_len,
            ntohl(tcp->seq), ntohl(tcp->ack));

  if( tcp->flags == SC_TCP_FLAG_SYN ) {
    send_reply(&svr->c, eth, ip, tcp, SC_TCP_FLAG_SYN | SC_TCP_FLAG_ACK,
               1, NULL, 0);
    ++(svr->c.stats->tx_syn);
    sc_forward(svr->c.node, svr->c.next_hop_rx_consumed, recv_frame);
    return;
  }

  int payload_len = payload_end - payload;
  int ack_bytes = payload_len + !!(tcp->flags & SC_TCP_FLAG_FIN);

  if( payload_len ) {
    /* Received request, send reply. */
    unsigned tcp_flags = SC_TCP_FLAG_ACK | SC_TCP_FLAG_PSH;
    if( ! svr->keepalive ) {
      tcp_flags |= SC_TCP_FLAG_FIN;
      ++(svr->c.stats->tx_fin);
    }
    send_reply(&svr->c, eth, ip, tcp, tcp_flags, ack_bytes,
               svr->c.msg, svr->c.msg_len);
    ++(svr->c.stats->tx_msg);
  }
  else if( ack_bytes ) {
    /* Received FIN.  If keepalive, then respond with FIN.  Otherwise we've
     * already sent a FIN with reply, so just ACK.
     */
    unsigned tcp_flags = SC_TCP_FLAG_ACK;
    if( svr->keepalive ) {
      tcp_flags |= SC_TCP_FLAG_FIN;
      ++(svr->c.stats->tx_fin);
    }
    else {
      ++(svr->c.stats->tx_ack);
    }
    send_reply(&svr->c, eth, ip, tcp, tcp_flags, ack_bytes, NULL, 0);
  }
  else {
    /* Just an ACK. */
    ++(svr->c.stats->rx_ack);
  }
  sc_forward(svr->c.node, svr->c.next_hop_rx_consumed, recv_frame);
  return;

 not_for_me:
  ++(svr->c.stats->not_for_me);
  sc_forward(svr->c.node, svr->c.next_hop_rx_not_for_me, recv_frame);
}


static void server_go(struct tickler_server* svr)
{
  if( sc_callback_is_active(svr->c.pool_cb) )
    return;

  while( ! sc_packet_list_is_empty(&svr->c.rx_backlog) ) {
    if( ! get_buf(&svr->c) )
      return;
    server_recv(svr, sc_packet_list_pop_head(&svr->c.rx_backlog));
  }
}


static void server_pool_not_empty(struct sc_callback* cb, void* event_info)
{
  struct tickler_server* svr = cb->cb_private;
  server_go(svr);
}


static void server_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct tickler_server* svr = node->nd_private;
  sc_packet_list_append_list(&svr->c.rx_backlog, pl);
  server_go(svr);
}


static int server_prep(struct sc_node* node,
                       const struct sc_node_link*const* links, int n_links)
{
  struct tickler_server* svr = node->nd_private;
  return common_prep(&svr->c, links, n_links);
}


static int server_init(struct sc_node* node, const struct sc_attr* attr)
{
  struct sc_thread* thread = sc_node_get_thread(node);
  int rc;

  struct sc_node_type* nt = (struct sc_node_type*) node->nd_type;
  nt->nt_prep_fn = server_prep;
  nt->nt_pkts_fn = server_pkts;

  struct tickler_server* svr;
  svr = sc_thread_calloc(thread, sizeof(*svr));
  node->nd_private = svr;
  if( (rc = common_init(&svr->c, node, attr, 0)) < 0 )
    return rc;

  const char *lhost, *lport;
  if( sc_node_init_get_arg_str(&lhost, node, "local_ip", NULL) != 0 )
    return sc_node_set_error(node, EINVAL,
                             "sct_tickler: required arg 'local_ip' missing\n");
  if( parse_ip(&svr->lhost_ne, lhost) != 0 )
    return sc_node_set_error(node, EINVAL,
                             "sct_tickler: bad local_ip=%s\n", lhost);

  if( sc_node_init_get_arg_str(&lport, node, "local_port", "http") < 0 )
    return sc_node_set_error(node, EINVAL,
                             "sct_tickler: bad arg 'local_port'\n");
  if( parse_port(&svr->lport_ne, lport) != 0 )
    return sc_node_set_error(node, EINVAL,
                             "sct_tickler: bad local_port=%s\n", lport);

  if( sc_node_init_get_arg_int(&svr->keepalive, node, "keepalive", 0) < 0 )
    return sc_node_set_error(node, EINVAL,
                             "sct_tickler: bad arg 'keepalive'\n");

  TEST(sc_callback_alloc(&svr->c.pool_cb, attr, thread) == 0);
  svr->c.pool_cb->cb_private = svr;
  svr->c.pool_cb->cb_handler_fn = server_pool_not_empty;

  return 0;
}


/**********************************************************************
 * sct_tickler factory.
 */

static int tickler_init(struct sc_node* node, const struct sc_attr* attr,
                        const struct sc_node_factory* factory)
{
  struct sc_node_type* nt;
  sc_node_type_alloc(&nt, NULL, factory);
  node->nd_type = nt;

  const char* s;
  if( sc_node_init_get_arg_str(&s, node, "server", NULL) == 0 )
    return client_init(node, attr);
  else
    return server_init(node, attr);
}


const struct sc_node_factory sct_tickler_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sct_tickler",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = tickler_init,
};


/**********************************************************************
 * sct_tickler_ctl
 */

static void tickler_ctl_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct tickler_ctl* ctl = node->nd_private;
  ctl->tickler->syn_backlog += pl->num_pkts;
  sc_forward_list(node, ctl->next_hop, pl);
  client_go(ctl->tickler);
}


static int tickler_ctl_prep(struct sc_node* node,
                               const struct sc_node_link*const* links,
                               int n_links)
{
  struct tickler_ctl* ctl = node->nd_private;
  ctl->next_hop = sc_node_prep_get_link_or_free(node, "");
  return sc_node_prep_check_links(node);
}


static int tickler_ctl_init(struct sc_node* node,
                               const struct sc_attr* attr,
                               const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_pkts_fn = tickler_ctl_pkts;
    nt->nt_prep_fn = tickler_ctl_prep;
  }
  node->nd_type = nt;

  struct tickler_ctl* ctl;
  ctl = sc_thread_calloc(sc_node_get_thread(node), sizeof(*ctl));
  node->nd_private = ctl;
  return 0;
}


static const struct sc_node_factory tickler_ctl_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sct_tickler_ctl",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = tickler_ctl_init,
};
