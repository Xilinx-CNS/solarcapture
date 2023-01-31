/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#define SC_API_VER 4
#include <solar_capture.h>
#include <solar_capture/nodes/subnode_helper.h>

#include "sct.h"
#include <limits.h>
#include <errno.h>
#include <time.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netdb.h>


#ifndef ETHERTYPE_8021Q
# define ETHERTYPE_8021Q  0x8100
#endif


struct mode1_hdr {
  char      stuff[20];
  uint16_t  inner_ip_offset;
};


struct m1e_state {
  /* Resources (constant after init and prep). */
  struct sc_node*            node;
  const struct sc_node_link* next_hop;
  struct sc_pool*            pool;
  struct sc_attr*            attr;
  struct sc_subnode_helper*  snh;
  int                        pad;
  uint32_t                   outer_saddr;
  uint32_t                   outer_daddr;
  uint8_t                    outer_ether_dhost[6];
  uint8_t                    outer_ether_shost[6];

  /* State. */
  unsigned                   rand_seed;
  int                        ip_id;
};


static void m1e_handle_backlog(struct sc_subnode_helper* snh)
{
  struct m1e_state* st = snh->sh_private;

  /* Find offset of IP header in frame to be encapsulated.  We support
   * frames with a single VLAN tag (using standard 802.1Q tag 0x8100).
   */
  struct sc_packet* in_pkt = sc_packet_list_pop_head(&(snh->sh_backlog));
  const struct ether_header* in_eth = in_pkt->iov[0].iov_base;
  const uint16_t* p_ether_type = &in_eth->ether_type;
  if( *p_ether_type == htons(ETHERTYPE_8021Q) )
    p_ether_type += 2;
  switch( ntohs(*p_ether_type) ) {
  case ETHERTYPE_IP:
  case ETHERTYPE_IPV6:
    break;
  default:
    /* We only encapsulate IP frames. */
    sc_forward(snh->sh_node, snh->sh_free_link, in_pkt);
    return;
  }
  int in_pkt_skip = (uintptr_t) (p_ether_type + 1) - (uintptr_t) in_eth;

  struct sc_packet_list pl;
  __sc_packet_list_init(&pl);
  sc_pool_get_packets(&pl, st->pool, 1, 1);
  /* sc_subnode_helper should only invoke us if the pool has at least
   * sh_pool_threshold buffers available.
   */
  TEST( pl.num_pkts == 1 );
  struct sc_packet* out_pkt = pl.head;
  out_pkt->ts_sec = in_pkt->ts_sec;
  out_pkt->ts_nsec = in_pkt->ts_nsec;

  struct ether_header* eth = out_pkt->iov[0].iov_base;
  struct iphdr* ip = (void*) (eth + 1);
  struct mode1_hdr* m1hdr = (void*) (ip + 1);
  uint8_t* inner_ip = (uint8_t*) (m1hdr + 1) + st->pad;
  uint8_t* end = inner_ip + (in_pkt->frame_len - in_pkt_skip);

  memcpy(eth->ether_dhost, st->outer_ether_dhost, 6);
  memcpy(eth->ether_shost, st->outer_ether_shost, 6);
  eth->ether_type = htons(ETHERTYPE_IP);

  ip->ihl = sizeof(*ip) >> 2;
  ip->version = 4;
  ip->tos = 0;
  ip->tot_len = (uintptr_t) end - (uintptr_t) ip;
  ip->tot_len = htons(ip->tot_len);
  ip->id = st->ip_id++;
  ip->frag_off = 0;
  ip->ttl = 1;
  ip->protocol = 254;
  ip->check = 0;
  ip->saddr = st->outer_saddr ? st->outer_saddr : rand_r(&(st->rand_seed));
  ip->daddr = st->outer_daddr ? st->outer_daddr : rand_r(&(st->rand_seed));

  m1hdr->inner_ip_offset = htons((uint16_t)st->pad);

  out_pkt->frame_len = (uintptr_t) inner_ip - (uintptr_t) eth;
  out_pkt->iov[0].iov_len = out_pkt->frame_len;

  struct sc_iovec_ptr iovp;
  sc_iovec_ptr_init_packet(&iovp, in_pkt);
  TEST( sc_iovec_ptr_skip(&iovp, in_pkt_skip) == in_pkt_skip );
  TEST( sc_packet_append_iovec_ptr(out_pkt, NULL, &iovp, INT_MAX) == 0 );
  sc_forward(snh->sh_node, snh->sh_free_link, in_pkt);
  sc_forward(st->node, st->next_hop, out_pkt);
}


static int m1e_prep(struct sc_node* node,
                    const struct sc_node_link*const* links, int n_links)
{
  struct m1e_state* st = node->nd_private;
  st->next_hop = sc_node_prep_get_link_or_free(node, "");
  TEST(sc_node_prep_get_pool(&st->pool, st->attr, node, &st->next_hop, 1) == 0);
  st->snh->sh_pool = st->pool;
  st->snh->sh_pool_threshold = 1;
  return sc_node_prep_check_links(node);
}


static struct sc_node* m1e_select_subnode(struct sc_node* node,
                                          const char* name, char** new_name_out)
{
  struct m1e_state* st = node->nd_private;
  return st->snh->sh_node;
}


static int get_arg_str(const char** s, struct sc_node* node,
                       const char* name, int required)
{
  if( sc_node_init_get_arg_str(s, node, name, NULL) < 0 )
    return -1;
  if( required && *s == NULL )
    return sc_node_set_error(node, EINVAL, "sct_mode1_encap: ERROR: required "
                             "arg '%s' not provided\n", name);
  return (*s == NULL) ? 1 : 0;
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
  freeaddrinfo(ai);
  return 0;
}


static int get_arg_ip(uint32_t* pip, struct sc_node* node,
                      const char* name, int required)
{
  const char* s;
  int rc;
  if( get_arg_str(&s, node, name, required) < 0 )
    return -1;
  if( s != NULL && (rc = parse_ip(pip, s)) < 0 )
    return sc_node_set_error(node, EINVAL, "sct_mode1_encap: ERROR: could not "
                             "resolve '%s' to an IP address for arg %s (%s)\n",
                             s, name, gai_strerror(rc));
  return (s == NULL) ? 1 : 0;
}


static int parse_mac(uint8_t* mac, const char* s)
{
  unsigned u[6];
  int i;
  char c;
  if( sscanf(s, "%x:%x:%x:%x:%x:%x%c",
             &u[0], &u[1], &u[2], &u[3], &u[4], &u[5], &c) != 6 )
    return -1;
  for( i = 0; i < 6; ++i ) {
    if( u[i] > 255 )
      return -1;
    mac[i] = u[i];
  }
  return 0;
}


static int get_arg_mac(uint8_t* mac, struct sc_node* node,
                       const char* name, int required)
{
  const char* s;
  if( get_arg_str(&s, node, name, required) < 0 )
    return -1;
  if( s != NULL && parse_mac(mac, s) < 0 )
    return sc_node_set_error(node, EINVAL, "sct_mode1_encap: ERROR: arg "
                             "'%s=%s' badly formatted; expected mac address\n",
                             name, s);
  return (s == NULL) ? 1 : 0;
}


static int m1e_init(struct sc_node* node, const struct sc_attr* attr,
                       const struct sc_node_factory* factory)
{
  struct sc_thread* thread = sc_node_get_thread(node);

  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_prep_fn = m1e_prep;
    nt->nt_select_subnode_fn = m1e_select_subnode;
  }
  node->nd_type = nt;

  struct m1e_state* st = sc_thread_calloc(thread, sizeof(*st));
  node->nd_private = st;
  st->node = node;
  st->rand_seed = time(NULL);

  memset(st->outer_ether_dhost, 0xff, 6);
  memset(st->outer_ether_shost, 0x12, 6);

  if( get_arg_ip(&(st->outer_daddr), node, "daddr", 0) < 0     ||
      get_arg_ip(&(st->outer_saddr), node, "saddr", 0) < 0     ||
      get_arg_mac(st->outer_ether_dhost, node, "dhost", 0) < 0 ||
      get_arg_mac(st->outer_ether_shost, node, "shost", 0) < 0 ||
      sc_node_init_get_arg_int(&(st->pad), node, "pad", 0) < 0  )
    goto error;

  struct sc_node* snh_node;
  TEST( sc_node_alloc_named(&snh_node, attr, thread, "sc_subnode_helper",
                            NULL, NULL, 0) == 0 );
  struct sc_subnode_helper* snh = sc_subnode_helper_from_node(snh_node);
  st->snh = snh;
  snh->sh_private = st;
  snh->sh_handle_backlog_fn = m1e_handle_backlog;

  st->attr = sc_attr_dup(attr);
  /* This is a slightly ugly hack so that we can avoid allocating huge
   * numbers of buffers when used with solar_replay and
   * SC_ATTR=n_bufs_tx=$big.
   */
  TEST( sc_attr_set_int(st->attr, "n_bufs_tx", 512) == 0 );
  TEST( sc_attr_set_int(st->attr, "private_pool", 1) == 0 );
  return 0;

 error:
  sc_thread_mfree(sc_node_get_thread(node), st);
  return -1;
}


const struct sc_node_factory sct_mode1_encap_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sct_mode1_encap",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = m1e_init,
};
