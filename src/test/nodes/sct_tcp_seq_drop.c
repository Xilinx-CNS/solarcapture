/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#define SC_API_VER 1
#include <solar_capture.h>
#include <solar_capture_ext.h>

#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <sys/time.h>
#include <stdarg.h>
#include <stdbool.h>


struct sct_tcp_seq_drop_state {
  int tsds_drop_rep;
  int tsds_drop_extra;
  int tsds_drop_wait_ms;
  int tsds_init_tcp_count;
  uint32_t tsds_drop_seq;
  int tsds_num_seq_drops;
  int tsds_num_extra_drops;
  int tsds_num_tcp;
  struct timeval tsds_end_drop_tv;
  bool tsds_dropped_last;
  bool tsds_drop_started;
  const struct sc_node_link* tsds_forward_hop;
  const struct sc_node_link* tsds_drop_hop;
};


/* Return pointer to TCP hdr or NULL if not an IPv4 TCP packet
 * Also has TCP payload length as output parameter
 */
static const struct tcphdr*
get_tcp_hdr(const struct sc_packet* pkt, uint16_t* tcp_payload_len_out)
{
  struct tcphdr* out;
  struct ether_header* eth = pkt->iov[0].iov_base;
  struct iphdr* ip;
  if( ntohs(eth->ether_type) != ETHERTYPE_IP ) {
    out = NULL;
    *tcp_payload_len_out = 0;
  }
  else {
    ip = (void*)((char*)eth + sizeof(struct ether_header));
    if( ip->protocol != IPPROTO_TCP ) {
      out = NULL;
      *tcp_payload_len_out = 0;
    }
    else {
      uint16_t ip_hdr_len = ip->ihl * 4;
      uint16_t tot_len = ntohs(ip->tot_len);
      out = (void*)((char*)ip + ip_hdr_len);
      *tcp_payload_len_out = tot_len - (ip_hdr_len + out->doff * 4);
    }
  }
  return out;
}


static void
sct_tcp_seq_drop_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct sct_tcp_seq_drop_state* state = node->nd_private;
  struct timeval tv;
  uint64_t drop_gap_ms;

  if( state->tsds_drop_rep <= 0 ) {
    sc_forward_list(node, state->tsds_forward_hop, pl);
    return;
  }

  /* Not concerned with timing accuracy so getting time once per packet list
   * is fine
   */
  gettimeofday(&tv, NULL);
  drop_gap_ms = (tv.tv_sec - state->tsds_end_drop_tv.tv_sec) * 1000
                + (tv.tv_usec - state->tsds_end_drop_tv.tv_usec) / 1000;

  while( ! sc_packet_list_is_empty(pl) ) {
    uint16_t tcp_payload_len;
    uint32_t seq;
    struct sc_packet* pkt = sc_packet_list_pop_head(pl);
    const struct tcphdr* tcp = get_tcp_hdr(pkt, &tcp_payload_len);

    /* Forward any packets which aren't IPv4 TCP or don't have TCP payload */
    if( tcp == NULL ) {
      sc_forward(node, state->tsds_forward_hop, pkt);
      continue;
    }
    else if( ! tcp_payload_len ) {
      sc_forward(node, state->tsds_forward_hop, pkt);
      state->tsds_num_tcp++;
      continue;
    }

    /* Check initial number of TCP packets observed before dropping */
    state->tsds_num_tcp++;
    if( ! state->tsds_drop_started ) {
      if( state->tsds_num_tcp > state->tsds_init_tcp_count )
        state->tsds_drop_started = true;
      else {
        sc_forward(node, state->tsds_forward_hop, pkt);
        continue;
      }
    }
    seq = ntohl(tcp->seq);
    if( state->tsds_drop_seq == 0 && drop_gap_ms >= state->tsds_drop_wait_ms )
      /* Waited long enough to start dropping again */
      state->tsds_drop_seq = seq;

    if( seq == state->tsds_drop_seq ) {
      state->tsds_num_seq_drops++;
      state->tsds_dropped_last = true;
      sc_forward(node, state->tsds_drop_hop, pkt);
      if( state->tsds_num_seq_drops == state->tsds_drop_rep ) {
        state->tsds_drop_seq = 0;
        state->tsds_num_seq_drops = 0;
        state->tsds_num_extra_drops = 0;
        state->tsds_end_drop_tv.tv_sec = tv.tv_sec;
        state->tsds_end_drop_tv.tv_usec = tv.tv_usec;
      }
    }
    else if( state->tsds_num_extra_drops < state->tsds_drop_extra
              && state->tsds_drop_seq > 0 && ! state->tsds_dropped_last ) {
      state->tsds_num_extra_drops++;
      state->tsds_dropped_last = true;
      sc_forward(node, state->tsds_drop_hop, pkt);
    }
    else {
      sc_forward(node, state->tsds_forward_hop, pkt);
      state->tsds_dropped_last = false;
    }
  }
}


static void sct_tcp_seq_drop_end_of_stream(struct sc_node* node)
{
  struct sct_tcp_seq_drop_state* state = node->nd_private;
  sc_node_link_end_of_stream(node, state->tsds_forward_hop);
  sc_node_link_end_of_stream(node, state->tsds_drop_hop);
}


static int
sct_tcp_seq_drop_prep(struct sc_node* node,
                      const struct sc_node_link*const* links, int n_links)
{
  struct sct_tcp_seq_drop_state* state = node->nd_private;
  state->tsds_forward_hop = sc_node_prep_get_link_or_free(node, "");
  state->tsds_drop_hop = sc_node_prep_get_link_or_free(node, "drop");
  return sc_node_prep_check_links(node);
}


static int
sct_tcp_seq_drop_init(struct sc_node* node, const struct sc_attr* attr,
                      const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  struct sct_tcp_seq_drop_state* state;

  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_prep_fn = sct_tcp_seq_drop_prep;
    nt->nt_pkts_fn = sct_tcp_seq_drop_pkts;
    nt->nt_end_of_stream_fn = sct_tcp_seq_drop_end_of_stream;
  }
  node->nd_type = nt;

  state = sc_thread_calloc(sc_node_get_thread(node), sizeof(*state));
  node->nd_private = state;

  if( sc_node_init_get_arg_int(&state->tsds_drop_rep,
                               node, "drop_rep", 3) < 0 ) {
    sc_node_set_error(node,
                      EINVAL, "%s: bad arg 'drop_rep'\n", __FUNCTION__);
    goto error;
  }
  if( sc_node_init_get_arg_int(&state->tsds_drop_extra,
                               node, "drop_extra", 0) < 0 ) {
    sc_node_set_error(node,
                      EINVAL, "%s: bad arg 'drop_extra'\n", __FUNCTION__);
    goto error;
  }
  if( sc_node_init_get_arg_int(&state->tsds_drop_wait_ms,
                               node, "drop_wait_ms", 500) < 0 ) {
    sc_node_set_error(node,
                      EINVAL, "%s: bad arg 'drop_wait_ms'\n", __FUNCTION__);
    goto error;
  }
  if( sc_node_init_get_arg_int(&state->tsds_init_tcp_count,
                               node, "init_tcp_count", 30) < 0 ) {
    sc_node_set_error(node,
                      EINVAL, "%s: bad arg 'init_tcp_count'\n", __FUNCTION__);
    goto error;
  }
  return 0;

 error:
  sc_thread_mfree(sc_node_get_thread(node), state);
  return -1;
}


const struct sc_node_factory sct_tcp_seq_drop_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sct_tcp_seq_drop",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sct_tcp_seq_drop_init,
};
