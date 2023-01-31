/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/*
 * The implementation of the 'reflect' node in this file improves on the
 * one in reflect.c because it does not modify the input stream.  This is
 * useful if the input stream is readonly, or if you want to pass the
 * unmodified input stream on to other nodes (for example to write to
 * disk).
 *
 * NB. There are fewer comments in this file, and some features have been
 * removed for brevity: Please read reflect.c for more details.
 */

#define SC_API_VER 4
#include <solar_capture.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <limits.h>


struct reflect_state {
  struct sc_attr*            attr;
  const struct sc_node_link* next_hop;
  const struct sc_node_link* free_input_hop;
  struct sc_packet_list      backlog;
  struct sc_pool*            pool;
  struct sc_callback*        pool_callback;
  int                        end_of_input;
};


static int reflect_prep(struct sc_node* node,
                         const struct sc_node_link*const* links, int n_links)
{
  struct reflect_state* st = node->nd_private;

  st->next_hop = sc_node_prep_get_link_or_free(node, "");
  int rc = sc_node_prep_check_links(node);
  if( rc < 0 )
    return sc_node_fwd_error(node, rc);

  /* Allocate a packet pool.  This will supply buffers that copy input
   * packets.  We pass the attributes we saved in the nf_init_fn(), as that
   * allows the user to control the pool's attributes (such as buffer size
   * and number of buffers).
   */
  rc = sc_node_prep_get_pool(&st->pool, st->attr, node, &st->next_hop, 1);
  if( rc < 0 )
    return sc_node_fwd_error(node, rc);

  return 0;
}


static void reflect_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  /* Packets have arrived: Put them on the backlog and request a callback
   * when we have some buffers in the pool (which will usually be
   * immediately).
   */
  struct reflect_state* st = node->nd_private;
  sc_packet_list_append_list(&st->backlog, pl);
  if( ! sc_callback_is_active(st->pool_callback) ) {
    struct sc_packet* pkt = st->backlog.head;
    sc_pool_on_threshold(st->pool, st->pool_callback, pkt->frags_n + 1);
  }
}


static void reflect_end_of_stream(struct sc_node* node)
{
  /* We've received the end-of-stream indication on our input.  However, we
   * can only forward end-of-stream once the backlog is empty.
   */
  struct reflect_state* st = node->nd_private;
  st->end_of_input = 1;
  if( sc_packet_list_is_empty(&st->backlog) ) {
    sc_node_link_end_of_stream2(st->next_hop);
    sc_node_link_end_of_stream2(st->free_input_hop);
  }
}


static int pkt_is_unicast(const struct sc_packet* pkt)
{
  const uint8_t* addr = pkt->iov[0].iov_base;
  return (addr[0] & 1) == 0;
}


static inline void reflect_packet(struct sc_packet* pkt)
{
  uint8_t* p_dmac = pkt->iov[0].iov_base;
  uint8_t* p_smac = p_dmac + 6;
  uint8_t tmp[6];
  memcpy(tmp, p_dmac, 6);
  memcpy(p_dmac, p_smac, 6);
  memcpy(p_smac, tmp, 6);
}


static void reflect_drain(struct sc_callback* cb, void* event_info)
{
  /* This callback is invoked when the backlog is non-empty and the pool
   * has enough buffers to at least copy one packet from the backlog.
   */
  struct reflect_state* st = cb->cb_private;

  do {
    struct sc_packet* pkt = sc_packet_list_pop_head(&st->backlog);
    struct sc_packet* copy = sc_pool_duplicate_packet(st->pool, pkt, INT_MAX);
    if( copy == NULL ) {
      sc_packet_list_push_head(&st->backlog, pkt);
      sc_pool_on_threshold(st->pool, st->pool_callback, pkt->frags_n + 1);
      return;
    }
    if( pkt_is_unicast(copy) )
      reflect_packet(copy);
    sc_forward2(st->next_hop, copy);
    sc_forward2(st->free_input_hop, pkt);
  } while( ! sc_packet_list_is_empty(&st->backlog) );

  if( st->end_of_input ) {
    sc_node_link_end_of_stream2(st->next_hop);
    sc_node_link_end_of_stream2(st->free_input_hop);
  }
}


static int reflect_init(struct sc_node* node, const struct sc_attr* attr,
                        const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_pkts_fn = reflect_pkts;
    nt->nt_prep_fn = reflect_prep;
    nt->nt_end_of_stream_fn = reflect_end_of_stream;
  }
  node->nd_type = nt;

  struct sc_thread* thread = sc_node_get_thread(node);
  struct reflect_state* st = sc_thread_calloc(thread, sizeof(*st));
  node->nd_private = st;
  st->attr = sc_attr_dup(attr);
  sc_packet_list_init(&st->backlog);

  /* Allocate a callback object: This provides a way for SolarCapture to
   * call us back when an interesting event happens.  In this case, we want
   * to be told when the packet pool has some buffers.
   */
  int rc = sc_callback_alloc(&st->pool_callback, attr, thread);
  if( rc < 0 )
    return sc_node_fwd_error(node, rc);
  st->pool_callback->cb_private = st;
  st->pool_callback->cb_handler_fn = reflect_drain;

  return 0;
}


const struct sc_node_factory reflect_v2_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "reflect_v2",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = reflect_init,
};
