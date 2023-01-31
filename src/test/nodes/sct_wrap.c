/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#define SC_API_VER 4
#include <solar_capture.h>
#include <solar_capture/nodes/subnode_helper.h>

#include "sct.h"

#include <errno.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>


struct sct_wrap_state {
  const struct sc_node_link* next_hop;
  struct sc_attr*            attr;
  struct sc_subnode_helper*  snh;
};


static void sct_wrap_pkt(struct sct_wrap_state* st, struct sc_packet* wrapee,
                         struct sc_packet* wrapper)
{
  TEST( wrapee->iovlen == 1 );  /* artificial limitation! */
  TEST( wrapper->frags == NULL );
  TEST( wrapper->frags_n == 0 );

  wrapper->ts_sec = wrapee->ts_sec;
  wrapper->ts_nsec = wrapee->ts_nsec;
  wrapper->flags = wrapee->flags;
  wrapper->frame_len = wrapee->frame_len;
  wrapper->frags_n = 1;
  wrapper->iovlen = wrapee->iovlen;
  uint8_t i;
  for( i = 0; i < wrapee->iovlen; ++i ) {
    wrapper->iov[i].iov_base = wrapee->iov[i].iov_base;
    wrapper->iov[i].iov_len  = wrapee->iov[i].iov_len;
  }
  wrapper->frags = wrapee;
  wrapper->frags_tail = &(wrapee->next);
}


static void sct_wrap_handle_backlog(struct sc_subnode_helper* snh)
{
  struct sct_wrap_state* st = snh->sh_private;
  struct sc_packet_list pl;
  __sc_packet_list_init(&pl);
  sc_pool_get_packets(&pl, snh->sh_pool, 1, snh->sh_backlog.num_pkts);
  TEST( pl.num_pkts <= snh->sh_backlog.num_pkts );
  TEST( pl.num_pkts >= snh->sh_pool_threshold ||
        pl.num_pkts == snh->sh_backlog.num_pkts );

  struct sc_packet *pkt, *next;
  for( next = pl.head; (pkt = next) && ((next = next->next), 1); )
    sct_wrap_pkt(st, sc_packet_list_pop_head(&(snh->sh_backlog)), pkt);
  sc_forward_list2(st->next_hop, &pl);
}


static void sct_wrap_handle_end_of_stream(struct sc_subnode_helper* snh)
{
  struct sct_wrap_state* st = snh->sh_private;
  TEST( sc_packet_list_is_empty(&(snh->sh_backlog)) );
  sc_node_link_end_of_stream2(st->next_hop);
}


static int sct_wrap_prep(struct sc_node* node,
                         const struct sc_node_link*const* links, int n_links)
{
  struct sct_wrap_state* st = node->nd_private;
  st->next_hop = sc_node_prep_get_link_or_free(node, "");
  if( sc_node_prep_check_links(node) < 0 )
    return -1;
  int rc = sc_node_prep_get_pool(&(st->snh->sh_pool), st->attr, node, NULL, 0);
  if( rc < 0 )
    return sc_node_fwd_error(node, rc);
  st->snh->sh_pool_threshold = 1;

  struct sc_arg args[] = {
    SC_ARG_OBJ("pool", sc_pool_to_object(st->snh->sh_pool)),
    SC_ARG_OBJ("node", sc_node_to_object(st->snh->sh_node)),
  };
  struct sc_node* undo_node;
  TEST( sc_node_alloc_named(&undo_node, st->attr, sc_node_get_thread(node),
                            "sc_wrap_undo", NULL,
                            args, sizeof(args) / sizeof(args[0])) == 0 );

  sc_pool_set_refill_node(st->snh->sh_pool, undo_node);
  TRY( sc_pool_wraps_node(st->snh->sh_pool, st->snh->sh_node) );
  return 0;
}


static struct sc_node* sct_wrap_select_subnode(struct sc_node* node,
                                               const char* name,
                                               char** new_name_out)
{
  struct sct_wrap_state* st = node->nd_private;
  return st->snh->sh_node;
}


static int sct_wrap_init(struct sc_node* node, const struct sc_attr* attr,
                       const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_prep_fn = sct_wrap_prep;
    nt->nt_select_subnode_fn = sct_wrap_select_subnode;
  }
  node->nd_type = nt;

  struct sc_thread* thread = sc_node_get_thread(node);

  struct sct_wrap_state* st;
  st = sc_thread_calloc(thread, sizeof(*st));
  node->nd_private = st;
  TEST( st->attr = sc_attr_dup(attr) );

  struct sc_arg args[] = {
    SC_ARG_INT("with_free_link", 0),
  };
  struct sc_node* snh_node;
  TEST( sc_node_alloc_named(&snh_node, attr, thread, "sc_subnode_helper",
                            NULL, args, sizeof(args) / sizeof(args[0])) == 0 );
  struct sc_subnode_helper* snh = sc_subnode_helper_from_node(snh_node);
  st->snh = snh;
  snh->sh_private = st;
  snh->sh_handle_backlog_fn = sct_wrap_handle_backlog;
  snh->sh_handle_end_of_stream_fn = sct_wrap_handle_end_of_stream;
  return 0;
}


const struct sc_node_factory sct_wrap_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sct_wrap",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sct_wrap_init,
};
