/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \node{sc_ps_unpacker}
 *
 * \brief Takes packed-stream buffers as input and unpacks them.
 *
 * \nodedetails
 * Takes packed-stream buffers as input and unpacks them,
 * allocating new buffers and copying the individual packets into them.
 *
 * \namedinputlinks
 * None
 *
 * \outputlinks
 * Link     | Description
 * -------- | -----------------------------------
 *  ""      | Unpacked packets are forwarded on this link
 *  "input" | The input buffers are forwarded on this link
 *
 * \cond NODOC
 */

#include <sc_internal.h>
#include <sc_internal/builtin_nodes.h>
#include <solar_capture/nodes/subnode_helper.h>
#include <solar_capture/packed_stream.h>

#include <errno.h>

/* Delaying the pool callback until it has several buffers
 * available is better for performance than a threshold of 1. */
#define POOL_THRESHOLD 32

struct unpacker {
  struct sc_node*            node;
  struct sc_subnode_helper*  sh;
  struct sc_pool*            pool;
  struct sc_attr*            attr;
  const struct sc_node_link* out_link;

  struct sc_packed_packet*   current_pkt;
};


static bool sc_ps_unpacker_unpack_buffer(struct unpacker* up)
{
  struct sc_session* tg = sc_thread_get_session(sc_node_get_thread(up->node));
  struct sc_packet* ps_buffer = up->sh->sh_backlog.head;
  struct sc_packed_packet* end = sc_packet_packed_end(ps_buffer);
  struct sc_packet* pkt;
  bool done = true;
  struct sc_packet_list unpacked_pl;
  sc_packet_list_init(&unpacked_pl);

  while( up->current_pkt < end ) {
    pkt = sc_pool_duplicate_packed_packet(up->pool,
                                          up->current_pkt,
                                          up->current_pkt->ps_cap_len);
    if( pkt == NULL ) {
      sc_tracefp(tg, "%s: pool dry\n", __func__);
      done = false;
      break;
    }

    sc_packet_list_append(&unpacked_pl, pkt);

    if( up->current_pkt->ps_next_offset == 0 )
      break; /* bug48308: CSS buffers use this to indicate final packet */
    up->current_pkt = sc_packed_packet_next(up->current_pkt);
  }

  if( done ) {
    sc_forward2(up->sh->sh_links[0],
                sc_packet_list_pop_head(&up->sh->sh_backlog));
    if( sc_packet_list_is_empty(&up->sh->sh_backlog) )
      up->current_pkt = NULL;
    else
      up->current_pkt = sc_packet_packed_first(up->sh->sh_backlog.head);
  }

  if( ! sc_packet_list_is_empty(&unpacked_pl) )
    sc_forward_list2(up->out_link, &unpacked_pl);

  return done;
}


static void sc_ps_unpacker_handle_backlog(struct sc_subnode_helper* sh)
{
  struct unpacker* up = sh->sh_private;

  if( up->current_pkt == NULL )
    up->current_pkt = sc_packet_packed_first(sh->sh_backlog.head);

  while( ! sc_packet_list_is_empty(&sh->sh_backlog) ) {
    if( ! sc_ps_unpacker_unpack_buffer(up) )
      break;
  }
}


static void sc_ps_unpacker_handle_end_of_stream(struct sc_subnode_helper* sh)
{
  struct unpacker* up = sh->sh_private;
  sc_node_link_end_of_stream2(up->out_link);
}


static struct sc_node* sc_ps_unpacker_select_subnode(struct sc_node* node,
                                                     const char* name,
                                                     char** new_name_out)
{
  struct unpacker* up = node->nd_private;
  return up->sh->sh_node;
}


static int sc_ps_unpacker_add_link(struct sc_node* from_node,
                                   const char* link_name,
                                   struct sc_node* to_node,
                                   const char* to_name_opt)
{
  struct unpacker* up = from_node->nd_private;
  if( ! strcmp(link_name, "input") )
    from_node = up->sh->sh_node;
  return sc_node_add_link(from_node, link_name, to_node, to_name_opt);
}


static int sc_ps_unpacker_prep(struct sc_node* node,
                               const struct sc_node_link*const* links,
                               int n_links)
{
  struct unpacker* up = node->nd_private;
  up->out_link = sc_node_prep_get_link_or_free(node, "");
  if( sc_node_prep_get_pool(&up->pool, up->attr, node, NULL, 0) != 0 )
    return -1;
  up->sh->sh_pool = up->pool;
  return sc_node_prep_check_links(node);
}


static int sc_ps_unpacker_init(struct sc_node* node, const struct sc_attr* attr,
                               const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_prep_fn = sc_ps_unpacker_prep;
    nt->nt_add_link_fn = sc_ps_unpacker_add_link;
    nt->nt_select_subnode_fn = sc_ps_unpacker_select_subnode;
  }
  node->nd_type = nt;

  struct sc_thread* thread = sc_node_get_thread(node);
  struct unpacker* up = sc_thread_calloc(thread, sizeof(*up));
  node->nd_private = up;
  up->node = node;
  up->attr = sc_attr_dup(attr);

  struct sc_arg sh_args[] = {
    SC_ARG_INT("with_free_link", 2),
  };

  struct sc_node* subnode;
  if( sc_node_alloc_named(&subnode, up->attr, thread, "sc_subnode_helper", NULL,
                          sh_args, sizeof(sh_args) / sizeof(sh_args[0])) != 0 )
    return -1;

  up->sh = sc_subnode_helper_from_node(subnode);
  up->sh->sh_private = up;
  up->sh->sh_pool_threshold = POOL_THRESHOLD;
  up->sh->sh_handle_backlog_fn = sc_ps_unpacker_handle_backlog;
  up->sh->sh_handle_end_of_stream_fn = sc_ps_unpacker_handle_end_of_stream;

  return 0;
}


const struct sc_node_factory sc_ps_unpacker_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_ps_unpacker",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_ps_unpacker_init,
};

/** \endcond NODOC */
