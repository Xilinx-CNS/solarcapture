/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#define SC_API_VER 4
#include <solar_capture.h>
#include <solar_capture/nodes/subnode_helper.h>
#include "sct.h"

#include <errno.h>


struct sh_test {
  struct sc_node*            node;
  struct sc_subnode_helper*  sh;
  const struct sc_node_link* a_hop;
  const struct sc_node_link* b_hop;
};


static void sh_test_handle_backlog(struct sc_subnode_helper* sh)
{
  struct sh_test* st = sh->sh_private;
  printf("%s: n=%d\n", __func__, sh->sh_backlog.num_pkts);
  sc_forward_list(sh->sh_node, st->a_hop, &sh->sh_backlog);
  sc_packet_list_init(&sh->sh_backlog);
}


struct sc_node* sh_test_select_subnode(struct sc_node* node, const char* name,
                                       char** new_name_out)
{
  struct sh_test* st = node->nd_private;
  return st->sh->sh_node;
}


static int sh_test_add_link(struct sc_node* from_node,
                            const char* link_name,
                            struct sc_node* to_node,
                            const char* to_name_opt)
{
  struct sh_test* st = from_node->nd_private;
  return sc_node_add_link(st->sh->sh_node, link_name, to_node, to_name_opt);
}


static int sh_test_prep(struct sc_node* node,
                        const struct sc_node_link*const* links, int n_links)
{
  /* This relies on subnodes being preped before their parents. */
  struct sh_test* st = node->nd_private;
  struct sc_subnode_helper* sh = st->sh;
  printf("%s n_links=%d\n", __func__, sh->sh_n_links);
  int i;
  if( sh->sh_n_links != 2 )
    return sc_node_set_error(sh->sh_node, EINVAL, "ERROR: %s: Exactly 2 "
                             "outgoing links are required\n", __func__);
  for( i = 0; i < sh->sh_n_links; ++i ) {
    const struct sc_node_link* link = sh->sh_links[i];
    if( ! strcmp(link->name, "a") )
      st->a_hop = link;
    else if( ! strcmp(link->name, "b") )
      st->b_hop = link;
    else
      return sc_node_set_error(sh->sh_node, EINVAL, "ERROR: %s: Links "
                               "must be named 'a' and 'b'\n", __func__);
  }
  return 0;
}


static int sh_test_init(struct sc_node* node, const struct sc_attr* attr,
                       const struct sc_node_factory* factory)
{
  struct sc_thread* thread = sc_node_get_thread(node);
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_select_subnode_fn = sh_test_select_subnode;
    nt->nt_add_link_fn = sh_test_add_link;
    nt->nt_prep_fn = sh_test_prep;
  }
  node->nd_type = nt;

  struct sh_test* st = sc_thread_calloc(thread, sizeof(*st));
  node->nd_private = st;
  st->node = node;

  struct sc_node* sh_node;
  TEST( sc_node_alloc_named(&sh_node, attr, thread, "sc_subnode_helper",
                            NULL, NULL, 0) == 0 );
  st->sh = sc_subnode_helper_from_node(sh_node);
  st->sh->sh_private = st;
  st->sh->sh_handle_backlog_fn = sh_test_handle_backlog;
  return 0;
}


const struct sc_node_factory sct_subnode_prep_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sct_subnode_prep",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sh_test_init,
};
