/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#include <sc_internal.h>

#include <errno.h>


struct sct_always_busy {
  struct sc_callback*        callback;
};


static void always_busy_callback(struct sc_callback* cb, void* event_info)
{
  sc_timer_expire_after_ns(cb, 1);
}


static int always_busy_prep(struct sc_node* node,
                            const struct sc_node_link*const* links, int n_links)
{
  struct sct_always_busy* st = node->nd_private;
  sc_timer_expire_after_ns(st->callback, 1);
  return sc_node_prep_check_links(node);
}


static int always_busy_init(struct sc_node* node, const struct sc_attr* attr,
                       const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_prep_fn = always_busy_prep;
  }
  node->nd_type = nt;

  struct sct_always_busy* st;
  st = sc_thread_calloc(sc_node_get_thread(node), sizeof(*st));
  node->nd_private = st;
  SC_TRY(sc_callback_alloc(&st->callback, attr, sc_node_get_thread(node)));
  st->callback->cb_handler_fn = always_busy_callback;
  return 0;
}


const struct sc_node_factory sct_always_busy_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sct_always_busy",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = always_busy_init,
};
