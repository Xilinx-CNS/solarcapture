/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#include <sc_internal.h>
#include <sc_internal/builtin_nodes.h>
#include <sc_internal/ef_vi.h>

#include <errno.h>
#include <string.h>


struct sc_vi_monitor {
  struct sc_node*               node;
  const struct sc_node_link*    next_hop;
  const struct sc_node_link*    next_hop_drop;
  struct sc_ef_vi*              vi;
  struct sc_vi_monitor_stats*  stats;
};


static void sc_vi_monitor_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct sc_vi_monitor* st = node->nd_private;
  struct sc_ef_vi* vi = st->vi;

  if( ef_vi_receive_fill_level(&vi->vi) >= vi->rx_ring_high_level ) {
    sc_forward_list(node, st->next_hop, pl);
  }
  else {
    st->stats->pkts_dropped += pl->num_pkts;
    sc_forward_list(node, st->next_hop_drop, pl);
  }
}


static void sc_vi_monitor_end_of_stream(struct sc_node* node)
{
  struct sc_vi_monitor* st = node->nd_private;
  sc_node_link_end_of_stream2(st->next_hop);
  sc_node_link_end_of_stream2(st->next_hop_drop);
}


static int sc_vi_monitor_prep(struct sc_node* node,
                              const struct sc_node_link*const* links,
                              int n_links)
{
  struct sc_vi_monitor* st = node->nd_private;
  st->next_hop = sc_node_prep_get_link_or_free(node, "");
  st->next_hop_drop = sc_node_prep_get_link_or_free(node, "drop");
  return sc_node_prep_check_links(node);
}


static int sc_vi_monitor_init(struct sc_node* node, const struct sc_attr* attr,
                              const struct sc_node_factory* factory)
{
  struct sc_thread* thread = sc_node_get_thread(node);

  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_prep_fn = sc_vi_monitor_prep;
    nt->nt_pkts_fn = sc_vi_monitor_pkts;
    nt->nt_end_of_stream_fn = sc_vi_monitor_end_of_stream;
  }
  node->nd_type = nt;

  struct sc_vi_monitor* st;
  st = sc_thread_calloc(thread, sizeof(*st));
  node->nd_private = st;
  st->node = node;
  struct sc_object* obj;
  int rc = sc_node_init_get_arg_obj(&obj, node, "vi", SC_OBJ_OPAQUE);
  if( rc < 0 )
    goto error;
  if( rc > 0 ) {
    sc_node_set_error(node, EINVAL, "sc_vi_monitor: ERROR: no vi arg\n");
    goto error;
  }
  st->vi = sc_opaque_get_ptr(obj);
  sc_node_export_state(node, "sc_vi_monitor_stats",
                       sizeof(struct sc_vi_monitor_stats), &st->stats);
  return 0;

 error:
  sc_thread_mfree(thread, st);
  return -1;
}


const struct sc_node_factory sc_vi_monitor_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_vi_monitor",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_vi_monitor_init,
};
