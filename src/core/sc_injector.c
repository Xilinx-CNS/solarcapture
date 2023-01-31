/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#include "internal.h"
#include <sc_internal/ef_vi.h>


static int sc_injector_node_prep(struct sc_node* node,
                                 const struct sc_node_link*const* links,
                                 int n_links)
{
  struct sc_node_impl* ni = SC_NODE_IMPL_FROM_NODE(node);
  struct sc_session* tg = ni->ni_thread->session;
  struct sc_injector_node* inj = node->nd_private;
  struct sc_ef_vi* vi = inj->vi;
  int pp_id;

  TEST(inj->vi != NULL);

  sc_trace(tg, "%s: n%d v%d pools=(%s)\n",
           __func__, ni->ni_id, vi->id, sc_bitmask_fmt(&ni->ni_src_pools));

  /* Determine which pools send payload to this injector, and request that
   * they be DMA mapped.
   */
  for( pp_id = 0; pp_id < tg->tg_pkt_pools_n; ++pp_id )
    if( sc_bitmask_is_set(&ni->ni_src_pools, pp_id) ) {
      struct sc_pkt_pool* pp = tg->tg_pkt_pools[pp_id];
      do {
        sc_trace(tg, "%s:   p%d buf_size=%zd inline=%d\n", __func__,
                 pp->pp_id, pp->pp_buf_size, (int) pp->pp_is_inline);
        if( pp->pp_buf_size )
          sc_pkt_pool_add_netif(pp, vi->netif);
      } while( (pp = pp->pp_linked_pool) != NULL );
    }

  inj->next_hop = sc_node_prep_get_link_or_free(node, "");
  return sc_node_prep_check_links(node);
}


static void sc_injector_node_pkts(struct sc_node* node,
                               struct sc_packet_list* pl)
{
  struct sc_injector_node* inj = node->nd_private;
  assert(inj->eos == 0);
  sc_validate_list(SC_NODE_IMPL_FROM_NODE(node)->ni_thread->session,
                   pl, node->nd_name, "");
  inj->n_pkts_in += pl->num_pkts;
  sc_ef_vi_transmit_list(inj->vi, pl, inj);
}


static void sc_injector_node_end_of_stream(struct sc_node* node)
{
  struct sc_injector_node* inj = node->nd_private;
  assert(inj->eos == 0);
  inj->eos = 1;
  if( inj->n_pkts_in == inj->n_pkts_out )
    sc_node_link_end_of_stream2(inj->next_hop);
}


const struct sc_node_type sc_injector_node_type = {
  .nt_name             = "sc_injector",
  .nt_prep_fn          = sc_injector_node_prep,
  .nt_pkts_fn          = sc_injector_node_pkts,
  .nt_end_of_stream_fn = sc_injector_node_end_of_stream,
};


static void __sc_injector_node_init(struct sc_node* n, struct sc_ef_vi* vi)
{
  struct sc_injector_node* inj;
  inj = sc_thread_calloc(vi->thread, sizeof(*inj));
  TEST(inj != NULL);

  inj->node = n;
  inj->vi = vi;
  n->nd_private = inj;
  sc_node_add_info_int(n, "vi_id", vi->id);
}


static int sc_injector_node_init(struct sc_node* n, const struct sc_attr* attr,
                               const struct sc_node_factory* factory)
{
  int csum_ip = 0, csum_tcpudp = 0;
  int i, rc;

  n->nd_type = &sc_injector_node_type;

  const char* if_name;
  if( (rc = sc_node_init_get_arg_str(&if_name, n, "interface", NULL)) < 0 )
    return -1;
  if( if_name == NULL )
    return sc_node_set_error(n, EINVAL, "%s: ERROR: required arg 'interface' "
                             "missing\n", __func__);

  if( (rc = sc_node_init_get_arg_int(&csum_ip, n, "csum_ip", 0)) < 0 )
    return -1;
  if( (rc = sc_node_init_get_arg_int(&csum_tcpudp, n, "csum_tcpudp", 0)) < 0 )
    return -1;
  unsigned sc_ef_vi_flags = ((!!csum_ip * vif_tx_csum_ip) |
                             (!!csum_tcpudp * vif_tx_csum_tcpudp));
  unsigned flags_mask = vif_tx_csum_ip | vif_tx_csum_tcpudp;

  struct sc_thread* thread = SC_NODE_IMPL_FROM_NODE(n)->ni_thread;

  /* Is there an existing VI we can use? */
  struct sc_ef_vi* vi;
  for( i = 0; i < thread->n_vis; ++i ) {
    vi = thread->vis[i];
    if( strcmp(vi->netif->interface->if_name, if_name) == 0 &&
        ef_vi_transmit_capacity(&vi->vi) != 0 &&
        ((vi->flags & flags_mask) == sc_ef_vi_flags) )
      break;
  }
  if( i == thread->n_vis ) {
    /* We need to ensure that we don't allocate a new VI from a cluster, so
     * we set the cluster attribute to 'none'.  (This has the unfortunate
     * side-effect of preventing us from using an existing ef_vi that
     * happens to be clustered, which would be fine.  The mess caused by
     * interaction of clustering with sc_netif needs fixing.)
     */
    struct sc_attr* attr_nc;
    SC_TEST(attr_nc = sc_attr_dup(attr));
    SC_TRY(sc_attr_set_str(attr_nc, "cluster", "none") == 0);
    SC_TRY(sc_attr_set_str(attr_nc, "vi_mode", "normal") == 0);
    rc = sc_ef_vi_alloc(&vi, attr_nc, thread, if_name, sc_ef_vi_flags);
    sc_attr_free(attr_nc);
    if( rc < 0 ) {
      t_fwd_err(thread,
                "%s: ERROR: sc_ef_vi_alloc(%s) failed for thread %d/%s\n",
                __func__, if_name, thread->id, thread->name);
      return rc;
    }
  }
  __sc_injector_node_init(n, vi);
  return 0;
}


const struct sc_node_factory sc_injector_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_injector",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_injector_node_init,
};
