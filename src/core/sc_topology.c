/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#include "internal.h"
#include <sc_internal/ef_vi.h>


int sc_topology_check(struct sc_session* tg)
{
  /* ?? TODO: check for problems such as:
   *
   * node not reachable (warn) (unless mailbox send node)
   *
   * reachable mailbox not being connected
   *
   * reachable mailbox not having recv_node on RX side
   *
   * linked to node having dispatch order < linked from node
   */
  struct sc_node_impl* ni;
  struct sc_ef_vi* vi;
  int i;

  for( i = 0; i < tg->tg_vis_n && (vi = tg->tg_vis[i], 1); ++i ) {
    if( vi->vi_recv_node == NULL && (vi->flags & vif_has_stream) )
      return sc_set_err(tg, EINVAL, "ERROR: vi%d(%s) has stream but no recv "
                        "node\n", vi->id, vi->name);
#if 0
    /* ?? FIXME: You get this warning for VIs from an sc_vi_group if
     * streams are added to the group.
     *
     * Also not obvious we can get the insight needed to do this properly
     * when we add app clustering.
     */
    if( vi->vi_recv_node != NULL && ! (vi->flags & vif_has_stream) )
      sc_warn(tg, "%s: WARNING: vi%d(%s) has recv node but no "
              "streams\n", __func__, vi->id, vi->name);
#endif
  }

  for( i = 0; i < tg->tg_nodes_n && (ni = tg->tg_nodes[i], 1); ++i )
    if( sc_bitmask_ffs(&ni->ni_src_pools) && ni->ni_node.nd_type->nt_pkts_fn == NULL )
      return sc_set_err(tg, EINVAL, "ERROR: n%d:%s cannot accept packets\n",
                        ni->ni_id, ni->ni_node.nd_name);

  return 0;
}


uint64_t sc_topology_find_sender_netifs(struct sc_node_impl* ni)
{
  /* Return the set of netifs that packets reaching the given node can be
   * sent out of.  ie. We follow the node graph looking for sc_injector
   * nodes.
   */
  uint64_t netifs = 0;

  if( ni->ni_node.nd_type == &sc_injector_node_type ) {
    struct sc_injector_node* inj = ni->ni_node.nd_private;
    netifs |= 1llu << inj->vi->netif->netif_id;
    /* Keep going, as sender nodes have outgoing links too... */
  }
  else if( sc_node_is_mailbox(&ni->ni_node) ) {
    struct sc_mailbox* mb = SC_MAILBOX_FROM_NODE_IMPL(ni);
    struct sc_mailbox* rmb;
    if( mb->mb_send_slot != NULL ) {
      rmb = SC_CONTAINER(struct sc_mailbox, mb_recv_slot, mb->mb_send_slot);
      if( rmb->mb_recv_node != NULL )
        return sc_topology_find_sender_netifs(rmb->mb_recv_node);
    }
  }

  struct sc_node_link_impl* nl;
  int i;
  for( i = 0; i < ni->ni_n_links; ++i )
    if( (nl = ni->ni_links[i])->nl_to_node != NULL )
      netifs |= sc_topology_find_sender_netifs(nl->nl_to_node);
  return netifs;
}


static void sc_topology_dump_link(struct sc_session* scs,
                                  const char* link_name,
                                  struct sc_node_impl* to_ni,
                                  const struct sc_bitmask* pools)
{
  if( to_ni == NULL ) {
    sc_log(scs, "    %s => pools=(%s)\n", link_name, sc_bitmask_fmt(pools));
    return;
  }
  char via_str[80];
  via_str[0] = '\0';
  if( sc_node_is_mailbox(&(to_ni->ni_node)) ) {
    struct sc_mailbox* mb = SC_MAILBOX_FROM_NODE_IMPL(to_ni);
    struct sc_mailbox* rmb = sc_mailbox_get_peer(mb);
    if( rmb != NULL && rmb->mb_recv_node != NULL ) {
      sprintf(via_str, "via m%d,m%d", mb->mb_id, rmb->mb_id);
      to_ni = rmb->mb_recv_node;
    }
  }
  sc_log(scs, "    %s => pools=(%s) n%d/%s %s\n", link_name,
         sc_bitmask_fmt(pools), to_ni->ni_id,
         to_ni->ni_node.nd_name, via_str);
}


static void sc_topology_dump_node(struct sc_node_impl* ni)
{
  struct sc_session* tg = ni->ni_thread->session;
  struct sc_node* node = &(ni->ni_node);
  sc_log(tg, "  id=%d thrd=%d type=%s name=%s pools=(%s) order=%d "
         "links=%d,%d,%d\n",
         ni->ni_id, ni->ni_thread->id, node->nd_type->nt_name, node->nd_name,
         sc_bitmask_fmt(&ni->ni_src_pools), ni->ni_dispatch_order, ni->ni_n_links,
         ni->ni_n_incoming_links, ni->ni_n_incoming_links_preped);
  int nl_id;
  for( nl_id = 0; nl_id < ni->ni_n_links; ++nl_id ) {
    struct sc_node_link_impl* nl = ni->ni_links[nl_id];
    sc_topology_dump_link(tg, nl->nl_public.name, nl->nl_to_node, &nl->nl_pools);
  }
}


static int compare_nodes_by_dispatch_order(const void* a, const void* b)
{
  struct sc_node_impl*const* ni_a = a;
  struct sc_node_impl*const* ni_b = b;
  return (*ni_a)->ni_dispatch_order - (*ni_b)->ni_dispatch_order;
}


void sc_topology_dump_nodes(struct sc_session* tg)
{
  struct sc_node_impl* nis[tg->tg_nodes_n];
  int ni_id, i;
  for( ni_id = 0; ni_id < tg->tg_nodes_n; ++ni_id )
    nis[ni_id] = tg->tg_nodes[ni_id];
  qsort(nis, tg->tg_nodes_n, sizeof(nis[0]), compare_nodes_by_dispatch_order);
  sc_log(tg, "%s:\n", __func__);
  for( i = 0; i < tg->tg_nodes_n; ++i )
    sc_topology_dump_node(nis[i]);
}


static void sc_topology_dump_pool(struct sc_session* tg,
                                  struct sc_pkt_pool* pp)
{
  sc_log(tg, "  id=%d intfs=%"PRIx64" bufs=%d refill=n%d/%s\n",
         pp->pp_id, pp->pp_netifs, pp->pp_n_bufs,
         pp->pp_refill_node ? pp->pp_refill_node->ni_id : -1,
         pp->pp_refill_node ? pp->pp_refill_node->ni_node.nd_name : "");
}


void sc_topology_dump_pools(struct sc_session* tg)
{
  int pp_id;
  sc_log(tg, "%s:\n", __func__);
  for( pp_id = 0; pp_id < tg->tg_pkt_pools_n; ++pp_id )
    sc_topology_dump_pool(tg, tg->tg_pkt_pools[pp_id]);
}


void sc_topology_dump(struct sc_session* tg)
{
  sc_topology_dump_nodes(tg);
  sc_topology_dump_pools(tg);
}
