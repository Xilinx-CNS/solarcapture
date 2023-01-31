/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/** \cond NODOC */
/*
 * NOTE: We do not want customers to use this node at this point.
 *       If you add any Doxygen documentation, mark it as \internal.
 */
#include <sc_internal.h>

#include <errno.h>

#define MAX_HOPS 2

struct sc_stopcock {
  struct sc_node*            node;
  struct sc_node*            ctl_node;
  const struct sc_node_link* hops[MAX_HOPS];
  int                        active_hop;
};


struct sc_stopcock_ctl {
  struct sc_node*            node;
  struct sc_stopcock*        stopcock;
  const struct sc_node_link* next_hop;
};


static void sc_stopcock_ctl_end_of_stream(struct sc_node* node)
{
  struct sc_stopcock_ctl* stc_ctl = node->nd_private;
  sc_node_link_end_of_stream(stc_ctl->node, stc_ctl->next_hop);
  struct sc_stopcock* stc = stc_ctl->stopcock;
  if( stc->active_hop == 0 ) {
    sc_node_link_end_of_stream(stc->node, stc->hops[0]);
    stc->active_hop = 1;
  }
}


static void sc_stopcock_ctl_pkts(struct sc_node* node,
                                 struct sc_packet_list* pl)
{
  struct sc_stopcock_ctl* stc_ctl = node->nd_private;
  struct sc_packet* pkt = pl->head;
  int* tmp = NULL;
  while( pkt ) {
    tmp = pkt->iov[0].iov_base;
    if( pkt->iov[0].iov_len != sizeof(*tmp) || *tmp < 0 || *tmp >= MAX_HOPS) {
      struct sc_session* tg = sc_thread_get_session(sc_node_get_thread(node));
      sc_warn(tg, "WARNING: %s: bad ctl message\n", __func__);
    }
    else {
      stc_ctl->stopcock->active_hop = *tmp;
    }
    pkt = pkt->next;
  }
  sc_forward_list(node, stc_ctl->next_hop, pl);
}


static int sc_stopcock_ctl_prep(struct sc_node* node,
                                const struct sc_node_link*const* links,
                                int n_links)
{
  struct sc_stopcock_ctl* stc_ctl = node->nd_private;
  stc_ctl->next_hop = sc_node_prep_get_link_or_free(node, "");
  return sc_node_prep_check_links(node);
}


static int sc_stopcock_ctl_init(struct sc_node* node,
                                const struct sc_attr* attr,
                                const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_prep_fn = sc_stopcock_ctl_prep;
    nt->nt_pkts_fn = sc_stopcock_ctl_pkts;
    nt->nt_end_of_stream_fn = sc_stopcock_ctl_end_of_stream;
  }
  node->nd_type = nt;

  struct sc_stopcock_ctl* stc_ctl;
  stc_ctl = sc_thread_calloc(sc_node_get_thread(node), sizeof(*stc_ctl));
  stc_ctl->node = node;
  node->nd_private = stc_ctl;
  return 0;
}


const struct sc_node_factory sc_stopcock_ctl_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_stopcock_ctl",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_stopcock_ctl_init,
};


static void sc_stopcock_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct sc_stopcock* stc = node->nd_private;
  sc_forward_list(stc->node, stc->hops[stc->active_hop], pl);
}


struct sc_node* sc_stopcock_select_subnode(struct sc_node* node,
                                           const char* name,
                                           char** new_name_out)
{
  struct sc_stopcock* stc = node->nd_private;

  if( name == NULL || ! strcmp(name, "") )
    return node;
  if( ! strcmp(name, "ctl") )
    return stc->ctl_node;
  sc_node_set_error(node, EINVAL,
                    "sc_stopcock: ERROR: bad incoming link name '%s'\n", name);
  return NULL;
}


static int sc_stopcock_add_link(struct sc_node* from_node,
                                const char* link_name,
                                struct sc_node* to_node,
                                const char* to_name_opt)
{
  struct sc_stopcock* stc = from_node->nd_private;
  int rc;
  if( ! strcmp(link_name, "") )
    rc = sc_node_add_link(from_node, link_name, to_node, to_name_opt);
  else if( ! strcmp(link_name, "ctl") )
    rc = sc_node_add_link(stc->ctl_node, "", to_node, to_name_opt);
  else
    return sc_node_set_error(from_node, EINVAL, "sc_stopcock: ERROR: bad "
                             "link name '%s'\n", link_name);
  if( rc < 0 )
    return sc_node_fwd_error(from_node, rc);
  return 0;
}


static void sc_stopcock_end_of_stream(struct sc_node* node)
{
  struct sc_stopcock* stc = node->nd_private;
  sc_node_link_end_of_stream(stc->node, stc->hops[0]);
  sc_node_link_end_of_stream(stc->node, stc->hops[1]);
}


static int sc_stopcock_prep(struct sc_node* node,
                             const struct sc_node_link*const* links,
                             int n_links)
{
  struct sc_stopcock* stc = node->nd_private;
  stc->hops[0] = sc_node_prep_get_link_or_free(node, "");
  stc->hops[1] = sc_node_prep_get_link_or_free(node, "off");
  return sc_node_prep_check_links(node);
}


static int sc_stopcock_init(struct sc_node* node, const struct sc_attr* attr,
                            const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_prep_fn = sc_stopcock_prep;
    nt->nt_select_subnode_fn = sc_stopcock_select_subnode;
    nt->nt_add_link_fn = sc_stopcock_add_link;
    nt->nt_pkts_fn = sc_stopcock_pkts;
    nt->nt_end_of_stream_fn = sc_stopcock_end_of_stream;
  }
  node->nd_type = nt;

  struct sc_stopcock* stc;
  stc = sc_thread_calloc(sc_node_get_thread(node), sizeof(*stc));
  node->nd_private = stc;
  stc->node = node;
  /* stc->active_hop = 0; */

  struct sc_node* ctl_node;
  int rc = sc_node_alloc(&ctl_node, attr, sc_node_get_thread(node),
                         &sc_stopcock_ctl_sc_node_factory, NULL, 0);
  if( rc < 0 )
    return sc_node_fwd_error(node, rc);

  struct sc_stopcock_ctl* stc_ctl = ctl_node->nd_private;
  stc_ctl->stopcock = stc;
  stc->ctl_node = ctl_node;

  return 0;
}


const struct sc_node_factory sc_stopcock_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_stopcock",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_stopcock_init,
};
/** \endcond NODOC */
