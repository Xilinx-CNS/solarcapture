/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \cond NODOC
 *
 * \brief This node stops all ::sc_vi instances in the same thread.
 *
 * \nodedetails
 * This node signals ::sc_vi instances in the same thread to stop when it
 * gets the end-of-stream signal on its "ctl" input.
 *
 * \node{sc_signal_vi}
 */
#include "../core/internal.h"
#include <sc_internal.h>

#include <errno.h>


struct sc_signal_vi {
  struct sc_node*            node;
  struct sc_node*            ctl_node;
  const struct sc_node_link* next_hop;
};


struct sc_signal_vi_ctl {
  struct sc_node*            node;
  struct sc_signal_vi*       signal_vi;
  const struct sc_node_link* next_hop;
};


static void sc_signal_vi_ctl_end_of_stream(struct sc_node* node)
{
  struct sc_signal_vi_ctl* ssv_ctl = node->nd_private;
  sc_node_link_end_of_stream(ssv_ctl->node, ssv_ctl->next_hop);
  sc_thread_stop_vis(sc_node_get_thread(node));
}


static int sc_signal_vi_ctl_prep(struct sc_node* node,
                                const struct sc_node_link*const* links,
                                int n_links)
{
  struct sc_signal_vi_ctl* ssv_ctl = node->nd_private;
  ssv_ctl->next_hop = sc_node_prep_get_link_or_free(node, "");
  return sc_node_prep_check_links(node);
}


static void sc_signal_vi_ctl_pkts(struct sc_node* node,
                                  struct sc_packet_list* pl)
{
  struct sc_signal_vi_ctl* ssv_ctl = node->nd_private;
  sc_forward_list(ssv_ctl->node, ssv_ctl->next_hop, pl);
}


static int sc_signal_vi_ctl_init(struct sc_node* node,
                                const struct sc_attr* attr,
                                const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_prep_fn = sc_signal_vi_ctl_prep;
    nt->nt_end_of_stream_fn = sc_signal_vi_ctl_end_of_stream;
    nt->nt_pkts_fn = sc_signal_vi_ctl_pkts;
  }
  node->nd_type = nt;

  struct sc_signal_vi_ctl* ssv_ctl;
  ssv_ctl = sc_thread_calloc(sc_node_get_thread(node), sizeof(*ssv_ctl));
  ssv_ctl->node = node;
  node->nd_private = ssv_ctl;
  return 0;
}


const struct sc_node_factory sc_signal_vi_ctl_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_signal_vi_ctl",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_signal_vi_ctl_init,
};


static void sc_signal_vi_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct sc_signal_vi* ssv = node->nd_private;
  sc_forward_list(ssv->node, ssv->next_hop, pl);
}


struct sc_node* sc_signal_vi_select_subnode(struct sc_node* node,
                                           const char* name,
                                           char** new_name_out)
{
  struct sc_signal_vi* ssv = node->nd_private;

  if( name == NULL || ! strcmp(name, "") )
    return node;
  if( ! strcmp(name, "ctl") )
    return ssv->ctl_node;
  sc_node_set_error(node, EINVAL,
                    "sc_signal_vi: ERROR: bad incoming link name '%s'\n", name);
  return NULL;
}


static int sc_signal_vi_add_link(struct sc_node* from_node,
                                const char* link_name,
                                struct sc_node* to_node,
                                const char* to_name_opt)
{
  struct sc_signal_vi* ssv = from_node->nd_private;
  int rc;
  if( ! strcmp(link_name, "") )
    rc = sc_node_add_link(from_node, link_name, to_node, to_name_opt);
  else if( ! strcmp(link_name, "ctl") )
    rc = sc_node_add_link(ssv->ctl_node, "", to_node, to_name_opt);
  else
    return sc_node_set_error(from_node, EINVAL, "sc_signal_vi: ERROR: bad "
                             "link name '%s'\n", link_name);
  if( rc < 0 )
    return sc_node_fwd_error(from_node, rc);
  return 0;
}


static void sc_signal_vi_end_of_stream(struct sc_node* node)
{
  struct sc_signal_vi* ssv = node->nd_private;
  sc_node_link_end_of_stream(ssv->node, ssv->next_hop);
}


static int sc_signal_vi_prep(struct sc_node* node,
                             const struct sc_node_link*const* links,
                             int n_links)
{
  struct sc_signal_vi* ssv = node->nd_private;
  ssv->next_hop = sc_node_prep_get_link_or_free(node, "");
  return sc_node_prep_check_links(node);
}


static int sc_signal_vi_init(struct sc_node* node, const struct sc_attr* attr,
                            const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_prep_fn = sc_signal_vi_prep;
    nt->nt_select_subnode_fn = sc_signal_vi_select_subnode;
    nt->nt_add_link_fn = sc_signal_vi_add_link;
    nt->nt_pkts_fn = sc_signal_vi_pkts;
    nt->nt_end_of_stream_fn = sc_signal_vi_end_of_stream;
  }
  node->nd_type = nt;

  struct sc_signal_vi* ssv;
  ssv = sc_thread_calloc(sc_node_get_thread(node), sizeof(*ssv));
  node->nd_private = ssv;
  ssv->node = node;

  struct sc_node* ctl_node;
  int rc = sc_node_alloc(&ctl_node, attr, sc_node_get_thread(node),
                         &sc_signal_vi_ctl_sc_node_factory, NULL, 0);
  if( rc < 0 )
    return sc_node_fwd_error(node, rc);

  struct sc_signal_vi_ctl* ssv_ctl = ctl_node->nd_private;
  ssv_ctl->signal_vi = ssv;
  ssv->ctl_node = ctl_node;

  return 0;
}


const struct sc_node_factory sc_signal_vi_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_signal_vi",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_signal_vi_init,
};
/** \endcond NODOC */
