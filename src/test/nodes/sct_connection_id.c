/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/** \cond NODOC */
#include <sc_internal.h>

#include <errno.h>


struct sct_connection_id {
  struct sc_node*            node;
  struct sc_node*            ctl_node;
  int                        connection_id;

  const struct sc_node_link*  next_hop;
};


struct sct_connection_id_ctl {
  struct sc_node*            node;
  struct sct_connection_id*  cid;
  const struct sc_node_link* next_hop;
};


static void sct_connection_id_ctl_end_of_stream(struct sc_node* node)
{
  struct sct_connection_id_ctl* cid_ctl = node->nd_private;
  sc_node_link_end_of_stream(cid_ctl->node, cid_ctl->next_hop);
  struct sct_connection_id* cid = cid_ctl->cid;
  sc_node_link_end_of_stream(cid->node, cid->next_hop);
}


static void sct_connection_id_ctl_pkts(struct sc_node* node,
                                 struct sc_packet_list* pl)
{
  struct sct_connection_id_ctl* cid_ctl = node->nd_private;
  struct sc_packet* pkt = pl->head;
  int* tmp = NULL;
  while( pkt ) {
    tmp = pkt->iov[0].iov_base;
    if( pkt->iov[0].iov_len != sizeof(*tmp)) {
      printf("WARNING: %s: bad ctl message\n", __func__);
    }
    else {
      printf("WARNING: %s: changing connection id to %d\n", __func__, *tmp);
      cid_ctl->cid->connection_id = *tmp;
    }
    pkt = pkt->next;
  }
  sc_forward_list(node, cid_ctl->next_hop, pl);
}


static int sct_connection_id_ctl_prep(struct sc_node* node,
                                const struct sc_node_link*const* links,
                                int n_links)
{
  struct sct_connection_id_ctl* cid_ctl = node->nd_private;
  cid_ctl->next_hop = sc_node_prep_get_link_or_free(node, "");
  return sc_node_prep_check_links(node);
}


static int sct_connection_id_ctl_init(struct sc_node* node,
                                const struct sc_attr* attr,
                                const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_prep_fn = sct_connection_id_ctl_prep;
    nt->nt_pkts_fn = sct_connection_id_ctl_pkts;
    nt->nt_end_of_stream_fn = sct_connection_id_ctl_end_of_stream;
  }
  node->nd_type = nt;

  struct sct_connection_id_ctl* cid_ctl;
  cid_ctl = sc_thread_calloc(sc_node_get_thread(node), sizeof(*cid_ctl));
  cid_ctl->node = node;
  node->nd_private = cid_ctl;
  return 0;
}


const struct sc_node_factory sct_connection_id_ctl_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sct_connection_id_ctl",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sct_connection_id_ctl_init,
};


static void sct_connection_id_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct sct_connection_id* cid = node->nd_private;

  struct sc_packet* pkt = pl->head;
  int* uid;
  while( pkt ) {
    uid = (void*)&pkt->metadata;
    *uid = cid->connection_id;
    pkt = pkt->next;
  }
  sc_forward_list(cid->node, cid->next_hop, pl);
}


struct sc_node* sct_connection_id_select_subnode(struct sc_node* node,
                                           const char* name,
                                           char** new_name_out)
{
  struct sct_connection_id* cid = node->nd_private;

  if( name == NULL || ! strcmp(name, "") )
    return node;
  if( ! strcmp(name, "ctl") )
    return cid->ctl_node;
  sc_node_set_error(node, EINVAL,
                    "sc_stopcock: ERROR: bad incoming link name '%s'\n", name);
  return NULL;
}


static int sct_connection_id_add_link(struct sc_node* from_node,
                                const char* link_name,
                                struct sc_node* to_node,
                                const char* to_name_opt)
{
  struct sct_connection_id* cid = from_node->nd_private;
  int rc;
  if( ! strcmp(link_name, "") )
    rc = sc_node_add_link(from_node, link_name, to_node, to_name_opt);
  else if( ! strcmp(link_name, "ctl") )
    rc = sc_node_add_link(cid->ctl_node, "", to_node, to_name_opt);
  else
    return sc_node_set_error(from_node, EINVAL, "sc_stopcock: ERROR: bad "
                             "link name '%s'\n", link_name);
  if( rc < 0 )
    return sc_node_fwd_error(from_node, rc);
  return 0;
}


static void sct_connection_id_end_of_stream(struct sc_node* node)
{
  struct sct_connection_id* cid = node->nd_private;
  sc_node_link_end_of_stream(cid->node, cid->next_hop);
}


static int sct_connection_id_prep(struct sc_node* node,
                             const struct sc_node_link*const* links,
                             int n_links)
{
  struct sct_connection_id* cid = node->nd_private;
  cid->next_hop = sc_node_prep_get_link_or_free(node, "");
  return sc_node_prep_check_links(node);
}


static int sct_connection_id_init(struct sc_node* node, const struct sc_attr* attr,
                            const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_prep_fn = sct_connection_id_prep;
    nt->nt_select_subnode_fn = sct_connection_id_select_subnode;
    nt->nt_add_link_fn = sct_connection_id_add_link;
    nt->nt_pkts_fn = sct_connection_id_pkts;
    nt->nt_end_of_stream_fn = sct_connection_id_end_of_stream;
  }
  node->nd_type = nt;

  struct sct_connection_id* cid;
  cid = sc_thread_calloc(sc_node_get_thread(node), sizeof(*cid));
  node->nd_private = cid;
  cid->node = node;
  cid->connection_id = 1;

  struct sc_node* ctl_node;
  int rc = sc_node_alloc(&ctl_node, attr, sc_node_get_thread(node),
                         &sct_connection_id_ctl_sc_node_factory, NULL, 0);
  if( rc < 0 )
    return sc_node_fwd_error(node, rc);

  struct sct_connection_id_ctl* cid_ctl = ctl_node->nd_private;
  cid_ctl->cid = cid;
  cid->ctl_node = ctl_node;

  return 0;
}


const struct sc_node_factory sct_connection_id_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sct_connection_id",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sct_connection_id_init,
};
/** \endcond */
