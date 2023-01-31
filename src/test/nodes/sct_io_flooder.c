/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#include <sc_internal.h>
#include <sc_internal/io.h>
#include <solar_capture/nodes/subnode_helper.h>

#include <errno.h>


struct flooder {
  struct sc_node*            node;
  const struct sc_node_link* next_hop;

  struct sc_packet_list      backlog;
  struct sc_subnode_helper*  sh;
  int                        conn_id;
};


static void flooder_go(struct flooder* fl)
{
  SC_TEST( fl->conn_id != -1 && ! sc_packet_list_is_empty(&fl->backlog) );
  struct sc_packet* pkt = fl->backlog.head;
  while( pkt != NULL ) {
    struct sc_io_msg_hdr* hdr = pkt->iov[0].iov_base;
    hdr->msg_type = SC_IO_MSG_DATA;
    hdr->connection_id = fl->conn_id;
    pkt->iov[0].iov_len = sizeof(*hdr) + 32;
    pkt = pkt->next;
  }
  sc_forward_list(fl->node, fl->next_hop, &fl->backlog);
  sc_packet_list_init(&fl->backlog);
}


static void flooder_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct flooder* fl = node->nd_private;
  sc_packet_list_append_list(&fl->backlog, pl);
  if( fl->conn_id != -1 )
    flooder_go(fl);
}


static void flooder_handle_msg(struct sc_subnode_helper* sh)
{
  struct flooder* fl = sh->sh_private;
  struct sc_packet* pkt = sc_packet_list_pop_head(&sh->sh_backlog);
  struct sc_io_msg_hdr* hdr = pkt->iov[0].iov_base;
  if( hdr->msg_type == SC_IO_MSG_NEW_CONN ) {
    fl->conn_id = hdr->connection_id;
    if( ! sc_packet_list_is_empty(&fl->backlog) )
      flooder_go(fl);
  }
  else if( hdr->msg_type == SC_IO_MSG_CLOSE ) {
    fl->conn_id = -1;
  }
}


static struct sc_node* flooder_select_subnode(struct sc_node* node,
                                              const char* name,
                                              char** new_name_out)
{
  struct flooder* fl = node->nd_private;
  if( strcmp(name, "") )
    node = fl->sh->sh_node;
  return node;
}


static int flooder_prep(struct sc_node* node,
                       const struct sc_node_link*const* links, int n_links)
{
  struct flooder* fl = node->nd_private;
  fl->next_hop = sc_node_prep_get_link_or_free(node, "");
  return sc_node_prep_check_links(node);
}


static int flooder_init(struct sc_node* node, const struct sc_attr* attr,
                        const struct sc_node_factory* factory)
{
  struct sc_thread* thread = sc_node_get_thread(node);
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_prep_fn = flooder_prep;
    nt->nt_select_subnode_fn = flooder_select_subnode;
    nt->nt_pkts_fn = flooder_pkts;
  }
  node->nd_type = nt;

  struct flooder* fl = sc_thread_calloc(thread, sizeof(*fl));
  node->nd_private = fl;
  fl->node = node;
  sc_packet_list_init(&fl->backlog);
  fl->conn_id = -1;

  struct sc_node* sh_node;
  SC_TRY( sc_node_alloc_named(&sh_node, attr, thread, "sc_subnode_helper",
                              NULL, NULL, 0) );
  fl->sh = sc_subnode_helper_from_node(sh_node);
  fl->sh->sh_private = fl;
  fl->sh->sh_handle_backlog_fn = flooder_handle_msg;

  return 0;
}


const struct sc_node_factory sct_io_flooder_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sct_io_flooder",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = flooder_init,
};
