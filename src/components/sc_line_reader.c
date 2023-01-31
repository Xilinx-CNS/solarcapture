/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \node{sc_line_reader}
 *
 * \brief This node parses out lines from a data stream.
 *
 * \nodedetails
 * This node parses out lines from a data stream. Input is interpreted
 * as a stream of text data. Output is a single contiguous packet buffer per
 * line of input.
 * 
 * This is useful for parsing ::sc_packet objects created by an
 * \noderef{sc_fd_reader} node, and converting them into one ::sc_packet
 * object per line.
 *
 * \nodeargs
 * Argument           | Optional? | Default   | Type           | Description
 * ------------------ | --------- | --------- | -------------- | ----------------------------------------------------------------------------------------------------
 * forward_truncated  | Yes       | 0         | ::SC_PARAM_INT | Specifies whether lines too large to fit in an ::sc_packet object should be sent down stream. If set to true such packets will have the ::SC_TRUNCATED flag set.
 * lstrip             | Yes       | 1         | ::SC_PARAM_INT | Specifies whether whitespace should be stripped from the start of a line.
 * rstrip             | Yes       | 1         | ::SC_PARAM_INT | Specifies whether whitespace should be stripped from the end of a line.
 * strip_comments     | Yes       | 1         | ::SC_PARAM_INT | Specifies whether lines starting with '#' should be forwarded.
 * strip_blank        | Yes       | 1         | ::SC_PARAM_INT | Specifies whether blank lines should be forwarded.
 * add_nul            | Yes       | 1         | ::SC_PARAM_INT | Specifies whether a nul ('\0') character should be appended to each line sent downstream.
 * add_new_line       | Yes       | 0         | ::SC_PARAM_INT | Specifies whether a new line ('\n') character should be appended to each line sent downstream.
 *
 * \namedinputlinks
 * None
 *
 * \outputlinks
 * Link    | Description
 * ------- |----------------------------------------------------------------------------
 * ""      | One ::sc_packet object per line in the input data stream.
 * "input" | The ::sc_packet objects sent on the "" input link.
 *
 * \cond NODOC
 */

#include <sc_internal.h>
#include <sc_internal/builtin_nodes.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>


struct sc_line_reader {
  struct sc_node*            node;
  struct sc_attr*            attr;
  const struct sc_node_link* next_hop;
  const struct sc_node_link* free_input_hop;
  const struct sc_node_link* free_bufs_hop;
  struct sc_pool*            pool;
  struct sc_callback*        pool_cb;
  int                        forward_truncated;
  int                        lstrip;
  int                        rstrip;
  int                        strip_comments;
  int                        strip_blank;
  int                        add_nul;
  int                        add_new_line;
  int                        space_for_terminators;

  struct sc_packet_list      in_pl;
  struct sc_iovec_ptr        in_iovp;
  struct sc_packet*          pkt;
  uint8_t*                   pkt_start;
  uint8_t*                   pkt_end;
  int                        eof;
};


static char* pkt_start(struct sc_packet* pkt)
{
  return (char*) pkt->iov[0].iov_base;
}


static char* pkt_ptr(struct sc_packet* pkt)
{
  return (char*) pkt->iov[0].iov_base + pkt->iov[0].iov_len;
}


static void pkt_lstrip(struct sc_packet* pkt, int n)
{
  assert(pkt->frame_len > n);
  pkt->iov[0].iov_base = (char*) pkt->iov[0].iov_base + n;
  pkt->iov[0].iov_len -= n;
  pkt->frame_len -= n;
}


static void pkt_rstrip(struct sc_packet* pkt, int n)
{
  assert(pkt->frame_len > n);
  pkt->iov[0].iov_len -= n;
  pkt->frame_len -= n;
}


static int lr_pkt_space(struct sc_line_reader* lr)
{
  return lr->pkt_end - (uint8_t*) pkt_ptr(lr->pkt);
}


static void lr_pkt_undo(struct sc_line_reader* lr)
{
  lr->pkt->iov[0].iov_base = lr->pkt_start;
  lr->pkt->iov[0].iov_len = 0;
  lr->pkt->frame_len = 0;
  lr->pkt->flags = 0;
}


static void sc_line_reader_send(struct sc_line_reader* lr)
{
  struct sc_packet* pkt = lr->pkt;

  if( (pkt->flags & SC_TRUNCATED) && ! lr->forward_truncated ) {
    fprintf(stderr, "sc_line_reader: [%s] ERROR: input line too long\n",
            lr->node->nd_name);//??
    lr_pkt_undo(lr);
    return;
  }

  while( lr->lstrip && isspace(pkt_start(pkt)[0]) )
    pkt_lstrip(pkt, 1);
  while( lr->rstrip && pkt->frame_len > 1 && isspace(pkt_ptr(pkt)[-1]) )
    pkt_rstrip(pkt, 1);

  if( (lr->strip_blank && pkt->frame_len == 0) ||
      (lr->strip_comments && pkt_start(pkt)[0] == '#') ) {
    lr_pkt_undo(lr);
    return;
  }

  /* Append a string terminator. */
  if( lr->add_new_line ) {
    assert( lr_pkt_space(lr) >= 1 );
    pkt_ptr(pkt)[0] = '\n';
    ++(pkt->iov[0].iov_len);
    ++(pkt->frame_len);
  }
  if( lr->add_nul ) {
    assert( lr_pkt_space(lr) >= 1 );
    pkt_ptr(pkt)[0] = '\0';
    ++(pkt->iov[0].iov_len);
    ++(pkt->frame_len);
  }

  sc_forward(lr->node, lr->next_hop, pkt);
  lr->pkt = NULL;
}


static int sc_line_reader_get_pkt(struct sc_line_reader* lr)
{
  struct sc_packet_list pl;
  __sc_packet_list_init(&pl);
  if( sc_pool_get_packets(&pl, lr->pool, 1, 1) != 1 ) {
    sc_pool_on_threshold(lr->pool, lr->pool_cb, 1);
    return 0;
  }
  lr->pkt = pl.head;
  lr->pkt_end = (void*) pkt_ptr(lr->pkt);
  lr->pkt_start = (void*) pkt_start(lr->pkt);
  lr->pkt->iov[0].iov_len = 0;
  return 1;
}


static void sc_line_reader_try(struct sc_line_reader* lr)
{
  int n;

  while( ! sc_packet_list_is_empty(&lr->in_pl) ) {
    if( lr->pkt == NULL && ! sc_line_reader_get_pkt(lr) )
      return;
    int space = lr_pkt_space(lr) - lr->space_for_terminators;
    int nl_off = sc_iovec_ptr_find_chr(&lr->in_iovp, '\n');
    if( nl_off >= 0 ) {
      if( space >= nl_off ) {
        n = sc_packet_append_iovec_ptr(lr->pkt, NULL, &lr->in_iovp, nl_off);
        assert(n == 0);  (void) n;
      }
      else {
        n = sc_packet_append_iovec_ptr(lr->pkt, NULL, &lr->in_iovp, space);
        assert(n == 0);
        lr->pkt->flags |= SC_TRUNCATED;
        n = sc_iovec_ptr_skip(&lr->in_iovp, nl_off - space);
        assert(n == nl_off - space);
      }
      /* Skip the '\n' in the input. */
      n = sc_iovec_ptr_skip(&lr->in_iovp, 1);
      assert(n == 1);
      sc_line_reader_send(lr);
    }
    else {
      /* '\n' not found in current packet, so copy/trash and move on. */
      int in_bytes_left = sc_iovec_ptr_bytes(&lr->in_iovp);
      if( in_bytes_left ) {
        sc_packet_append_iovec_ptr(lr->pkt, NULL, &lr->in_iovp, space);
        if( space < in_bytes_left )
          lr->pkt->flags |= SC_TRUNCATED;
      }
      sc_forward(lr->node, lr->free_input_hop,
                 sc_packet_list_pop_head(&lr->in_pl));
      if( ! sc_packet_list_is_empty(&lr->in_pl) )
        sc_iovec_ptr_init_packet(&lr->in_iovp, lr->in_pl.head);
    }
  }

  if( lr->eof ) {
    if( lr->pkt != NULL ) {
      if( lr->pkt->frame_len )
        sc_line_reader_send(lr);
      if( lr->pkt != NULL ) {
        sc_forward(lr->node, lr->free_bufs_hop, lr->pkt);
        lr->pkt = NULL;
      }
    }
    sc_node_link_end_of_stream(lr->node, lr->free_input_hop);
    sc_node_link_end_of_stream(lr->node, lr->free_bufs_hop);
    sc_node_link_end_of_stream(lr->node, lr->next_hop);
  }
}


static void sc_line_reader_pool_cb(struct sc_callback* cb, void* event_info)
{
  struct sc_line_reader* lr = cb->cb_private;
  sc_line_reader_try(lr);
}


static void sc_line_reader_pkts(struct sc_node* node,
                                struct sc_packet_list* pl)
{
  struct sc_line_reader* lr = node->nd_private;
  int was_empty = sc_packet_list_is_empty(&lr->in_pl);
  sc_packet_list_append_list(&lr->in_pl, pl);
  if( was_empty )
    sc_iovec_ptr_init_packet(&lr->in_iovp, lr->in_pl.head);
  if( ! sc_callback_is_active(lr->pool_cb) )
    sc_line_reader_try(lr);
}


static void sc_line_reader_end_of_stream(struct sc_node* node)
{
  struct sc_line_reader* lr = node->nd_private;
  SC_TEST(lr->eof == 0);
  lr->eof = 1;
  sc_line_reader_try(lr);
}


static int sc_line_reader_prep(struct sc_node* node,
                               const struct sc_node_link*const* links,
                               int n_links)
{
  struct sc_line_reader* lr = node->nd_private;
  int rc;

  lr->free_input_hop = sc_node_prep_get_link_or_free(node, "input");
  lr->free_bufs_hop = sc_node_prep_get_link_or_free(node, NULL);
  if( (lr->next_hop = sc_node_prep_get_link_or_free(node, "")) == NULL )
    return sc_node_set_error(node, EINVAL,
                             "sc_line_reader: ERROR: no next hop\n");
  if( sc_node_prep_check_links(node) < 0 )
    return -1;
  const struct sc_node_link* plinks[] = { lr->next_hop, lr->free_bufs_hop };
  if( (rc = sc_node_prep_get_pool(&lr->pool, lr->attr, node, plinks, 2)) < 0 )
    return sc_node_fwd_error(node, rc);
  sc_node_prep_does_not_forward(node);
  sc_node_prep_link_forwards_from_node(node, lr->free_input_hop, node);
  return 0;
}


static int get_int_arg(int* pval, struct sc_node* node, const char* name,
                       int default_val)
{
  int rc = sc_node_init_get_arg_int(pval, node, name, default_val);
  if( rc < 0 )
    sc_node_set_error(node, EINVAL, "sc_line_reader: bad arg '%s'\n", name);
  return rc;
}


static int sc_line_reader_init(struct sc_node* node,
                               const struct sc_attr* attr,
                               const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_prep_fn = sc_line_reader_prep;
    nt->nt_pkts_fn = sc_line_reader_pkts;
    nt->nt_end_of_stream_fn = sc_line_reader_end_of_stream;
  }
  node->nd_type = nt;

  struct sc_line_reader* lr;
  lr = sc_thread_calloc(sc_node_get_thread(node), sizeof(*lr));
  node->nd_private = lr;
  lr->node = node;

  if( get_int_arg(&lr->forward_truncated, node, "forward_truncated", 0) < 0 )
    goto error;
  if( get_int_arg(&lr->lstrip, node, "lstrip", 1) < 0 )
    goto error;
  if( get_int_arg(&lr->rstrip, node, "rstrip", 1) < 0 )
    goto error;
  if( get_int_arg(&lr->strip_comments, node, "strip_comments", 1) < 0 )
    goto error;
  if( get_int_arg(&lr->strip_blank, node, "strip_blank", 1) < 0 )
    goto error;
  if( get_int_arg(&lr->add_nul, node, "add_nul", 1) < 0 )
    goto error;
  if( get_int_arg(&lr->add_new_line, node, "add_new_line", 0) < 0 )
    goto error;

  sc_packet_list_init(&lr->in_pl);
  SC_TRY(sc_callback_alloc(&lr->pool_cb, attr, sc_node_get_thread(node)));
  lr->pool_cb->cb_private = lr;
  lr->pool_cb->cb_handler_fn = sc_line_reader_pool_cb;
  lr->attr = sc_attr_dup(attr);
  SC_TRY(sc_attr_set_int(lr->attr, "private_pool", 1));
  lr->space_for_terminators = (lr->add_nul != 0) + (lr->add_new_line != 0);
  return 0;

 error:
  sc_thread_mfree(sc_node_get_thread(node), lr);
  return -1;
}


const struct sc_node_factory sc_line_reader_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_line_reader",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_line_reader_init,
};

/** \endcond NODOC */
