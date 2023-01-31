/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \node{sc_snap}
 *
 * \brief Node that limits the length of a packet buffer.
 *
 * \nodedetails
 * Node that limits the length of a packet buffer.
 * Packets forwarded by this node are modified as follows: If the length of
 * the payload area exceeds the snap length, then it is reduced to the snap
 * length.  The frame_len field is not modified.
 *
 * \nodeargs
 * Argument      | Optional? | Default | Type           | Description
 * ------------- | --------- | ------- | -------------- | -------------------------------------------------------------------------------------------------------
 * snap          | No        |         | ::SC_PARAM_INT | Maximum payload length.
 *
 * \cond NODOC
 */
#define SC_API_VER 1
#include <solar_capture.h>
#include <sc_internal/builtin_nodes.h>

#include <errno.h>
#include <assert.h>


struct sc_snap_state {
  const struct sc_node_link* next_hop;
  int                        snap;
};


static void sc_snap_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct sc_snap_state* st = node->nd_private;
  struct sc_packet* next;
  struct sc_packet* pkt;

  for( next = pl->head; (pkt = next) && ((next = next->next), 1); )
    if( pkt->iovlen == 1 ) {
      if( pkt->iov[0].iov_len >= st->snap )
        pkt->iov[0].iov_len = st->snap;
    }
    else {
      assert(pkt->iovlen > 1);
      int i, n = st->snap;
      for( i = 0; i < pkt->iovlen; ++i )
        if( pkt->iov[i].iov_len >= n ) {
          pkt->iov[i].iov_len = n;
          pkt->iovlen = i + 1;
          break;
        }
        else {
          n -= pkt->iov[i].iov_len;
        }
    }

  sc_forward_list(node, st->next_hop, pl);
}


static void sc_snap_end_of_stream(struct sc_node* node)
{
  struct sc_snap_state* st = node->nd_private;
  sc_node_link_end_of_stream(node, st->next_hop);
}


static int sc_snap_prep(struct sc_node* node,
                          const struct sc_node_link*const* links, int n_links)
{
  struct sc_snap_state* st = node->nd_private;
  st->next_hop = sc_node_prep_get_link_or_free(node, "");
  return sc_node_prep_check_links(node);
}


static int sc_snap_init(struct sc_node* node, const struct sc_attr* attr,
                          const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_pkts_fn = sc_snap_pkts;
    nt->nt_prep_fn = sc_snap_prep;
    nt->nt_end_of_stream_fn = sc_snap_end_of_stream;
  }
  node->nd_type = nt;

  struct sc_snap_state* st;
  st = sc_thread_calloc(sc_node_get_thread(node), sizeof(*st));
  node->nd_private = st;
  int rc = sc_node_init_get_arg_int(&st->snap, node, "snap", -1);
  if( rc < 0 )
    goto error;
  if( rc > 0 || st->snap <= 0 ) {
    sc_node_set_error(node, EINVAL, "%s: ERROR: arg 'snap' missing or "
                      "bad (%d)\n", __func__, st->snap);
    goto error;
  }
  return 0;

 error:
  sc_thread_mfree(sc_node_get_thread(node), st);
  return -1;
}


const struct sc_node_factory sc_snap_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_snap",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_snap_init,
};

/** \endcond NODOC */
