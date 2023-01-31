/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \addtogroup scnode SolarCapture Nodes
 * @{
 * \struct sc_catchup
 * \brief Node that takes in blocks of packet data with headers (per the struct in sct_serialiser.h)
          and forwards individual packets annotated by the header information.
 *
 * \nodeargs
 * No arguments
 *
 * \namedinputlinks
 * None
 *
 * \outputlinks
 * Link  | Description
 * ------| -----------------------------------
 *  ""   | Individual packets built from the header information and packet data
 *
 * \cond NODOC
 */
#include <sc_internal.h>
#include <sc_internal/builtin_nodes.h>
#include <solar_capture/nodes/subnode_helper.h>
#include <solar_capture/iovec.h>
#include <errno.h>

#include "sct_pkt_serialiser.h"


struct sct_pkt_deserialiser_internal
{
  struct sc_node*              node;
  struct sc_subnode_helper*    sh;
  struct sc_serialised_pkt_hdr current_pkt_hdr;
  struct sc_packet*            out_pkt;
  int                          header_fill;
  struct sc_iovec_ptr          in_packet_iovec;
  struct sc_attr*              attr;
  struct sc_pool*              pool;
  const struct sc_node_link*   next_hop;
};


static void sct_pkt_deserialiser_eos(struct sc_subnode_helper* sh)
{
  struct sct_pkt_deserialiser_internal* ps = sh->sh_private;
  sc_node_link_end_of_stream(ps->node, ps->next_hop);
}


static void sct_pkt_deserialiser_handle_packets(struct sc_subnode_helper* sh)
{
  struct sct_pkt_deserialiser_internal* ps = sh->sh_private;
  struct sc_packet_list pl;
  unsigned int header_left;

  /* Set iovec to point to first packet */
  if( ps->in_packet_iovec.iov == NULL )
    sc_iovec_ptr_init_packet(&ps->in_packet_iovec, sh->sh_backlog.head);

  while( !sc_packet_list_is_empty(&sh->sh_backlog) ) {
    header_left = sizeof(struct sc_serialised_pkt_hdr) - ps->header_fill;
    if( header_left ) {
      /* Fill packet header */
      ps->header_fill += sc_iovec_ptr_copy_out(((uint8_t*)&ps->current_pkt_hdr)
                         + ps->header_fill, &ps->in_packet_iovec, header_left);
     }
     else {
      /* Get a new outgoing packet (if not resuming from running out of input data) */
      if( ps->out_pkt == NULL ) {
        /* Create a new output packet */
        sc_packet_list_init(&pl);
        if( sc_pool_get_packets(&pl, ps->pool, 1, 1) != 1 )
          return; /* Pool empty */
        ps->out_pkt = pl.head;

        /* Check that the packet we are deserialising is smaller or equal
         * to the outgoing pool size */
        SC_TEST( ps->out_pkt->iov[0].iov_len >= ps->current_pkt_hdr.packet_length + ps->current_pkt_hdr.metadata_length );
        ps->out_pkt->iov[0].iov_len = 0;
      }

      /* Fill packet data */
      ps->out_pkt->iov[0].iov_len += sc_iovec_ptr_copy_out(
         ((uint8_t*)ps->out_pkt->iov[0].iov_base) + ps->out_pkt->iov[0].iov_len,
         &ps->in_packet_iovec,
         ps->current_pkt_hdr.packet_length + ps->current_pkt_hdr.metadata_length - ps->out_pkt->iov[0].iov_len);

      if( ps->out_pkt->iov[0].iov_len == ps->current_pkt_hdr.packet_length + ps->current_pkt_hdr.metadata_length ) {
        /* Set packet length information */
        ps->header_fill = 0; /* Need new header for next packet */
        if( ps->current_pkt_hdr.packet_length < UINT16_MAX )
          ps->out_pkt->frame_len = ps->current_pkt_hdr.packet_length;
        else
          ps->out_pkt->frame_len = 0; /* Packet length too large to set */

        /* Send new packet on */
        ps->out_pkt->metadata = ps->out_pkt->iov[0].iov_base;
        ps->out_pkt->iov[0].iov_base = (uint8_t*)ps->out_pkt->iov[0].iov_base + ps->current_pkt_hdr.metadata_length;
        ps->out_pkt->iov[0].iov_len -= ps->current_pkt_hdr.metadata_length;
        ps->out_pkt->flags = ps->current_pkt_hdr.flags;
        ps->out_pkt->frame_len = ps->current_pkt_hdr.frame_len;
        ps->out_pkt->ts_sec = ps->current_pkt_hdr.ts_sec;
        ps->out_pkt->ts_nsec = ps->current_pkt_hdr.ts_nsec;
        sc_forward(ps->node, ps->next_hop, ps->out_pkt);
        ps->out_pkt = NULL;
      }
    }
    if( sc_iovec_ptr_bytes(&ps->in_packet_iovec) == 0 ) {
      /* Free incoming packet */
      sc_forward(sh->sh_node,
                 sh->sh_free_link,
                 sc_packet_list_pop_head(&sh->sh_backlog));

      if( !sc_packet_list_is_empty(&sh->sh_backlog) )
        sc_iovec_ptr_init_packet(&ps->in_packet_iovec, sh->sh_backlog.head);
      else
        ps->in_packet_iovec.iov = NULL;

    }
  }
}


/* Node Links */
static struct sc_node* sct_pkt_deserialiser_select_subnode(struct sc_node* node,
                                                  const char* name,
                                                  char** new_name_out)
{
  struct sct_pkt_deserialiser_internal* ps = node->nd_private;
  return ps->sh->sh_node;
}


static int sct_pkt_deserialiser_prep(struct sc_node* node,
                                 const struct sc_node_link*const* links,
                                 int n_links)
{
  /* Get our internal pool */
  struct sct_pkt_deserialiser_internal* ps = node->nd_private;
  ps->next_hop = sc_node_prep_get_link_or_free(node, "");

  int rc = sc_node_prep_get_pool(&ps->pool, ps->attr, node, NULL, 0);
  if( rc < 0 )
    return sc_node_fwd_error(node, rc);

  /* Tell our subnode helper about it */
  ps->sh->sh_pool = ps->pool;
  ps->sh->sh_pool_threshold = 1;
  return 0;
}


/* Initialisation */
static int sct_packet_setup_subnode(struct sct_pkt_deserialiser_internal *ps)
{
  struct sc_node* parent = ps->node;
  struct sc_node* subnode;
  struct sc_thread* thread = sc_node_get_thread(parent);

  int rc = sc_node_alloc_named(&subnode, ps->attr, thread,
                               "sc_subnode_helper", NULL, NULL, 0);
  if( rc < 0 )
    return sc_node_fwd_error(parent, rc);

  ps->sh = sc_subnode_helper_from_node(subnode);
  ps->sh->sh_private = ps;
  ps->sh->sh_handle_backlog_fn = sct_pkt_deserialiser_handle_packets;
  ps->sh->sh_handle_end_of_stream_fn = sct_pkt_deserialiser_eos;

  return 0;
}

static int sct_pkt_deserialiser_init(struct sc_node* node,
             const struct sc_attr* attr, const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    SC_TRY(sc_node_type_alloc(&nt, NULL, factory));
    nt->nt_select_subnode_fn = sct_pkt_deserialiser_select_subnode;
    nt->nt_prep_fn = sct_pkt_deserialiser_prep;
  }
  node->nd_type = nt;

  struct sct_pkt_deserialiser_internal* ps =
                       sc_thread_calloc(sc_node_get_thread(node), sizeof(*ps));
  node->nd_private = ps;
  ps->node = node;

  ps->attr = sc_attr_dup(attr);
  sc_attr_set_str(ps->attr, "name", "pkt_deserialiser_subnode");

  return sct_packet_setup_subnode(ps);
}


const struct sc_node_factory sct_pkt_deserialiser_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sct_pkt_deserialiser",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sct_pkt_deserialiser_init,
};
/** \endcond */
