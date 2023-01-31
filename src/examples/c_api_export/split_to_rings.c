/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/*
 * This file contains an implementation of a plugin node for SolarCapture,
 * which purpose is to extract traffic from solar capture framework
 * and export it to be handled externally.
 * 
 * During that process the incoming IP traffic is split into separate memory
 * rings to allow concurrent processing.  This allows to parallelize
 * the consumption of the traffic with separate threads.  Content of each
 * packet is copied into one of the memory rings according to hash of source
 * and destination IP addresses.
 */

#define SC_API_VER 4
#include <solar_capture.h>

#include "split_to_rings.h"
#include "pkt_ring.h"

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <stdint.h>
#include <assert.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netinet/ip.h>


/* Node state contains information where to pass the packets on to after
 * processing in the node is finished as well as information required for
 * processing within the node. The latter is pointer to memory ring array with
 * its length.
 */
struct split_to_rings_state {
  const struct sc_node_link* next_hop;
  struct pkt_ring*const*     pkt_rings;
  int                        n_pkt_rings;
};


static int select_ring(struct split_to_rings_state* st,
                       const struct sc_packet* pkt)
{
  struct ether_header* eth = pkt->iov[0].iov_base;
  if( eth->ether_type == htons(ETHERTYPE_IP) ) {
    const struct iphdr* ip = (void*) (&(eth->ether_type) + 1);
    uint32_t v = ip->saddr ^ ip->daddr;
    v = (v ^ (v >> 8) ^ (v >> 16) ^ (v >> 24)) % st->n_pkt_rings;
    return v;
  }
  return 0;
}


/* The packet function copies content of each packet into one of the memory
 * rings.
 *
 * For simplicity it drops packets that do not fit into the ring.
 * Also it only deals with packets consisting of single I/O vector.
 */
static void split_to_rings_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct split_to_rings_state* st = node->nd_private;
  struct sc_packet* next;
  struct sc_packet* pkt;

  for( next = pl->head; (pkt = next) && ((next = next->next) || 1); ) {
    assert(pkt->iovlen == 1);
    int ring_id = select_ring(st, pkt);
    /* NB. We are ignoring the return value, so we are dropping packets if
     * the ring gets full.  We should instead queue-up packets in this
     * scenario.
     */
    pkt_ring_put(st->pkt_rings[ring_id], pkt->iov[0].iov_base,
                 pkt->iov[0].iov_len);
  }

  /* Forward packet list to the subsequent link */
  sc_forward_list2(st->next_hop, pl);
}



static int split_to_rings_prep(struct sc_node* node,
                               const struct sc_node_link*const* links,
                               int n_links)
{
  struct split_to_rings_state* st = node->nd_private;
  /* Store pointer to the subsequent link.  In case the link has not been
   * provided get a link that simply frees packets.
   */
  st->next_hop = sc_node_prep_get_link_or_free(node, "");
  return sc_node_prep_check_links(node);
}


static int split_to_rings_init(struct sc_node* node, const struct sc_attr* attr,
                               const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_pkts_fn = split_to_rings_pkts;
    nt->nt_prep_fn = split_to_rings_prep;
  }
  node->nd_type = nt;

  /* Allocate structure to hold private state of the node.
   * As the state is used on performance critical path use
   * sc_thread_calloc function.
   */
  struct split_to_rings_state* st;
  st = sc_thread_calloc(sc_node_get_thread(node), sizeof(*st));
  node->nd_private = st;

  /* Obtain values of arguments required by the node. */
  struct sc_object* obj;
  if( sc_node_init_get_arg_obj(&obj, node, "pkt_rings", SC_OBJ_OPAQUE) != 0 ) {
    sc_node_set_error(node, EINVAL, "ERROR: pkt_rings arg missing or bad\n");
    goto error;
  }
  st->pkt_rings = sc_opaque_get_ptr(obj);
  if( sc_node_init_get_arg_int(&st->n_pkt_rings, node,
                               "n_pkt_rings", 0) != 0 ) {
    sc_node_set_error(node, EINVAL, "ERROR: n_pkt_rings arg missing or bad\n");
    goto error;
  }
  return 0;

 error:
  sc_thread_mfree(sc_node_get_thread(node), st);
  return -1;
}

/* The node factory provides the information needed for SolarCapture to
 * create a node of this type.
 */
const struct sc_node_factory split_to_rings_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "split_to_rings",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = split_to_rings_init,
};
