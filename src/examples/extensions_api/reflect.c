/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/*
 * This file contains an example implementation of a packet processing
 * 'node' for SolarCapture.  A node is a component of software which forms
 * part of a packet processing pipeline.
 *
 * This node just swaps the source and destination MAC addresses in the
 * Ethernet header.  It can therefore be used to 'reflect' packets back to
 * the sender.
 */


/* Specify the level of the SolarCapture API used by this node.  The value
 * of SC_API_VER determines the versions of SolarCapture that the node can
 * be used with.  ie. A node compiled with SC_API_VER set to 2 can be used
 * with libsolarcapture1.so.2.0 or later.
 */
#define SC_API_VER 4
#include <solar_capture.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>


/* Private state for this type of node. */
struct reflect_state {
  int                        logging;
  const struct sc_node_link* next_hop;
};


/* The nt_prep_fn() method is called to prepare the node prior to packet
 * processing starting.  It gives the node an opportunity to discover its
 * outgoing links, and to allocate resources.
 *
 * The nt_prep_fn() is called in response to sc_session_prepare() or
 * sc_session_go().
 *
 * There are two ways to query the set of outgoing links: Either inspect
 * the 'links' array passed as an argument, or invoke
 * sc_node_prep_get_link() and sc_node_prep_get_link_or_free().  Use the
 * latter if you're expecting outgoing links with fixed known names, and
 * the former if outgoing links can have arbitrary names.
 */
static int reflect_prep(struct sc_node* node,
                         const struct sc_node_link*const* links, int n_links)
{
  struct reflect_state* st = node->nd_private;

  /* This node requires an outgoing link named '' and will raise an error
   * if there isn't one.
   *
   * If your node has optional outgoing links, you can either inspect the
   * 'links' argument, or call sc_node_prep_get_link_or_free().
   */
  st->next_hop = sc_node_prep_get_link(node, "");
  if( st->next_hop == NULL )
    return sc_node_set_error(node, EINVAL,
                             "%s: ERROR: no next hop\n", __func__);

  /* The sc_node_prep_check_links() call checks to see if any links have
   * been added that we haven't queried.  If there are any then an error is
   * raised.
   */
  return sc_node_prep_check_links(node);
}


static int pkt_is_unicast(const struct sc_packet* pkt)
{
  const uint8_t* addr = pkt->iov[0].iov_base;
  return (addr[0] & 1) == 0;
}


/* Swap source and destination MAC addresses.  (The destination mac is the
 * first 6 bytes in a packet, and the source mac the next 6 bytes).
 */
static inline void reflect_packet(struct sc_packet* pkt)
{
  uint8_t* p_dmac = pkt->iov[0].iov_base;
  uint8_t* p_smac = p_dmac + 6;
  uint8_t tmp[6];
  memcpy(tmp, p_dmac, 6);
  memcpy(p_dmac, p_smac, 6);
  memcpy(p_smac, tmp, 6);
}


static inline void log_packet(const struct sc_packet* pkt)
{
  const uint8_t* m = pkt->iov[0].iov_base;
  fprintf(stderr, "reflect: %02x:%02x:%02x:%02x:%02x:%02x\n",
          (unsigned) m[0], (unsigned) m[1], (unsigned) m[2],
          (unsigned) m[3], (unsigned) m[4], (unsigned) m[5]);
}


/* The nt_pkts_fn() method is called when packets arrive at a node along an
 * incoming link.  The node can inspect the packets, modify them, buffer
 * them and/or forward them along an outgoing link.  Packets are freed by
 * forwarding along a link that is not connected to any other node.
 */
static void reflect_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct reflect_state* st = node->nd_private;
  struct sc_packet* next;
  struct sc_packet* pkt;

  for( next = pl->head; (pkt = next) && ((next = next->next), 1); ) {
    if( st->logging )
      log_packet(pkt);
    if( pkt_is_unicast(pkt) )
      reflect_packet(pkt);
    sc_forward2(st->next_hop, pkt);
  }
}


/* The nt_end_of_stream_fn() method is called when all incoming links have
 * themselves indicated end-of-stream.  Once a node has finished forwarding
 * packets down an outgoing link it should invoke
 * sc_node_link_end_of_stream2().
 */
static void reflect_end_of_stream(struct sc_node* node)
{
  struct reflect_state* st = node->nd_private;
  sc_node_link_end_of_stream2(st->next_hop);
}


/* The nf_init_fn() method is invoked by SolarCapture to instantiate a new
 * node instance.  It should allocate any private state for the node, and
 * initialise the sc_node_type callbacks.
 *
 * Node arguments passed to sc_node_alloc() or sc_node_alloc_named() can be
 * queried by calling sc_node_init_get_arg_*().
 */
static int reflect_init(struct sc_node* node, const struct sc_attr* attr,
                        const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_pkts_fn = reflect_pkts;
    nt->nt_prep_fn = reflect_prep;
    nt->nt_end_of_stream_fn = reflect_end_of_stream;
  }
  node->nd_type = nt;

  /* sc_thread_calloc() is used to allocate zeroed memory that is on the
   * appropriate numa-node for the thread.
   */
  struct sc_thread* thread = sc_node_get_thread(node);
  struct reflect_state* st = sc_thread_calloc(thread, sizeof(*st));
  node->nd_private = st;

  if( sc_node_init_get_arg_int(&st->logging, node, "enable_logging", 0) < 0 ) {
    /* Argument passed had the wrong type (not an integer). */
    sc_thread_mfree(thread, st);
    return -1;
  }

  return 0;
}


/* The node factory provides the information needed for SolarCapture to
 * create nodes of this type.
 *
 * When a node factory is in a node library (a shared library object), the
 * instance must be named foo_sc_node_factory so that it can be found by a
 * call to sc_node_factory_lookup(&f, tg, "foo", lib).
 */
const struct sc_node_factory reflect_sc_node_factory = {
  /* The node API version is used to ensure that the node factory is
   * compatible with the version of SolarCapture that is trying to create
   * the node.
   */
  .nf_node_api_ver   = SC_API_VER,
  /* The name of this node factory.
   */
  .nf_name           = "reflect",
  /* The name of the source file that implements the node.
   */
  .nf_source_file    = __FILE__,
  /* SolarCapture invokes this method to instantiate new nodes.
   */
  .nf_init_fn        = reflect_init,
};
