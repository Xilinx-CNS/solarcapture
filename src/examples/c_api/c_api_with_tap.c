/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/*
 * This file contains an example of how to use the SolarCapture C API.  It
 * reads packets in from a pcap file, uses a tap node to split the stream
 * into two copies, and then uses two injector nodes to transmit the packets
 * and copies on two different ports.
 */

#define SC_API_VER 1
#include <solar_capture.h>
#include <solar_capture_ext.h>

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>


#define TRY(x)                                                  \
  do {                                                          \
    int __rc = (x);                                             \
    if( __rc < 0 ) {                                            \
      fprintf(stderr, "ERROR: TRY(%s) failed\n", #x);           \
      fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__); \
      fprintf(stderr, "ERROR: rc=%d errno=%d (%s)\n",           \
              __rc, errno, strerror(errno));                    \
      exit(1);                                                  \
    }                                                           \
  } while( 0 )

#define N_ARGS(x) (sizeof((x)) / sizeof((x)[0]))


/* Predicate state struct. The app allocates one of these at setup time,
 * which will be passed to the predicate function each time it is called.
 *
 * This example has a single field to store the maximum acceptable packet
 * size, but in general the state can be arbitrarily complex.
 *
 * It is also valid to modify the state at runtime, from either within
 * the predicate function or elsewhere. */
struct size_filter_state {
  uint32_t max_size;
};


int filter_by_size(struct sc_pkt_predicate* pred, struct sc_packet* pkt)
{
  struct size_filter_state* state = pred->pred_private;
  return pkt->frame_len <= state->max_size;
}


int main(int argc, char* argv[])
{
  if( argc != 4 ) {
    printf("Usage: %s <pcap> <intf1> <intf2>\n", argv[0]);
    exit(1);
  }

  /* Attributes are used to specify options.  The defaults are
   * fine for this application. */
  struct sc_attr* attr;
  TRY(sc_attr_alloc(&attr));

  /* A session is an association between components that together
   * form a single SolarCapture topology. */
  struct sc_session* tg;
  TRY(sc_session_alloc(&tg, attr));

  struct sc_thread* t;
  TRY(sc_thread_alloc(&t, attr, tg));


  /****************************************************************************
   * PCAP reader node                                                         *
   ****************************************************************************
   * A reader node reads pcap data from a file and emits a stream
   * of packets */
  struct sc_node* reader_node;

  /* Most nodes take one or more arguments. For the reader we
   * specify where to read packets from, and what to do on reaching
   * end-of-file. */
  struct sc_arg reader_args[] = {
    SC_ARG_STR("filename", argv[1]),

    /* signal_eof: on reaching end-of-file, send an end-of-stream
     * signal to indicate to downstream nodes that no more packets
     * will be sent. */
    SC_ARG_INT("signal_eof", 1),
  };

  TRY( sc_node_alloc_named(&reader_node, attr, t, "sc_reader", NULL,
                           reader_args, N_ARGS(reader_args)) );


  /****************************************************************************
   * Tap node                                                                 *
   ****************************************************************************
   * A tap node copies incoming packets and forwards the
   * original and the copy on different links. */
  struct sc_node* tap_node;

  /* By default a tap node copies every packet it sees; alternatively
   * it can be configured to copy only a subset of the incoming
   * packets. This can be done in one of two ways - via a BPF filter or
   * via a predicate. In this example we use a predicate which accepts
   * packets of length <= 100 bytes. */
  struct sc_pkt_predicate* predicate;
  TRY( sc_pkt_predicate_alloc(&predicate, sizeof(struct size_filter_state)) );
  struct size_filter_state* fs = predicate->pred_private;
  fs->max_size = 100;
  predicate->pred_test_fn = filter_by_size;

  /* To pass it into a node, the predicate must be converted to an sc_object */
  struct sc_object* predicate_obj = sc_pkt_predicate_to_object(predicate);

  struct sc_arg tap_args[] = {
    /* If set to 0, then do unreliable tapping: if the pool runs dry, then
     * copies will be lost.
     *
     * Set to 1 to wait until the pool has buffers in this case. Note that
     * this can backpressure the input link. When reading from a file this
     * is harmless, but if using a VI it can lead to packet drops. */
    SC_ARG_INT("reliable", 1),

    /* Copy at most n bytes of the duplicated frames, set to 0 to copy
     * entire frame */
    SC_ARG_INT("snap", 60),

    /* Only copy packets that match this predicate */
    SC_ARG_OBJ("predicate", predicate_obj),
  };

  TRY( sc_node_alloc_named(&tap_node, attr, t, "sc_tap", NULL,
                           tap_args, N_ARGS(tap_args)) );


  /****************************************************************************
   * Injector nodes                                                           *
   ****************************************************************************
   * An injector node takes a stream of packets and transmits it over a
   * Solarflare interface. */
  struct sc_node *inj1_node, *inj2_node;

  struct sc_arg inj1_args[] = {
    SC_ARG_STR("interface", argv[2]),
    SC_ARG_INT("csum_ip", 1),     /* Offload IP checksum calculation */
    SC_ARG_INT("csum_tcpudp", 1), /* Offload L4 checksum calculation */
  };

  TRY( sc_node_alloc_named(&inj1_node, attr, t, "sc_injector", NULL,
                           inj1_args, N_ARGS(inj1_args)) );

  struct sc_arg inj2_args[] = {
    SC_ARG_STR("interface", argv[3]),
  };

  TRY( sc_node_alloc_named(&inj2_node, attr, t, "sc_injector", NULL,
                           inj2_args, N_ARGS(inj2_args)) );


  /****************************************************************************
   * Exit node                                                                *
   ****************************************************************************
   * The job of an exit node is to exit the application on hitting an exit
   * condition.
   *
   * By default the exit condition is that all exit nodes in the process have
   * seen an end-of-stream signal on all their incoming links.
   *
   * Our topology has a single exit node with two incoming links (the two
   * injectors transmitting the original and copied packet stream), so the
   * application will exit once both injectors have transmitted all their
   * packets.
   *
   * Because the node's default behaviour is acceptable here, we do not need
   * to provide any arguments to this node.*/
  struct sc_node* exit_node;
  TRY( sc_node_alloc_named(&exit_node, attr, t, "sc_exit", NULL, NULL, 0) );


  /****************************************************************************
   * Topology setup                                                           *
   ****************************************************************************
   *
   *                                      |-------------|
   *                                 /--->| sc_injector |---\
   *  |-----------|     |--------|  /     |-------------|    \    |---------|
   *  | sc_reader |---->| sc_tap |--                          --->| sc_exit |
   *  |-----------|     |--------|  \     |-------------|    /    |---------|
   *                                 \--->| sc_injector |---/
   *                                      |-------------|
   */
  TRY( sc_node_add_link(reader_node, "", tap_node, "") );
  TRY( sc_node_add_link(tap_node, "", inj1_node, "") ); /* Original packets */
  TRY( sc_node_add_link(tap_node, "tap", inj2_node, "") ); /* Copied packets */
  TRY( sc_node_add_link(inj1_node, "", exit_node, "") );
  TRY( sc_node_add_link(inj2_node, "", exit_node, "") );

  sc_session_go(tg);
  while( 1 )
    sleep(100000);

  return 0;
}
