/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/* Sample code of a predicate function that stores stats on a timer.
 * Application will play a pcap file as fast as it can out of one
 * interface; and copy some of those packets out of a second interface
 */

/* gcc pred_stats.c -I. -lsolarcapture1 -o pred_stats */

#define SC_API_VER 1
/* NOTE: API version 5 is needed to give a friendly name to the callback */

#include <solar_capture.h>
#include <solar_capture_ext.h>

#include <solar_capture/predicate.h>
#include <solar_capture/event.h>
#include <solar_capture/time.h>

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

/* Build the struct pred_stats type */
#define SC_TYPE_TEMPLATE "pred_stats_tmpl.h"
#define SC_DECLARE_TYPES pred_stats_declare
#include <solar_capture/declare_types.h>

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
 * This example has two fields - the timer object and the statistics.
 *
 * It is valid to modify the state at runtime, from either within
 * the predicate function or elsewhere.
 */
struct predicate_state {
  struct sc_callback* timer;
  struct pred_stats* pred_filt_stats;
};


/* This is the actual predicate function - the custom code that will run
 * for each packet.  sc_tap uses the return value to decide whether to copy a
 * packet or not.  We are going to act/decide based on number of packets seen
 * since the last timer tick - and also store some statistics.
 */
int custom_predicate(struct sc_pkt_predicate* pred, struct sc_packet* pkt)
{
  struct predicate_state* state;
  /* We're ignoring the packet we are being passed - most real predicate
   * functions would want to look at the packet meta-data and contents,
   * to make their decision.
   */
  (void) pkt;
  /* Get our private data */
  state = (struct predicate_state*) pred->pred_private;
  /* This statistic is visible in "solar_capture_monitor dump" output,
   * Although as it is cleared every second, probably isn't very useful.
   */
  state->pred_filt_stats->subtotal_packets ++;

  /* If we've never set up the timer; do so now - we could have done this in main;
   * but this way the first tick is 1s after the first packet, rather than 1s
   * after the application starts.
   */
  if( ! sc_callback_is_active(state->timer) )
    sc_timer_expire_after_ns (state->timer, 1000000000 );

  /* TODO: Insert your own code here to decide what to copy
   * This sample code will simply every other packet.
   * (resetting each second)
   */
  return (state->pred_filt_stats->subtotal_packets & 1) == 0;
}


/* This is the callback function that will be executed (roughly) once every
 *  second.  We get passed in the private data we request - in this case,
 * the same state as the predicate function.
 */
void timer_callback(struct sc_callback* cb, void* event_info)
{
  (void) event_info; /* unused by timers */

  struct predicate_state* state = (struct predicate_state*) cb->cb_private;

  /* Save the running total into the per-second total, and clear it.
   * TODO: Store whatever additional statistics you are interested in.
   * But remember - this is on a critical thread; so don't spend too many
   * CPU cycles here.
   */
  state->pred_filt_stats->packets_last_second =
      state->pred_filt_stats->subtotal_packets;
  /* Note: Clearing that to 0 to ensure we copy the 1st packet each second */
  state->pred_filt_stats->subtotal_packets = 0;

  /* Schedule the next callback, in 1s time - timers are one-shot, so if
   * you need it to tick repeatedly, request a new expiry.
   */
  sc_timer_expire_after_ns (cb, 1000000000);
}

int main(int argc, char* argv[])
{
  if( argc != 4 ) {
    printf("Simple test app to send all packets to one interface\n");
    printf("and some to another; as fast as it can.\n");
    printf("With statistics (see: solar_capture_monitor dump)\n");
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
  /* Note that the sc_reader node will read packets as fast as it can.
   * In order to moderate playback to rate, you would need to insert a
   * pacer node.  This is omitted here, to make the example simpler.
   */

  /* Most nodes take one or more arguments. For the reader we
   * specify where to read packets from, and what to do on reaching
   * end-of-file.
   */
  struct sc_arg reader_args[] = {
    SC_ARG_STR("filename", argv[1]),

    /* signal_eof: on reaching end-of-file, send an end-of-stream
     * signal to indicate to downstream nodes that no more packets
     * will be sent.
     * Turn this off, if you'd like to check the stats before exit.
     */
    SC_ARG_INT("signal_eof", 1),
  };

  TRY( sc_node_alloc_named(&reader_node, attr, t, "sc_reader", NULL,
                           reader_args, N_ARGS(reader_args)) );


  /****************************************************************************
   * Tap node                                                                 *
   ****************************************************************************
   * A tap node copies incoming packets and forwards the
   * original and the copy on different links.
   */
  struct sc_node* tap_node;

  /* By default a tap node copies every packet it sees; alternatively
   * it can be configured to copy only a subset of the incoming
   * packets. This can be done in one of two ways - via a BPF filter or
   * via a predicate. In this example we use a predicate to demonstrate
   * inserting your own code into the node graph, without needing a full
   * custom node.
   */
  struct sc_pkt_predicate* predicate;
  TRY( sc_pkt_predicate_alloc(&predicate, sizeof(struct predicate_state)) );
  struct predicate_state* fs = predicate->pred_private;

  /* Construct a timer callback object; wrapping our function and the data */
  struct sc_callback* timer;
  TRY( sc_callback_alloc (&timer, attr, t) );
#if SC_API_VER >= 5
  TRY( sc_callback_set_description (timer, "Stats timer callback") );
#endif
  timer->cb_handler_fn = timer_callback;
  timer->cb_private = (void*) fs;

  predicate->pred_test_fn = custom_predicate;

  fs->timer = timer;

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

  /* register statistics - so solar_capture_monitor can understand it */
  pred_stats_declare(sc_thread_get_session(sc_node_get_thread(tap_node)));
  /* And actually expose the particular block */
  TRY( sc_node_export_state(
         tap_node, "pred_stats", sizeof(struct pred_stats),
         &(fs->pred_filt_stats)) );

  /****************************************************************************
   * Injector nodes                                                           *
   ****************************************************************************
   * An injector node takes a stream of packets and transmits it over a
   * Solarflare interface.
   * Sample application uses two; one for each side of the tap node.
   */
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
