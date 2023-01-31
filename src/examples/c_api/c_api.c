/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/*
 * This file contains an example of how to use the SolarCapture C API to
 * embed SolarCapture in a C application.
 *
 * It captures all packets on an interface and passes them through an
 * sc_rate_monitor node, which monitors performance.
 *
 * The example creates two threads.  The first thread has a VI which
 * captures packets from the interface.  The second thread has a rate
 * monitor node that updates solar_capture_monitor output to say how
 * many packets were captured.
 */

#define SC_API_VER 1
#include <solar_capture.h>

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


#define TEST(x)                                                 \
  do {                                                          \
    if( ! (x) ) {                                               \
      fprintf(stderr, "ERROR: TEST(%s) failed\n", #x);          \
      fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__); \
      exit(1);                                                  \
    }                                                           \
  } while( 0 )


int main(int argc, char* argv[])
{
  if( argc != 2 ) {
    printf("Usage: %s <intf>\n", argv[0]);
    exit(1);
  }
  const char* intf = argv[1];

  /* Attributes are used to specify options.  Examples include specifing
   * the sizes of buffers and tuning options.  For a full list of available
   * attributes run "solar_capture_doc attr".
   *
   * The defaults can be changed by setting the SC_ATTR environment
   * variable, and can be overridden programmatically as shown below.
   */
  struct sc_attr* attr;
  TRY(sc_attr_alloc(&attr));

  /* A SolarCapture session binds together a set of threads and components
   * that are doing a particular job.
   */
  struct sc_session* tg;
  TRY(sc_session_alloc(&tg, attr));

  struct sc_thread* t1;
  TRY(sc_thread_alloc(&t1, attr, tg));
  struct sc_thread* t2;
  TRY(sc_thread_alloc(&t2, attr, tg));

  /* Set the number of packet buffers to be allocated for the VI.  These
   * buffers are used to receive packets from the network adapter.
   */
  int n_bufs = 8192;
  sc_attr_set_int(attr, "n_bufs_rx", n_bufs);
  sc_attr_set_int(attr, "n_bufs_rx_min", n_bufs);

  /* A VI is used to receive packets from the network adapter. */
  struct sc_vi* vi;
  TRY(sc_vi_alloc(&vi, attr, t1, intf));

  /* Specify which packets should be delivered to this VI.  An sc_stream
   * object describes the set of packets wanted.
   *
   * The 'all' stream captures all packets that arrive at the interface,
   * excluding those explicitly steered elsewhere.  (Using the 'all' stream
   * requires administrative privileges because it steals packets away from
   * the kernel stack).
   */
  struct sc_stream* stream;
  TRY(sc_stream_alloc(&stream, attr, tg));
  TRY(sc_stream_all(stream));
  TRY(sc_vi_add_stream(vi, stream));
  TRY(sc_stream_free(stream));

  /* SolarCapture nodes perform packet processing functions such as
   * monitoring, packet modification, writing to disk, I/O etc.  When
   * allocating nodes you can specify node-specific arguments, which may be
   * required or optional.
   *
   * The 'sc_rate_monitor' node measures the packet rate and bandwidth for
   * packets passing through it, and exports that information via
   * solar_capture_monitor.  The 'period' argument gives the sampling
   * period in seconds.  The 'alpha' argument controls smoothing, and must
   * be in the range (0,1].  Values close to 1 give more weight to recent
   * samples, while values close to zero give more weight to previous
   * samples and so provide a greater level of smoothing.
   */
  struct sc_arg args[] = {
    SC_ARG_DBL("alpha",  0.5),
    SC_ARG_DBL("period", 0.1),
  };
  struct sc_node* rate_mon;
  TRY(sc_node_alloc_named(&rate_mon, attr, t2, "sc_rate_monitor", NULL,
                          args, sizeof(args) / sizeof(args[0])));

  /* Connect the VI to the rate monitor. */
  TRY(sc_vi_set_recv_node(vi, rate_mon, NULL));

  /* sc_session_go() starts the threads, and so starts packet handling. */
  sc_session_go(tg);
  while( 1 )
    sleep(100000);

  return 0;
}
