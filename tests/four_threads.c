/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#include <solar_capture/setup.h>
#include <solar_capture/pcap_handler.h>
#include <solar_capture/counter_handler.h>
#include <solar_capture/debug.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <assert.h>


#define SNAPLEN 60


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
  if( argc != 5 ) {
    printf("Usage: %s <intf0> <intf1> <microseconds|nanoseconds>"
           " <capture-file>\n",
           argv[0]);
    exit(1);
  }

  struct sc_thread* t0;
  TRY(sc_thread_alloc("", &t0));
  struct sc_thread* t1;
  TRY(sc_thread_alloc("", &t1));
  struct sc_thread* t2;
  TRY(sc_thread_alloc("", &t2));
  struct sc_thread* t3;
  TRY(sc_thread_alloc("", &t3));

  char* intf0 = argv[1];
  char* intf1 = argv[2];
  char* timestamp_type = argv[3];
  char* filename = argv[4];

  struct sc_pd* pd0;
  TRY(sc_pd_alloc(intf0, 0, &pd0));

  struct sc_pd* pd1;
  TRY(sc_pd_alloc(intf1, 0, &pd1));

  int n_bufs = 2500;
  int len = (1 << 11) * n_bufs;

  void* addr0;
  TRY(posix_memalign(&addr0, 1 << 21, len));
  bzero(addr0, len);
  struct sc_memreg* mr0;
  TRY(sc_memreg_alloc(t0, pd0, addr0, len, &mr0));

  void* addr1;
  TRY(posix_memalign(&addr1, 1 << 21, len));
  bzero(addr1, len);
  struct sc_memreg* mr1;
  TRY(sc_memreg_alloc(t1, pd1, addr1, len, &mr1));

  /* t0(vi0 -> fwd0 -> s0) -> t2(r0 -> counter0 -> s1) -> t3(r1 ->
     pcap -> s2) -> t0(r2 ->vi0) */

  /* t1(vi1 -> fwd1 -> s3) -> t2(r3 -> counter1 -> s4) -> t3(r4 ->
     pcap -> s5) -> t1(r5 ->vi1) */

  struct sc_mbox_node* s0;
  TRY(sc_mbox_node_alloc(t0, t2, "s0", &s0));
  struct sc_mbox_node* s1;
  TRY(sc_mbox_node_alloc(t2, t3, "s1", &s1));
  struct sc_mbox_node* s2;
  TRY(sc_mbox_node_alloc(t3, t0, "s2", &s2));
  struct sc_mbox_node* s3;
  TRY(sc_mbox_node_alloc(t1, t2, "s3", &s3));
  struct sc_mbox_node* s4;
  TRY(sc_mbox_node_alloc(t2, t3, "s4", &s4));
  struct sc_mbox_node* s5;
  TRY(sc_mbox_node_alloc(t3, t1, "s5", &s5));

  struct sc_mbox_node* r0;
  TRY(sc_mbox_node_alloc(t2, t0, "r0", &r0));
  struct sc_mbox_node* r1;
  TRY(sc_mbox_node_alloc(t3, t2, "r1", &r1));
  struct sc_mbox_node* r2;
  TRY(sc_mbox_node_alloc(t0, t3, "r2", &r2));
  struct sc_mbox_node* r3;
  TRY(sc_mbox_node_alloc(t2, t1, "r3", &r3));
  struct sc_mbox_node* r4;
  TRY(sc_mbox_node_alloc(t3, t2, "r4", &r4));
  struct sc_mbox_node* r5;
  TRY(sc_mbox_node_alloc(t1, t3, "r5", &r5));

  sc_mbox_node_connect(s0, r0);
  sc_mbox_node_connect(s1, r1);
  sc_mbox_node_connect(s2, r2);
  sc_mbox_node_connect(s3, r3);
  sc_mbox_node_connect(s4, r4);
  sc_mbox_node_connect(s5, r5);

  struct sc_node_impl* fwd0;
  TRY(sc_node_alloc(t0, &sc_counter_handler, "fwd0", &fwd0));
  TRY(sc_node_add_link(fwd0, "sender0", &s0->node));
  TRY(sc_node_finalise(fwd0, NULL, 0));

  struct sc_node_impl* fwd1;
  TRY(sc_node_alloc(t1, &sc_counter_handler, "fwd1", &fwd1));
  TRY(sc_node_add_link(fwd1, "sender3", &s3->node));
  TRY(sc_node_finalise(fwd1, NULL, 0));

  struct sc_node_impl* counter0;
  TRY(sc_node_alloc(t2, &sc_counter_handler, "counter0", &counter0));
  TRY(sc_node_add_link(counter0, "sender1", &s1->node));
  TRY(sc_node_finalise(counter0, NULL, 0));

  struct sc_node_impl* counter1;
  TRY(sc_node_alloc(t2, &sc_counter_handler, "counter1", &counter1));
  TRY(sc_node_add_link(counter1, "sender4", &s4->node));
  TRY(sc_node_finalise(counter1, NULL, 0));

  struct sc_node_impl* pcap;
  TRY(sc_node_alloc(t3, &sc_pcap_handler, "pcap", &pcap));
  struct sc_kv params[] = {
    { .key = SC_PCAP_HANDLER_TIMESTAMP_TYPE,
      .val.str = timestamp_type,
    },
    { .key = SC_PCAP_HANDLER_FILENAME,
      .val.str = filename,
    },
    { .key = SC_PCAP_HANDLER_SNAPLEN,
      .val.i = 60,
    },
  };
  TRY(sc_node_finalise(pcap, params, 3));

  sc_mbox_node_set_recv(r0, counter0);
  sc_mbox_node_set_recv(r1, pcap);
  sc_mbox_node_set_recv(r3, counter1);
  sc_mbox_node_set_recv(r4, pcap);

  struct sc_node_impl* r2_refill;
  TRY(sc_node_alloc(t0, &sc_mbox_node_local_refill_hdlr_type, "r2_refill",
                    &r2_refill));
  sc_mbox_node_set_recv(r2, r2_refill);
  TRY(sc_node_finalise(r2_refill, NULL, 0));

  struct sc_node_impl* r5_refill;
  TRY(sc_node_alloc(t1, &sc_mbox_node_local_refill_hdlr_type, "r5_refill",
                    &r5_refill));
  sc_mbox_node_set_recv(r5, r5_refill);
  TRY(sc_node_finalise(r5_refill, NULL, 0));

  struct sc_vi* vi0;
  TRY(sc_vi_alloc_from_pd(t0, pd0, 32, 64, 4096, 2048, n_bufs, fwd0, "", &vi0));
  TRY(sc_filter_all(vi0, NULL));

  struct sc_vi* vi1;
  TRY(sc_vi_alloc_from_pd(t1, pd1, 32, 64, 4096, 2048, n_bufs, fwd1, "", &vi1));
  TRY(sc_filter_all(vi1, NULL));

  sc_go();
  while( 1 )
    sleep(100000);

  return 0;
}
