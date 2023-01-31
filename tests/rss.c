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
  if( argc != 4 ) {
    printf("Usage: %s <intf> <microseconds|nanoseconds> <capture-file>\n",
           argv[0]);
    exit(1);
  }

  struct sc_thread* t0;
  TRY(sc_thread_alloc("", &t0));
  struct sc_thread* t1;
  TRY(sc_thread_alloc("", &t1));

  char* intf = argv[1];
  char* timestamp_type = argv[2];
  char* filename = argv[3];

  struct sc_pd* pd;
  TRY(sc_pd_alloc(intf, 0, &pd));

  int n_bufs = 5000;
  int len = (1 << 11) * n_bufs;
  void* addr;
  TRY(posix_memalign(&addr, 1 << 21, len));
  bzero(addr, len);
  struct sc_memreg* mr;
  TRY(sc_memreg_alloc(t0, pd, addr, len, &mr));

  /* t0(vi0 -> pcap0) */
  /* t1(vi1 -> pcap1) */

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
  struct sc_node_impl* pcap0;
  TRY(sc_node_alloc(t0, &sc_pcap_handler, "", &pcap0));
  TRY(sc_node_finalise(pcap0, params, 3));

  struct sc_node_impl* pcap1;
  TRY(sc_node_alloc(t1, &sc_pcap_handler, "", &pcap1));
  TRY(sc_node_finalise(pcap1, params, 3));

  struct sc_vi_set* set;
  TRY(sc_vi_set_alloc(pd, 2, &set));
  TRY(sc_filter_all(NULL, set));

  struct sc_vi* vi0;
  TRY(sc_vi_alloc_from_set(t0, set, 32, 64, 4096, 2048, n_bufs / 2, pcap0, "",
                           &vi0));
  struct sc_vi* vi1;
  TRY(sc_vi_alloc_from_set(t1, set, 32, 64, 4096, 2048, n_bufs / 2, pcap1, "",
                           &vi1));

  sc_go();
  while( 1 )
    sleep(100000);

  return 0;
}
