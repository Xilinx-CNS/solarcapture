/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#include <solar_capture.h>
#include <solar_capture_nodes.h>

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
  if( argc != 3 ) {
    printf("Usage: %s <intf> <capture-file>\n", argv[0]);
    exit(1);
  }
  const char* intf = argv[1];
  const char* filename = argv[2];

  TRY(sc_initialise());

  struct sc_attr* attr;
  TRY(sc_attr_alloc(&attr));

  struct sc_thread* t1;
  TRY(sc_thread_alloc(&t1, attr));
  struct sc_thread* t2;
  TRY(sc_thread_alloc(&t2, attr));

  struct sc_netif* netif;
  TRY(sc_netif_alloc(&netif, attr, intf));

  int n_bufs = 2500;
  sc_attr_set_int(attr, "n_bufs", n_bufs);

  /* t1(vi -> sender) -> t2(receiver -> pcap) */

  struct sc_mbox_node* sender;
  TRY(sc_mbox_node_alloc(&sender, attr, t1, t2));
  struct sc_mbox_node* receiver;
  TRY(sc_mbox_node_alloc(&receiver, attr, t2, t1));
  sc_mbox_node_connect(sender, receiver);

  struct sc_node* pcap;
  TRY(sc_node_alloc(&pcap, attr, t2, &sc_pcap_node));
  struct sc_arg args[] = {
    SC_ARG_STR(SC_PCAP_NODE_TIMESTAMP_TYPE, "micro"),
    SC_ARG_STR(SC_PCAP_NODE_FILENAME, filename),
    SC_ARG_INT(SC_PCAP_NODE_SNAP, 60),
  };
  TRY(sc_node_finalise(pcap, args, sizeof(args) / sizeof(args[0])));

  sc_mbox_node_set_recv(receiver, pcap);

  struct sc_node* refill;
  TRY(sc_node_alloc(&refill, attr, t1, &sc_refill_node));
  sc_mbox_node_set_recv(sender, refill);
  TRY(sc_node_finalise(refill, NULL, 0));

  struct sc_vi* vi;
  TRY(sc_vi_alloc(&vi, attr, t1, netif));
  TRY(sc_vi_set_recv_node(vi, sc_mbox_node_get_node(sender)));

  struct sc_stream* stream;
  TRY(sc_stream_alloc(&stream, attr));
  TRY(sc_stream_all(stream));
  TRY(sc_vi_add_stream(vi, stream));

  sc_go();
  while( 1 )
    sleep(100000);

  return 0;
}
