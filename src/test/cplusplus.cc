/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

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
  if( argc != 3 ) {
    printf("Usage: %s <intf> <capture-file>\n", argv[0]);
    exit(1);
  }
  const char* intf = argv[1];
  const char* filename = argv[2];

  struct sc_attr* attr;
  TRY(sc_attr_alloc(&attr));

  struct sc_session* tg;
  TRY(sc_session_alloc(&tg, attr));

  struct sc_thread* t1;
  TRY(sc_thread_alloc(&t1, attr, tg));
  struct sc_thread* t2;
  TRY(sc_thread_alloc(&t2, attr, tg));

  int n_bufs = 8192;
  sc_attr_set_int(attr, "n_bufs_rx", n_bufs);
  sc_attr_set_int(attr, "n_bufs_rx_min", n_bufs);

  struct sc_vi* vi;
  TRY(sc_vi_alloc(&vi, attr, t1, intf));

  struct sc_stream* stream;
  TRY(sc_stream_alloc(&stream, attr, tg));
  TRY(sc_stream_all(stream));
  TRY(sc_vi_add_stream(vi, stream));

  const struct sc_node_factory* writer_factory;

  struct sc_node* writer;
  TRY(sc_node_factory_lookup(&writer_factory, tg, "sc_writer", NULL));

  struct sc_arg args[3];
  args[0].name = "filename";
  args[0].type = SC_PARAM_STR;
  args[0].val.str = filename;
  args[1].name = "format";
  args[1].type = SC_PARAM_STR;
  args[1].val.str = "pcap-ns";
  args[2].name = "snap";
  args[2].type = SC_PARAM_INT;
  args[2].val.i = 60;
  TRY(sc_node_alloc(&writer, attr, t2, writer_factory,
                    args, sizeof(args) / sizeof(args[0])));

  struct sc_mailbox* sender;
  TRY(sc_mailbox_alloc(&sender, attr, t1));
  struct sc_mailbox* receiver;
  TRY(sc_mailbox_alloc(&receiver, attr, t2));
  TRY(sc_mailbox_connect(sender, receiver));

  TRY(sc_vi_set_recv_node(vi, sc_mailbox_get_send_node(sender), NULL));
  TRY(sc_mailbox_set_recv(receiver, writer, NULL));

  sc_session_go(tg);
  while( 1 )
    sleep(100000);

  return 0;
}
