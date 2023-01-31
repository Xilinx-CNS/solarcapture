/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#define SC_API_VER 5
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

/**********************************************************************/

struct deliver_state {
  struct sc_packet_list*     dest;
  const struct sc_node_link* next_hop;
};


static void deliver_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct deliver_state* st = node->nd_private;
  sc_packet_list_append_list(st->dest, pl);
}


static int deliver_prep(struct sc_node* node,
                         const struct sc_node_link*const* links, int n_links)
{
  struct deliver_state* st = node->nd_private;
  st->next_hop = sc_node_prep_get_link_or_free(node, "");
  return sc_node_prep_check_links(node);
}


static int deliver_init(struct sc_node* node, const struct sc_attr* attr,
                        const struct sc_node_factory* factory)
{
  struct deliver_state* st = calloc(1, sizeof(*st));
  node->nd_private = st;

  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_pkts_fn = deliver_pkts;
    nt->nt_prep_fn = deliver_prep;
  }
  node->nd_type = nt;

  return 0;
}


static const struct sc_node_factory deliver_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "deliver",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = deliver_init,
};


static void deliver_set_dest(struct sc_node* node, struct sc_packet_list* dest)
{
  assert(!strcmp(node->nd_type->nt_name, "deliver"));
  struct deliver_state* st = node->nd_private;
  st->dest = dest;
}


static void deliver_forward(struct sc_node* node, struct sc_packet* pkt)
{
  assert(!strcmp(node->nd_type->nt_name, "deliver"));
  struct deliver_state* st = node->nd_private;
  sc_forward2(st->next_hop, pkt);
}

/**********************************************************************/

int main(int argc, char* argv[])
{
  if( argc != 2 ) {
    printf("Usage: %s <intf>\n", argv[0]);
    exit(1);
  }
  const char* intf = argv[1];

  struct sc_attr* attr;
  TRY(sc_attr_alloc(&attr));

  struct sc_attr* um_attr = sc_attr_dup(attr);
  TRY(sc_attr_set_int(um_attr, "managed", 0));

  struct sc_session* scs;
  TRY(sc_session_alloc(&scs, attr));

  /* Create a managed thread. */
  struct sc_thread* thrd;
  TRY(sc_thread_alloc(&thrd, attr, scs));

  /* An unmanaged thread.  This allows us to create SolarCapture objects
   * that will be used in a thread that we control.
   */
  struct sc_thread* um_thrd;
  TRY(sc_thread_alloc(&um_thrd, um_attr, scs));

  /* Capture all packets on [intf]. */
  struct sc_vi* vi;
  TRY(sc_vi_alloc(&vi, attr, thrd, intf));
  struct sc_stream* stream;
  TRY(sc_stream_alloc(&stream, attr, scs));
  TRY(sc_stream_set_str(stream, "all"));
  TRY(sc_vi_add_stream(vi, stream));

  /* Arrange for packets to be delivered into [deliver_list]. */
  struct sc_packet_list deliver_list;
  sc_packet_list_init(&deliver_list);

  struct sc_node* deliver_node;
  TRY(sc_node_alloc(&deliver_node, attr, um_thrd,
                    &deliver_sc_node_factory, NULL, 0));
  deliver_set_dest(deliver_node, &deliver_list);

  TRY(sc_vi_set_recv_node(vi, deliver_node, NULL));
  /* NB. We've not set an outgoing link for [deliver_node], so packets
   * forwarded from [deliver_node] will be freed.
   */

  /* Start managed threads. */
  sc_session_go(scs);

  /* Unmanaged threads should have their timers polled at start of day. */
  sc_thread_poll_timers(um_thrd);

  while( 1 ) {
    /* Poll the unmanaged thread.  This ensures that packets flow into
     * [deliver_node], and back to the managed thread after sc_forward().
     */
    sc_thread_poll(um_thrd);
    if( ! sc_packet_list_is_empty(&deliver_list) ) {
      struct sc_packet* next;
      struct sc_packet* pkt;
      for( next = deliver_list.head;
           (pkt = next) && ((next = next->next), 1); ) {
        printf("%lld.%09d\n", (unsigned long long) pkt->ts_sec, pkt->ts_nsec);
        deliver_forward(deliver_node, pkt);
      }
      sc_packet_list_init(&deliver_list);
    }
  }

  return 0;
}
