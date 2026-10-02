/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2026, Advanced Micro Devices, Inc.
*/
/* cluster_client
 *
 * ON-17615: minimal reference client for solar_clusterd, part of
 * SolarCapture (see docs/solar_cluster.md, and solar_clusterd(8)). It was
 * removed from Onload as of Onload 9.2.0 -- only older Onload releases
 * bundle their own copy.
 *
 * solar_clusterd pre-allocates one or more named "clusters" -- each a
 * protection domain + vi_set on a given interface, with capture filters
 * already installed from its config file (see solar_clusterd/example.conf).
 * Client processes attach to a channel within a named cluster and receive
 * packets matching those pre-installed filters, without needing their own
 * filter/PD setup and without contending with other clients for the same
 * resources.
 *
 * The client-side handshake is entirely transparent inside libciul:
 *
 *   ef_pd_alloc_by_name(&pd, dh, "[idx@]<cluster-name>", flags)
 *     - connects to solar_clusterd over its unix-domain socket
 *       (see $EF_VI_CLUSTER_SOCKET / DEFAULT_CLUSTERD_DIR),
 *     - does a version handshake and requests channel <idx> (or any
 *       channel, if no "idx@" prefix) of the named cluster,
 *     - receives back a driver fd (via SCM_RIGHTS) plus the cluster's
 *       pd/vi_set resource ids, and stashes them in pd->pd_cluster_*.
 *     - if no such cluster exists (e.g. solar_clusterd isn't running, or
 *       the name doesn't match a configured cluster), it falls back to
 *       treating the name as a plain interface and allocates a private PD.
 *
 *   ef_vi_alloc_from_pd(&vi, dh, &pd, dh, ...)
 *     - notices pd->pd_cluster_sock is set and transparently allocates the
 *       VI from the cluster's existing vi_set/channel instead of a new one.
 *
 * This client installs no filters of its own -- solar_clusterd's config
 * already did that for the whole cluster.
 *
 * Usage:
 *   cluster_client [-d] [-n num-packets] [idx@]<cluster-name>
 */

#include <etherfabric/vi.h>
#include <etherfabric/pd.h>
#include <etherfabric/memreg.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <time.h>


#define TRY(x)                                                        \
  do {                                                                 \
    int __rc = (x);                                                   \
    if( __rc < 0 ) {                                                  \
      fprintf(stderr, "ERROR: '%s' failed at %s:%d rc=%d errno=%d (%s)\n", \
              #x, __FILE__, __LINE__, __rc, errno, strerror(errno));  \
      exit(1);                                                        \
    }                                                                  \
  } while( 0 )

#define TEST(x)                                                        \
  do {                                                                 \
    if( ! (x) ) {                                                     \
      fprintf(stderr, "ERROR: '%s' failed at %s:%d\n", #x, __FILE__, __LINE__); \
      exit(1);                                                        \
    }                                                                  \
  } while( 0 )


/* Buffers are sized so RX DMA (max ef_vi_receive_buffer_len() bytes) never
 * crosses a 4K boundary. */
#define PKT_BUF_SIZE   2048
#define N_PKT_BUFS     512
#define RX_DMA_OFF     ROUND_UP(sizeof(struct pkt_buf), EF_VI_DMA_ALIGN)
#define ROUND_UP(p, align)  (((p) + (align) - 1u) & ~((align) - 1u))
#define REFILL_BATCH   16
#define HUGE_PAGE_SIZE (2ll * 1024 * 1024)


struct pkt_buf {
  ef_addr          dma_addr;
  void*            rx_ptr;
  int              id;
  struct pkt_buf*  next;
};

static ef_driver_handle  dh;
static ef_pd             pd;
static ef_vi             vi;
static ef_memreg         memreg;

static void*             pkt_bufs;
static struct pkt_buf*   free_pkt_bufs;
static int               free_pkt_bufs_n;

static uint64_t          n_rx_pkts;
static uint64_t          n_rx_bytes;

static int                cfg_hexdump;
static int64_t             cfg_exit_pkts = -1;
static volatile sig_atomic_t stop_requested;


static void on_signal(int signum)
{
  stop_requested = 1;
}


static inline struct pkt_buf* pkt_buf_from_id(int id)
{
  return (void*) ((char*) pkt_bufs + (size_t) id * PKT_BUF_SIZE);
}


static void pkt_buf_free(struct pkt_buf* pkt_buf)
{
  pkt_buf->next = free_pkt_bufs;
  free_pkt_bufs = pkt_buf;
  ++free_pkt_bufs_n;
}


static void hexdump(const void* pv, int len)
{
  const unsigned char* p = pv;
  int i;
  for( i = 0; i < len; ++i ) {
    printf("%02x%s", p[i], (i & 15) == 15 ? "\n" : " ");
  }
  if( (len & 15) != 0 )
    printf("\n");
}


static void refill_rx_ring(void)
{
  int i;
  if( ef_vi_receive_space(&vi) < REFILL_BATCH ||
      free_pkt_bufs_n < REFILL_BATCH )
    return;
  for( i = 0; i < REFILL_BATCH; ++i ) {
    struct pkt_buf* pkt_buf = free_pkt_bufs;
    free_pkt_bufs = free_pkt_bufs->next;
    --free_pkt_bufs_n;
    ef_vi_receive_init(&vi, pkt_buf->dma_addr + RX_DMA_OFF, pkt_buf->id);
  }
  ef_vi_receive_push(&vi);
}


static void handle_rx(int pkt_buf_i, int len)
{
  struct pkt_buf* pkt_buf = pkt_buf_from_id(pkt_buf_i);

  ++n_rx_pkts;
  n_rx_bytes += len;
  if( cfg_hexdump )
    hexdump(pkt_buf->rx_ptr, len);

  pkt_buf_free(pkt_buf);
}


static void poll_evq(void)
{
  ef_event evs[16];
  int i, n_ev = ef_eventq_poll(&vi, evs, sizeof(evs) / sizeof(evs[0]));
  int rx_prefix_len = ef_vi_receive_prefix_len(&vi);

  for( i = 0; i < n_ev; ++i ) {
    switch( EF_EVENT_TYPE(evs[i]) ) {
    case EF_EVENT_TYPE_RX:
      handle_rx(EF_EVENT_RX_RQ_ID(evs[i]),
                EF_EVENT_RX_BYTES(evs[i]) - rx_prefix_len);
      break;
    case EF_EVENT_TYPE_RX_DISCARD:
      fprintf(stderr, "WARNING: rx discard type=%d\n",
              EF_EVENT_RX_DISCARD_TYPE(evs[i]));
      handle_rx(EF_EVENT_RX_DISCARD_RQ_ID(evs[i]),
                EF_EVENT_RX_DISCARD_BYTES(evs[i]) - rx_prefix_len);
      break;
    case EF_EVENT_TYPE_RESET:
      fprintf(stderr, "ERROR: NIC was reset; VI is no longer valid\n");
      exit(2);
    default:
      fprintf(stderr, "WARNING: unexpected event type=%d\n",
              (int) EF_EVENT_TYPE(evs[i]));
      break;
    }
  }
}


static void print_stats(struct timespec* prev, uint64_t* prev_pkts,
                        uint64_t* prev_bytes)
{
  struct timespec now;
  int64_t ms;

  clock_gettime(CLOCK_MONOTONIC, &now);
  ms = (now.tv_sec - prev->tv_sec) * 1000 +
       (now.tv_nsec - prev->tv_nsec) / 1000000;
  if( ms < 1000 )
    return;

  printf("pkt-rate=%-10"PRId64" bandwidth(Mbps)=%-10"PRId64" total-pkts=%"PRIu64"\n",
         (int64_t) (n_rx_pkts - *prev_pkts) * 1000 / ms,
         (int64_t) (n_rx_bytes - *prev_bytes) * 8 / 1000 / ms,
         n_rx_pkts);
  fflush(stdout);

  *prev = now;
  *prev_pkts = n_rx_pkts;
  *prev_bytes = n_rx_bytes;
}


static __attribute__((noreturn)) void usage(void)
{
  fprintf(stderr,
          "usage: cluster_client [-d] [-n num-packets] [idx@]<cluster-name>\n"
          "\n"
          "  <cluster-name> must match a '[Cluster <name>]' section in the\n"
          "  config file that a running solar_clusterd instance was started\n"
          "  with. Prefix with 'idx@' to request a specific channel, e.g.\n"
          "  '0@ClusterA'; otherwise any free channel is used.\n"
          "\n"
          "  -d           hexdump received packets\n"
          "  -n <num>     exit after receiving <num> packets\n");
  exit(1);
}


int main(int argc, char* argv[])
{
  const char* cluster_name;
  int c, i;
  struct timespec stats_prev;
  uint64_t stats_prev_pkts = 0, stats_prev_bytes = 0;

  while( (c = getopt(argc, argv, "dn:")) != -1 )
    switch( c ) {
    case 'd':
      cfg_hexdump = 1;
      break;
    case 'n':
      cfg_exit_pkts = atoll(optarg);
      break;
    default:
      usage();
    }
  argc -= optind;
  argv += optind;
  if( argc != 1 )
    usage();
  cluster_name = argv[0];

  signal(SIGINT, on_signal);
  signal(SIGTERM, on_signal);

  TRY(ef_driver_open(&dh));
  TRY(ef_pd_alloc_by_name(&pd, dh, cluster_name, EF_PD_DEFAULT));

  if( pd.pd_cluster_sock != -1 )
    printf("Joined cluster '%s' via solar_clusterd (interface=%s)\n",
           cluster_name, pd.pd_intf_name);
  else
    printf("No such cluster (or solar_clusterd not running); allocated "
           "'%s' as a plain interface instead\n", pd.pd_intf_name);

  /* When pd was allocated from a cluster, this transparently allocates
   * the VI from the cluster's pre-existing vi_set/channel rather than
   * a fresh one -- see ef_vi_alloc_from_pd() in src/lib/ciul/pt_endpoint.c.
   */
  TRY(ef_vi_alloc_from_pd(&vi, dh, &pd, dh, -1, -1, 0, NULL, -1,
                          EF_VI_FLAGS_DEFAULT));

  TEST(posix_memalign(&pkt_bufs, HUGE_PAGE_SIZE,
                      ROUND_UP(N_PKT_BUFS * PKT_BUF_SIZE, HUGE_PAGE_SIZE)) == 0);
  TRY(ef_memreg_alloc(&memreg, dh, &pd, dh, pkt_bufs,
                      ROUND_UP(N_PKT_BUFS * PKT_BUF_SIZE, HUGE_PAGE_SIZE)));
  for( i = 0; i < N_PKT_BUFS; ++i ) {
    struct pkt_buf* pkt_buf = pkt_buf_from_id(i);
    pkt_buf->id = i;
    pkt_buf->dma_addr = ef_memreg_dma_addr(&memreg, i * PKT_BUF_SIZE);
    pkt_buf->rx_ptr = (char*) pkt_buf + RX_DMA_OFF + ef_vi_receive_prefix_len(&vi);
    pkt_buf_free(pkt_buf);
  }
  while( free_pkt_bufs_n >= REFILL_BATCH )
    refill_rx_ring();

  printf("cluster_client ready; waiting for packets (Ctrl-C to stop)\n");
  clock_gettime(CLOCK_MONOTONIC, &stats_prev);

  while( ! stop_requested &&
        (cfg_exit_pkts < 0 || (int64_t) n_rx_pkts < cfg_exit_pkts) ) {
    poll_evq();
    refill_rx_ring();
    print_stats(&stats_prev, &stats_prev_pkts, &stats_prev_bytes);
  }

  printf("Received %"PRIu64" packets (%"PRIu64" bytes); shutting down\n",
         n_rx_pkts, n_rx_bytes);

  ef_memreg_free(&memreg, dh);
  ef_vi_free(&vi, dh);
  /* Frees pd->pd_cluster_* state (closing the solar_clusterd connection)
   * when pd was allocated from a cluster -- see ef_pd_free() in
   * src/lib/ciul/pd.c. */
  ef_pd_free(&pd, dh);
  ef_driver_close(dh);
  return 0;
}
