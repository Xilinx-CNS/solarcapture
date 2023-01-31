/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <pthread.h>


static void usage_msg(FILE* strm)
{
  fprintf(strm, "\n");
  fprintf(strm, "usage:\n");
  fprintf(strm, "  fanout [options] INTERFACE FANOUT_TYPE NUM_WORKERS "
          "[FANOUT_ID]\n");
  fprintf(strm, "\n");
  fprintf(strm, "FANOUT_TYPE:\n");
  fprintf(strm, "  none hash lb cpu rollover rnd qm\n");
  fprintf(strm, "\n");
  fprintf(strm, "options:\n");
  fprintf(strm, "\n");
}


static void usage_err(void)
{
  usage_msg(stderr);
  exit(1);
}


#ifndef PACKET_FANOUT
# define PACKET_FANOUT                  18
#endif
#ifndef PACKET_FANOUT_HASH
# define PACKET_FANOUT_HASH             0
# define PACKET_FANOUT_LB               1
# define PACKET_FANOUT_CPU              2
# define PACKET_FANOUT_ROLLOVER         3
# define PACKET_FANOUT_RND              4
# define PACKET_FANOUT_QM               5
# define PACKET_FANOUT_FLAG_ROLLOVER    0x1000
# define PACKET_FANOUT_FLAG_DEFRAG      0x8000
#endif


struct config {
  const char*     device_name;
  int             fanout_id;
  int             fanout_type;
  unsigned        num_workers;
};


struct worker {
  struct config*     config;
  int                sock;
  volatile unsigned  pkts;
};


#define TEST(x)                                 \
  do {                                          \
    if( ! (x) ) {                               \
      fprintf(stderr, "ERROR: %s\n", #x);       \
      abort();                                  \
    }                                           \
  } while( 0 )


#define TRY(x)                                  \
  do {                                          \
    if( (x) < 0 ) {                             \
      perror(#x);                               \
      abort();                                  \
    }                                           \
  } while( 0 )


#if defined(__i386__) || defined(__x86_64__)
# define CACHE_LINE_SIZE   64
#elif defined(__PPC__) || defined(__PPC64__)
# define CACHE_LINE_SIZE   128
#else
# error "Need CACHE_LINE_SIZE for this arch."
#endif


static int mk_socket(const struct config* cfg)
{
  int sock;
  TRY( sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)) );

  struct sockaddr_ll ll;
  memset(&ll, 0, sizeof(ll));
  ll.sll_family = AF_PACKET;
  ll.sll_ifindex = if_nametoindex(cfg->device_name);
  TRY( bind(sock, (struct sockaddr*) &ll, sizeof(ll)) );

  if( cfg->fanout_type >= 0 ) {
    int fanout_arg = (cfg->fanout_id | (cfg->fanout_type << 16));
    TRY( setsockopt(sock, SOL_PACKET, PACKET_FANOUT,
                    &fanout_arg, sizeof(fanout_arg)) );
  }

  return sock;
}


static void* worker_main(void* arg)
{
  struct worker* w = arg;
  w->sock = mk_socket(w->config);

  while( 1 ) {
    char buf[1600];
    int rc = read(w->sock, buf, sizeof(buf));
    TEST( rc > 0 );
    ++(w->pkts);
  }
  return NULL;
}


static void monitor(struct worker** workers, int n_workers)
{
  struct timeval now_t, prev_t;
  int i;

  unsigned prev_pkts[n_workers];
  char buf[n_workers * 20];
  int buf_off;

  for( i = 0; i < n_workers; ++i )
    prev_pkts[i] = 0;
  gettimeofday(&prev_t, NULL);

  while( 1 ) {
    sleep(1);
    gettimeofday(&now_t, NULL);
    unsigned millis = (now_t.tv_sec - prev_t.tv_sec) * 1000;
    millis += (now_t.tv_usec - prev_t.tv_usec) / 1000;
    prev_t = now_t;
    buf_off = 0;
    for( i = 0; i < n_workers; ++i ) {
      uint64_t p = workers[i]->pkts;
      unsigned packets = p - prev_pkts[i];
      prev_pkts[i] = p;
      unsigned pkt_rate = (uint64_t) packets * 1000 / millis;
      buf_off += sprintf(buf + buf_off, "\t%u", pkt_rate);
    }
    printf("%s\n", buf);
    fflush(stdout);
  }
}


int main(int argc, char* argv[])
{
  struct config cfg;

  --argc; ++argv;
  if( argc < 3 || argc > 4 )
    usage_err();
  cfg.device_name = argv[0];
  const char* fanout_type = argv[1];
  cfg.num_workers = atoi(argv[2]);
  cfg.fanout_id = (argc > 3) ? atoi(argv[3]) : (getpid() & 0xffff);

  if( ! strcmp(fanout_type, "none") )
    cfg.fanout_type = -1;
  else if( ! strcmp(fanout_type, "hash") )
    cfg.fanout_type = PACKET_FANOUT_HASH;
  else if( ! strcmp(fanout_type, "lb") )
    cfg.fanout_type = PACKET_FANOUT_LB;
  else if( ! strcmp(fanout_type, "cpu") )
    cfg.fanout_type = PACKET_FANOUT_CPU;
  else if( ! strcmp(fanout_type, "rollover") )
    cfg.fanout_type = PACKET_FANOUT_ROLLOVER;
  else if( ! strcmp(fanout_type, "rnd") )
    cfg.fanout_type = PACKET_FANOUT_RND;
  else if( ! strcmp(fanout_type, "qm") )
    cfg.fanout_type = PACKET_FANOUT_QM;
  else
    usage_err();

  struct worker* all_workers[cfg.num_workers];

  unsigned i;
  for( i = 0; i < cfg.num_workers; ++i ) {
    void* p;
    TEST( posix_memalign(&p, CACHE_LINE_SIZE, sizeof(struct worker)) == 0 );
    struct worker* w = p;
    memset(w, 0, sizeof(*w));
    w->config = &cfg;
    pthread_t tid;
    TEST( pthread_create(&tid, NULL, worker_main, w) == 0 );
    all_workers[i] = w;
  }

  monitor(all_workers, cfg.num_workers);
  return 0;
}
