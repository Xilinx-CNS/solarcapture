/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <inttypes.h>

#define DO_SELECT 1

#define PCAP_SNAPLEN 65535
#define PCAP_TIMEOUT 1000
#define PCAP_PROMISC 1


#define TEST(x)                                 \
  do {                                          \
    if( ! (x) ) {                               \
      fprintf(stderr, "ERROR: %s\n", #x);       \
      abort();                                  \
    }                                           \
  } while( 0 )


static inline void hexdump(struct pcap_pkthdr* hdr, const uint8_t* data) {
  int i, offset=0;
  printf("packet (len=%d, caplen=%d):", hdr->len, hdr->caplen);
  for (i = 0; i < hdr->len; i++) {
    if ( ! (offset % 16) )
      printf("\n%04x ", offset);
    else if ( ! (offset % 8) )
      printf(" ");
    printf("%02x ", data[i]);
    offset += 1;
  }
  printf("\n\n");
}


static bool break_loop;
void handler(int signum)
{
  printf("Caught signal %d\n", signum);
  break_loop = true;
}


int main(int argc, char* argv[])
{
  if( argc != 2 ) {
    printf("USAGE: %s <interface>\n", argv[0]);
    exit(1);
  }
  const char* intf = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* pcap;
  int n_pkts = 0;
  struct pcap_pkthdr pkthdr;
  const u_char* pkt;

  pcap = pcap_open_live(intf, PCAP_SNAPLEN, PCAP_PROMISC, PCAP_TIMEOUT, errbuf);
  if( ! pcap ) {
    printf("ERROR: %s\n", errbuf);
    exit(1);
  }
  TEST(pcap_setnonblock(pcap, 1, errbuf) == 0);

#if DO_SELECT
  int pcap_fd;
  fd_set rfds;
  TEST( (pcap_fd = pcap_get_selectable_fd(pcap)) > 0 );
  FD_ZERO(&rfds);
  FD_SET(pcap_fd, &rfds);
#endif

  signal(SIGINT, handler);
  signal(SIGTERM, handler);
  printf("Capturing on %s (use_select=%d)\n", intf, DO_SELECT);
  while( ! break_loop ) {
#if DO_SELECT
    int rc = select(pcap_fd + 1, &rfds, NULL, NULL, NULL);
    TEST(rc == 1 || break_loop);
#endif
    while( ! break_loop && (pkt = pcap_next(pcap, &pkthdr)) ) {
      if( pkthdr.caplen == 0 || pkthdr.len == 0 )
        hexdump(&pkthdr, pkt);
      ++n_pkts;
    }
  }
  printf("Captured %d packets\n", n_pkts);
  return 0;
}
