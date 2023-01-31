/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <arpa/inet.h>


#define TEST(x)						\
  do {							\
	  if( ! (x) ) {					\
		  fprintf(stderr, "ERROR: %s\n", #x);	\
		  abort();				\
	  }						\
  } while( 0 )


#define PCAP_ERR_MSG(pcap, call, rc)				\
  do {								\
	fprintf(stderr, "ERROR: %s() => %d\n", (call), (rc));	\
	pcap_perror((pcap), (call));				\
  } while( 0 )


#define PCAP_TRY(pcap, x, args)			\
  do {						\
	fprintf(stderr, "call: %s\n", #x);	\
	int __rc = x args;			\
	if( __rc < 0 )				\
		PCAP_ERR_MSG(pcap, #x, __rc);	\
  } while( 0 )


static void usage_msg(FILE* strm)
{
	fprintf(strm, "\n");
	fprintf(strm, "usage:\n");
	fprintf(strm, "  pcap_inject_trivial <interface> <frame-len> "
		"[num-pkts] [gap-usec]\n");
	fprintf(strm, "\n");
}


static void usage_err(void)
{
	usage_msg(stderr);
	exit(1);
}


int main(int argc, char* argv[])
{
	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	struct ether_header* eth;
	const char* interface;
	char pkt_buf[1514];
	int frame_len, n = -1, gap_us = 0;
	pcap_t* pcap;

	--argc;  ++argv;
	if( argc < 2 )
		usage_err();
	interface = argv[0];
	frame_len = atoi(argv[1]);
	TEST(frame_len <= sizeof(pkt_buf));
	if( argc >= 3 )
		n = atoi(argv[2]);
	if( argc >= 4 )
		gap_us = atoi(argv[3]);

	pcap = pcap_create(interface, pcap_errbuf);
	if( pcap == NULL ) {
		fprintf(stderr, "ERROR: pcap_open_live: %s\n", pcap_errbuf);
		abort();
	}

	PCAP_TRY(pcap, pcap_activate, (pcap));

	eth = (void*) pkt_buf;
	memset(eth->ether_shost, 0x12, 6);
	memset(eth->ether_dhost, 0xff, 6);
	eth->ether_type = htons(0x0804);

	while( n < 0 || --n >= 0 ) {
		int rc = pcap_inject(pcap, pkt_buf, frame_len);
		if( rc < 0 )
			PCAP_ERR_MSG(pcap, "pcap_inject", rc);
		if( gap_us )
			usleep(gap_us);
	}

	return 0;
}
