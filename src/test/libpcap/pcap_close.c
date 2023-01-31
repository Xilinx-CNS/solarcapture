/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#include <pcap/pcap.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#include <time.h>


#define TEST(x)						\
  do {							\
	  if (! (x)) {					\
		  fprintf(stderr, "ERROR: %s\n", #x);	\
		  abort();				\
	  }						\
  } while( 0 )


#define PCAP_ERR_MSG(pcap, call, rc)				\
  do {								\
	fprintf(stderr, "ERROR: %s() => %d\n", (call), (rc));	\
	pcap_perror((pcap), (call));				\
  } while( 0 )


#define PCAP_TRY(pcap, x, args)					\
  do {								\
	if (verbose)  fprintf(stderr, "call: %s\n", #x);	\
	int __rc = x args;					\
	if (__rc < 0)						\
		PCAP_ERR_MSG(pcap, #x, __rc);			\
  } while( 0 )


static void usage_msg(FILE *strm)
{
	fprintf(strm, "\n");
	fprintf(strm, "usage:\n");
	fprintf(strm, "  pcap_close [-v] <interface>\n");
	fprintf(strm, "\n");
}


static void usage_err(void)
{
	usage_msg(stderr);
	exit(1);
}


int main(int argc, char *argv[])
{
	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	const char *interface = NULL;
	pcap_t *pcap;
	int i, verbose = 0;

	--argc;  ++argv;
	while (argc > 0) {
		if (! strcmp(*argv, "-v")) {
			verbose = 1;
		} else if (argv[0][0] == '-') {
			usage_err();
		} else {
			break;
		}
		--argc;  ++argv;
	}

	switch( argc ) {
	case 1:
		interface = argv[0];
		break;
	default:
		usage_err();
	}

	/* create, close */
	fprintf(stderr, "call: pcap_create\n");
	pcap = pcap_create(interface, pcap_errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "ERROR: pcap_open_live: %s\n", pcap_errbuf);
		abort();
	}
	fprintf(stderr, "call: pcap_close\n");
	pcap_close(pcap);

	for (i = 0; i < 4096; ++i) {
		/* create, activate, close */
		if (verbose)
			fprintf(stderr, "call: pcap_create\n");
		pcap = pcap_create(interface, pcap_errbuf);
		if (pcap == NULL) {
			fprintf(stderr, "ERROR: pcap_open_live: %s\n",
				pcap_errbuf);
			abort();
		}
		PCAP_TRY(pcap, pcap_activate, (pcap));
		if (verbose)
			fprintf(stderr, "call: pcap_close\n");
		pcap_close(pcap);
	}

	return 0;
}
