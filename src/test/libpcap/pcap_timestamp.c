/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#define _GNU_SOURCE  /* for dlsym() */
#include <pcap/pcap.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <dlfcn.h>


#define TEST(x)						\
  do {							\
	  if( ! (x) ) {					\
		  fprintf(stderr, "ERROR: %s\n", #x);	\
		  abort();				\
	  }						\
  } while( 0 )


#define PCAP_TRY(pcap, x, args)					\
  do {								\
	fprintf(stderr, "call: %s\n", #x);			\
	int __rc = x args;					\
	if( __rc < 0 ) {					\
		fprintf(stderr, "call: %s => %d\n", #x, __rc);	\
		pcap_perror(pcap, #x);				\
	}							\
  } while( 0 )


static void usage_msg(FILE* strm)
{
	fprintf(strm, "\n");
	fprintf(strm, "usage:\n");
	fprintf(strm, "  pcap_timestamp <interface> [type] [precision]\n");
	fprintf(strm, "\n");
}


static void usage_err(void)
{
	usage_msg(stderr);
	exit(1);
}


#ifndef PCAP_TSTAMP_HOST
# define PCAP_TSTAMP_HOST                0
# define PCAP_TSTAMP_HOST_LOWPREC        1
# define PCAP_TSTAMP_HOST_HIPREC         2
# define PCAP_TSTAMP_ADAPTER             3
# define PCAP_TSTAMP_ADAPTER_UNSYNCED    4

static int pcap_set_tstamp_type(pcap_t *p, int type)
{
	const char* fn_name = "pcap_set_tstamp_type";
	int (*fn)(pcap_t*, int);
	if( (fn = dlsym(RTLD_DEFAULT, fn_name)) == NULL ) {
		fprintf(stderr, "ERROR: dlsym(\"%s\") => %s\n",
			fn_name, dlerror());
		abort();
	}
	return fn(p, type);
}

#endif

#ifndef PCAP_TSTAMP_PRECISION_NANO
# define PCAP_TSTAMP_PRECISION_MICRO     0
# define PCAP_TSTAMP_PRECISION_NANO      1

static int pcap_set_tstamp_precision(pcap_t *p, int prec)
{
	const char* fn_name = "pcap_set_tstamp_precision";
	int (*fn)(pcap_t*, int);
	if( (fn = dlsym(RTLD_DEFAULT, fn_name)) == NULL ) {
		fprintf(stderr, "ERROR: dlsym(\"%s\") => %s\n",
			fn_name, dlerror());
		abort();
	}
	return fn(p, prec);
}

#endif


static int nanos;


static void handler(u_char *user, const struct pcap_pkthdr *h,
		    const u_char *bytes)
{
	printf("%ld.%0*d len=%d caplen=%d\n",
	       h->ts.tv_sec, (nanos ? 9 : 6), (int) h->ts.tv_usec,
	       h->len, h->caplen);
	fflush(stdout);
}


int main(int argc, char* argv[])
{
	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	const char* interface = NULL;
	pcap_t* pcap;
	int type = -1;
	int prec = -1;
	char dummy;

	--argc;  ++argv;
	switch( argc ) {
	case 3:
		if( ! strcmp(argv[2], "micro") )
			prec = PCAP_TSTAMP_PRECISION_MICRO;
		else if( ! strcmp(argv[2], "nano") )
			prec = PCAP_TSTAMP_PRECISION_NANO;
		else if( sscanf(argv[2], "%d%c", &prec, &dummy) == 1 )
			;
		else
			usage_err();
	case 2:
		if( ! strcmp(argv[1], "host") )
			type = PCAP_TSTAMP_HOST;
		else if( ! strcmp(argv[1], "host_lowprec") )
			type = PCAP_TSTAMP_HOST_LOWPREC;
		else if( ! strcmp(argv[1], "host_hiprec") )
			type = PCAP_TSTAMP_HOST_HIPREC;
		else if( ! strcmp(argv[1], "adapter") )
			type = PCAP_TSTAMP_ADAPTER;
		else if( ! strcmp(argv[1], "adapter_unsynced") )
			type = PCAP_TSTAMP_ADAPTER_UNSYNCED;
		else if( sscanf(argv[1], "%d%c", &type, &dummy) == 1 )
			;
		else
			usage_err();
	case 1:
		interface = argv[0];
		break;
	default:
		usage_err();
	}

	fprintf(stderr, "call: pcap_open_live\n");
	pcap = pcap_create(interface, pcap_errbuf);
	if( pcap == NULL ) {
		fprintf(stderr, "ERROR: pcap_open_live: %s\n", pcap_errbuf);
		abort();
	}

	PCAP_TRY(pcap, pcap_set_promisc, (pcap, 1));
	if( type >= 0 ) {
		PCAP_TRY(pcap, pcap_set_tstamp_type, (pcap, type));
	}
	if( prec >= 0 ) {
		PCAP_TRY(pcap, pcap_set_tstamp_precision, (pcap, prec));
	}
	if( prec == PCAP_TSTAMP_PRECISION_NANO )
		nanos = 1;

	PCAP_TRY(pcap, pcap_activate, (pcap));
	PCAP_TRY(pcap, pcap_loop, (pcap, 0, handler, NULL));
	return 0;
}
