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
#include <assert.h>
#include <poll.h>


#define TEST(x)						\
  do {							\
	  if( ! (x) ) {					\
		  fprintf(stderr, "ERROR: %s\n", #x);	\
		  abort();				\
	  }						\
  } while( 0 )


#define PCAP_CALL(rc, x, args)			\
  do {						\
	fprintf(stderr, "call: %s\n", #x);	\
	(rc) = x args;				\
  } while( 0 )


#define PCAP_ERR_MSG(pcap, call, rc)				\
  do {								\
	fprintf(stderr, "ERROR: %s() => %d\n", (call), (rc));	\
	pcap_perror((pcap), (call));				\
	if( abort_on_err )					\
		abort();					\
  } while( 0 )


#define PCAP_TRY(pcap, x, args)			\
  do {						\
	int __rc;				\
	PCAP_CALL(__rc, x, args);		\
	if( __rc < 0 )				\
		PCAP_ERR_MSG(pcap, #x, __rc);	\
  } while( 0 )


#if defined(__i386__) || defined(__x86_64__)
# define CACHE_LINE_SIZE   64
#elif defined(__PPC__) || defined(__PPC64__)
# define CACHE_LINE_SIZE   128
#else
# error "Need CACHE_LINE_SIZE for this arch."
#endif


#define RD_ONCE(p)  (*(volatile typeof(*(p))*) (p))


static int abort_on_err = 1;


static void usage_msg(FILE* strm)
{
	FILE* s = strm;
	int (*f)(FILE*, const char*, ...) = fprintf;
	f(s, "\n");
	f(s, "usage:\n");
	f(s, "  pcap_cluster [options] <interface> <n-workers> "
		"[work-nanos]\n");
	f(s, "\n");
	f(s, "options:\n");
	f(s, "  -r           -- reflect packets\n");
	f(s, "  -t           -- touch packet payload\n");
	f(s, "  -x           -- use pcap_next()\n");
	f(s, "  -d           -- use pcap_dispatch()\n");
	f(s, "  -n           -- put pcap in non-blocking mode\n");
	f(s, "  -s1          -- pcap_get_selectable_fd + n*pcap_next_ex\n");
	f(s, "  -s2          -- pcap_get_selectable_fd + 1*pcap_next_ex\n");
	f(s, "  -s3          -- pcap_get_selectable_fd + pcap_dispatch\n");
	f(s, "  -o <millis>  -- set timeout in milliseconds\n");
	f(s, "  -e           -- continue on error\n");
	f(s, "\n");
}


static void usage_err(void)
{
	usage_msg(stderr);
	exit(1);
}


enum pcap_mode {
	PCAP_MODE_LOOP,
	PCAP_MODE_DISPATCH,
	PCAP_MODE_NEXT,
	PCAP_MODE_SELECTABLE_NEXT_1,
	PCAP_MODE_SELECTABLE_NEXT_2,
	PCAP_MODE_SELECTABLE_DISPATCH,
};


struct worker {
	/* Config */
	pcap_t*     	pcap;
	int         	worker_id;
	const char* 	interface;
	unsigned    	work_nanos;
	int             reflect;
	int             touch;
	enum pcap_mode  pcap_mode;
	int         	nonblocking;
	int         	timeout_ms;
	/* State */
	uint64_t    	bytes;
	uint64_t    	packets;
	uint64_t        dispatches;
	uint64_t    	csum;
};


static struct worker** all_workers;


static struct worker* worker_alloc(int id, const char* interface,
				   unsigned work_nanos, int reflect, int touch,
				   enum pcap_mode pcap_mode, int nonblocking,
				   int timeout_ms)
{
	void* p;
	TEST(posix_memalign(&p, CACHE_LINE_SIZE, sizeof(struct worker)) == 0);
	struct worker* w = p;
	w->worker_id = id;
	w->interface = interface;
	w->work_nanos = work_nanos;
	w->reflect = reflect;
	w->touch = touch;
	w->pcap_mode = pcap_mode;
	w->nonblocking = nonblocking;
	w->timeout_ms = timeout_ms;
	w->bytes = 0;
	w->packets = 0;
	all_workers[id] = w;
	return w;
}


static void simulate_work(unsigned work_nanos)
{
	struct timespec start, now;
	uint64_t elapsed_nanos;
	clock_gettime(CLOCK_REALTIME, &start);
	do {
		clock_gettime(CLOCK_REALTIME, &now);
		elapsed_nanos = (now.tv_sec - start.tv_sec) * 1000000000;
		elapsed_nanos += now.tv_nsec - start.tv_nsec;
	} while( elapsed_nanos < work_nanos );
}


static uint64_t csum_data(const void* p, int len_bytes)
{
	uint64_t csum = 0;

	/* Read unaligned prefix.  (NB. We know that len_bytes >7) */
	assert(len_bytes >= 7);
	if( (uintptr_t) p & 1 ) {
		csum += *(const uint8_t*) p;
		p = (uint8_t*) p + 1;
	}
	if( (uintptr_t) p & 2 ) {
		csum += *(const uint16_t*) p;
		p = (uint16_t*) p + 1;
	}
	if( (uintptr_t) p & 4 ) {
		csum += *(const uint32_t*) p;
		p = (uint32_t*) p + 1;
	}
	len_bytes &= ~((uintptr_t) 7);

	/* Read aligned portion. */
	while( len_bytes >= 8 ) {
		csum += *(const uint64_t*) p;
		p = (uint64_t*) p + 1;
		len_bytes -= 8;
	}

	/* Read unaligned suffix. */
	if( len_bytes & 4 ) {
		csum += *(const uint32_t*) p;
		p = (uint32_t*) p + 1;
	}
	if( len_bytes & 2 ) {
		csum += *(const uint16_t*) p;
		p = (uint16_t*) p + 1;
	}
	if( len_bytes & 1 ) {
		csum += *(const uint8_t*) p;
		p = (uint8_t*) p + 1;
	}

	return csum;
}


static void pkt_handler(u_char *user, const struct pcap_pkthdr *h,
			const u_char *bytes)
{
	struct worker* w = (void*) user;

	if( 0 ) {
		printf("%d: %ld.%06d len=%d caplen=%d\n", w->worker_id,
		       h->ts.tv_sec, (int) h->ts.tv_usec, h->len, h->caplen);
		fflush(stdout);
	}

	if( w->work_nanos )
		simulate_work(w->work_nanos);
	if( w->touch )
		w->csum += csum_data(bytes, h->caplen);
	if( w->reflect ) {
		int rc = pcap_inject(w->pcap, bytes, h->caplen);
		if( rc < 0 )
			PCAP_ERR_MSG(w->pcap, "pcap_inject", rc);
	}

	w->packets += 1;
	w->bytes += h->len;
}


static void* worker_main(void* arg)
{
	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	struct worker* w = arg;

	fprintf(stderr, "call: pcap_create\n");
	w->pcap = pcap_create(w->interface, pcap_errbuf);
	if( w->pcap == NULL ) {
		fprintf(stderr, "ERROR: pcap_open_live: %s\n", pcap_errbuf);
		abort();
	}

	PCAP_TRY(w->pcap, pcap_set_promisc, (w->pcap, 1));
	if( w->timeout_ms )
		PCAP_TRY(w->pcap, pcap_set_timeout, (w->pcap, w->timeout_ms));
	PCAP_TRY(w->pcap, pcap_activate, (w->pcap));
	if( w->nonblocking )
		/* NB. man(pcap) says you should set options before
		 * activating, but most devices don't support
		 * pcap_setnonblock before activate (in 1.5.3 at least).
		 */
		PCAP_TRY(w->pcap, pcap_setnonblock, (w->pcap, 1, pcap_errbuf));

	switch( w->pcap_mode ) {
	case PCAP_MODE_LOOP:
		PCAP_TRY(w->pcap, pcap_loop,
			 (w->pcap, 0, pkt_handler, (void*) w));
		break;
	case PCAP_MODE_DISPATCH:
		while( 1 ) {
			PCAP_TRY(w->pcap, pcap_dispatch,
				 (w->pcap, 0, pkt_handler, (void*) w));
			++(w->dispatches);
		}
		break;
	case PCAP_MODE_NEXT:
		while( 1 ) {
			struct pcap_pkthdr hdr;
			const u_char* bytes = pcap_next(w->pcap, &hdr);
			if( bytes != NULL )
				pkt_handler((void*) w, &hdr, bytes);
		}
		break;
	case PCAP_MODE_SELECTABLE_NEXT_1: {
		struct pollfd pfd;
		PCAP_CALL(pfd.fd, pcap_get_selectable_fd, (w->pcap));
		if( pfd.fd < 0 )
			PCAP_ERR_MSG(w->pcap, "pcap_get_selectable_fd", pfd.fd);
		pfd.events = POLLIN;
		while( 1 ) {
			int rc = poll(&pfd, 1, -1);
			TEST( rc == 1 );
			TEST( pfd.revents == POLLIN );
			do {
				struct pcap_pkthdr* phdr;
				const u_char* bytes;
				if (pcap_next_ex(w->pcap, &phdr, &bytes) <= 0)
					break;
				pkt_handler((void*) w, phdr, bytes);
			} while (w->nonblocking);
		}
		break;
	}
	case PCAP_MODE_SELECTABLE_NEXT_2: {
		struct pollfd pfd;
		PCAP_CALL(pfd.fd, pcap_get_selectable_fd, (w->pcap));
		if( pfd.fd < 0 )
			PCAP_ERR_MSG(w->pcap, "pcap_get_selectable_fd", pfd.fd);
		pfd.events = POLLIN;
		while( 1 ) {
			int rc = poll(&pfd, 1, -1);
			TEST( rc == 1 );
			TEST( pfd.revents == POLLIN );
			struct pcap_pkthdr* phdr;
			const u_char* bytes;
			rc = pcap_next_ex(w->pcap, &phdr, &bytes);
			if( rc == 1 )
				pkt_handler((void*) w, phdr, bytes);
			else
				TEST( rc == 0 );
		}
		break;
	}
	case PCAP_MODE_SELECTABLE_DISPATCH: {
		struct pollfd pfd;
		PCAP_CALL(pfd.fd, pcap_get_selectable_fd, (w->pcap));
		if( pfd.fd < 0 )
			PCAP_ERR_MSG(w->pcap, "pcap_get_selectable_fd", pfd.fd);
		pfd.events = POLLIN;
		while( 1 ) {
			int rc = poll(&pfd, 1, -1);
			TEST( rc == 1 );
			TEST( pfd.revents == POLLIN );
			rc = pcap_dispatch(w->pcap, 0, pkt_handler, (void*) w);
			TEST( rc >= 0 );
			++(w->dispatches);
		}
		break;
	}
	}

	return NULL;
}


static void monitor(struct worker** workers, int n_workers)
{
	struct timeval now_t, prev_t;
	uint64_t prev_pkts[n_workers];
	uint64_t prev_bytes[n_workers];
	uint64_t prev_dispatches[n_workers];
	uint64_t packets, bytes, dispatches, pkt_rate, bw_mbps;
	uint64_t millis, total_packets = 0;
	int i;

	for( i = 0; i < n_workers; ++i ) {
		prev_pkts[i] = 0;
		prev_bytes[i] = 0;
		prev_dispatches[i] = 0;
	}
	gettimeofday(&prev_t, NULL);
	printf("#%10s %10s %12s %8s\n",
	       "pkt_rate", "BW(mbps)", "tot_pkts", "pkt/disp");

	while( 1 ) {
		sleep(1);
		bytes = packets = dispatches = 0;
		for( i = 0; i < n_workers; ++i ) {
			uint64_t b = RD_ONCE(&workers[i]->bytes);
			uint64_t p = RD_ONCE(&workers[i]->packets);
			uint64_t d = RD_ONCE(&workers[i]->dispatches);
			bytes += b - prev_bytes[i];
			packets += p - prev_pkts[i];
			dispatches += d - prev_dispatches[i];
			prev_bytes[i] = b;
			prev_pkts[i] = p;
			prev_dispatches[i] = d;
		}
		total_packets += packets;
		gettimeofday(&now_t, NULL);
		millis = (now_t.tv_sec - prev_t.tv_sec) * 1000;
		millis += (now_t.tv_usec - prev_t.tv_usec) / 1000;
		pkt_rate = packets * 1000 / millis;
		bw_mbps = bytes * 8 / millis / 1000;
		printf(" %10d %10d %12"PRIu64" %8.1f\n",
		       (int) pkt_rate, (int) bw_mbps, total_packets,
		       dispatches ? (double) packets / dispatches : -1.0);
		fflush(stdout);
		prev_t = now_t;
	}
}


int main(int argc, char* argv[])
{
	int i, n_workers, work_nanos = 0, reflect = 0, touch = 0;
	int nonblocking = 0, timeout_ms = 0;
	const char* interface = NULL;
	enum pcap_mode pcap_mode = PCAP_MODE_LOOP;
	char dummy;

	--argc;  ++argv;
	while( argc > 0 ) {
		if( ! strcmp(*argv, "-r") ) {
			reflect = 1;
		} else if( ! strcmp(*argv, "-t") ) {
			touch = 1;
		} else if( ! strcmp(*argv, "-x") ) {
			pcap_mode = PCAP_MODE_NEXT;
		} else if( ! strcmp(*argv, "-d") ) {
			pcap_mode = PCAP_MODE_DISPATCH;
		} else if( ! strcmp(*argv, "-s1") ) {
			pcap_mode = PCAP_MODE_SELECTABLE_NEXT_1;
		} else if( ! strcmp(*argv, "-s2") ) {
			pcap_mode = PCAP_MODE_SELECTABLE_NEXT_2;
		} else if( ! strcmp(*argv, "-s3") ) {
			pcap_mode = PCAP_MODE_SELECTABLE_DISPATCH;
		} else if( ! strcmp(*argv, "-n") ) {
			nonblocking = 1;
		} else if( ! strcmp(*argv, "-e") ) {
			abort_on_err = 0;
		} else if( ! strcmp(*argv, "-o") && argc >= 2 ) {
			timeout_ms = atoi(argv[1]);
			--argc;  ++argv;
		} else if( argv[0][0] == '-' ) {
			usage_err();
		} else {
			break;
		}
		--argc;  ++argv;
	}

	switch( argc ) {
	case 3:
		if( sscanf(argv[2], "%u%c", &work_nanos, &dummy) != 1 )
			usage_err();
		/* fall-through */
	case 2:
		interface = argv[0];
		if( sscanf(argv[1], "%u%c", &n_workers, &dummy) != 1 )
			usage_err();
		break;
	default:
		usage_err();
	}

	TEST(all_workers = calloc(n_workers, sizeof(void*)));

	for( i = 0; i < n_workers; ++i ) {
		struct worker* w = worker_alloc(i, interface,
						work_nanos, reflect, touch,
						pcap_mode, nonblocking,
						timeout_ms);
		pthread_t tid;
		TEST(pthread_create(&tid, NULL, worker_main, w) == 0);
	}

	monitor(all_workers, n_workers);
	return 0;
}
