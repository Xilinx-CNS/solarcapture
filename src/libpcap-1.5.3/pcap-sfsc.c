/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#define _GNU_SOURCE
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/param.h>

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <ctype.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/time.h>
#include <time.h>
#include <pwd.h>

#include "pcap-int.h"
#include "pcap-sfsc-poolnode.h"

#include <sc_internal.h>
#include <sc_internal/packed_stream.h>
#include <solar_capture/nodes/append_to_list.h>


#define TEST(x)                                                         \
  do {                                                                  \
    if( ! (x) ) {                                                       \
      fprintf(stderr, "ERROR: %s: TEST(%s) failed\n", __func__, #x);    \
      fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__);         \
      abort();                                                          \
    }                                                                   \
  } while( 0 )


#define TRY_SC(fn, args)						\
  do {									\
    int __rc = fn args;							\
    if (__rc < 0) {							\
      struct sc_session_error* e = sc_session_error_get(scs);		\
      if (e != NULL) {							\
        err(p, LL_ERR, "%s: %s failed (%s) errno=%s",			\
           __func__, #fn, e->err_msg, strerror(e->err_errno));		\
	sc_session_error_free(scs, e);					\
      } else {								\
        err(p, LL_ERR, "%s: %s failed (NO ERROR INFO) errno=%s",	\
           __func__, #fn, strerror(errno));                        	\
      }									\
      goto fail;							\
    }									\
  } while( 0 )


/* This just needs to be a value >0 and very unlikely to be set by user! */
#define RECV_BATCH_UNSET             123465789
#define RECV_BATCH_DEFAULT           4
#define RECV_BATCH_DEFAULT_PACKED    10


enum {
	LL_ERR = 1,
	LL_INF,
	LL_TRA,
};


struct pcap_sfsc {
	char*                 sfsc_device;
	int                   sfsc_log_level;
	bool                  sfsc_selectable_fd;
	int                   sfsc_recv_batch;
	int                   sfsc_recv_batch_i;
	FILE*                 sfsc_log_file;
	struct sc_session*    sfsc_session;
	struct sc_packed_packet* sfsc_cur_ps_pkt;
	struct sc_packet_list sfsc_rx_pl;
	struct sc_thread*     sfsc_rx_app_thrd;
	struct sc_node*       sfsc_rx_node;
	const struct sc_node_link* sfsc_rx_free_link;
	int                   sfsc_timeout;
	bool                  sfsc_nonblocking;
	bool                  sfsc_sleep;
	struct sc_thread*     sfsc_inj_thread;
	struct sc_node*       sfsc_pool_node;
	struct sc_node*       sfsc_inj_node;
	int                 (*sfsc_process)(pcap_t *, struct pcap_sfsc *,
					    pcap_handler, u_char *);
	struct pcap_stat      sfsc_stat;
};


static void sfsc_logv(pcap_t *p, int ll, const char* fmt, va_list va)
{
	struct pcap_sfsc* sfsc = p->priv;
	if (ll <= sfsc->sfsc_log_level)
		vfprintf(sfsc->sfsc_log_file, fmt, va);
}


static void sfsc_log(pcap_t *p, int ll, const char* fmt, ...)
  __attribute__((format(printf,3,4)));

static void sfsc_log(pcap_t *p, int ll, const char* fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	sfsc_logv(p, ll, fmt, va);
	va_end(va);
}


static int sfsc_err(pcap_t *p, int ll, const char* fmt, ...)
  __attribute__((format(printf,3,4)));

static int sfsc_err(pcap_t *p, int ll, const char* fmt, ...)
{
	va_list va;
	char fmt_nl[strlen(fmt) + 2];
	strcpy(fmt_nl, fmt);
	strcat(fmt_nl, "\n");
	va_start(va, fmt);
	sfsc_logv(p, ll, fmt_nl, va);
	va_end(va);
	va_start(va, fmt);
	vsnprintf(p->errbuf, PCAP_ERRBUF_SIZE, fmt, va);
	va_end(va);
	return -1;
}


/* Abbreviate, but I want the function to really have the sfsc_ prefix. */
#define log sfsc_log
#define err sfsc_err


static char *
sfsc_get_device(const char *device)
{
	char *env_name, *ret;
	const char *s;
	TEST( asprintf(&env_name, "SC_PCAP_SOURCE_%s", device) > 0 );
	if ((s = getenv(env_name)) != NULL)
		device = s;
	free(env_name);
	if (sc_match_prefix(device, "scshm:", &device)) {
		TEST( asprintf(&ret, "sc:sc_shm_import_node:path=%s", device)
		      > 0 );
	} else {
		ret = strdup(device);
	}
	return ret;
}


static int
sfsc_set_datalink(pcap_t *p, int dlt)
{
	p->linktype = dlt;
	return (0);
}

static int
sfsc_pcap_stats(pcap_t *p, struct pcap_stat *ps)
{
	struct pcap_sfsc* sfsc = p->priv;
	*ps = sfsc->sfsc_stat;
	return 0;
}

static void
sfsc_platform_cleanup(pcap_t *p)
{
	struct pcap_sfsc* sfsc = p->priv;
	struct sc_injector_node* inj_state;
	struct sc_session* scs;
	int rc;

	if (p == NULL)
		return;

	pcap_remove_from_pcaps_to_close(p);

	/* wait for outgoing packets to leave */

	/* We don't see packets as they're freed in the unmanaged case
	 * so we look directly at the node stats.
	 *
	 * We always do an sc_thread_poll after forwarding packets to
	 * the injector node, so we know that n_pkts_in reflects all
	 * injected packets.
	 */
	if (sfsc->sfsc_inj_node != NULL) {
		inj_state = sfsc->sfsc_inj_node->nd_private;
		while (inj_state->n_pkts_in != inj_state->n_pkts_out)
			sc_thread_poll(sfsc->sfsc_inj_thread);
	}

	pcap_cleanup_live_common(p);
	scs = sfsc->sfsc_session;

	if ((rc = sc_session_destroy(scs)) != 0)
		log(p, LL_ERR, "%s: sc_session_destroy() failed: %d\n",
		    __func__, rc);

	free(sfsc->sfsc_device);
}

static int
sfsc_getnonblock(pcap_t *p, char *errbuf)
{
	struct pcap_sfsc* sfsc = p->priv;
	return sfsc->sfsc_nonblocking;
}

static int
sfsc_setnonblock(pcap_t *p, int nonblock, char *errbuf)
{
	struct pcap_sfsc* sfsc = p->priv;
	if( nonblock == 0 && sfsc->sfsc_selectable_fd ) {
		snprintf(errbuf, PCAP_ERRBUF_SIZE, "Cannot set nonblock=0 "
			 "after calling pcap_get_selectable_fd");
		return -1;
	}
	sfsc->sfsc_nonblocking = nonblock != 0;
	return 0;
}


static int
sfsc_get_selectable_fd(pcap_t *p)
{
	int fd;
	struct pcap_sfsc *sfsc = p->priv;
	if (!sfsc->sfsc_nonblocking)
		return err(p, LL_ERR, "%s: require nonblocking", __func__);
	sfsc->sfsc_selectable_fd = true;
	fd = sc_thread_waitable_fd_get(sfsc->sfsc_rx_app_thrd, false);
	if ( fd < 0 )
		return err(p, LL_ERR, "%s: failed to get selectable_fd",
			   __func__);
	return fd;
}


static int sfsc_setdirection(pcap_t *p, pcap_direction_t d)
{
	if (d == PCAP_D_OUT)
		return err(p, LL_ERR, "%s: Direction 'out' not supported",
			   __func__);
	return 0;
}


static inline int want_nanos(const pcap_t *p)
{
	return p->opt.tstamp_precision == PCAP_TSTAMP_PRECISION_NANO;
}

static inline int
sfsc_process_buffer(pcap_t *p, pcap_handler callback, u_char *user,
		    void* buffer, uint32_t ts_sec, uint32_t ts_nsec,
		    int origlen, int caplen)
{
	struct pcap_pkthdr hdr;
	if ((p->fcode.bf_insns == NULL) ||
	    bpf_filter(p->fcode.bf_insns,
		       buffer,
		       origlen,
		       caplen)) {
		hdr.ts.tv_sec = ts_sec;
		if (want_nanos(p))
			hdr.ts.tv_usec = ts_nsec;
		else
			hdr.ts.tv_usec = ts_nsec / 1000;
		hdr.caplen = caplen;
		hdr.len = origlen;
		callback(user, &hdr, buffer);
		return 1;
	}
	return 0;
}

static inline int
sfsc_process_pkt_packed(pcap_t *p, struct pcap_sfsc *sfsc,
			pcap_handler callback, u_char *user)
{
	struct sc_packed_packet* ps_pkt;
	int caplen, rc;

	assert( sfsc->sfsc_rx_pl.head->flags & SC_PACKED_STREAM );

	if (sfsc->sfsc_cur_ps_pkt == NULL)
		sfsc->sfsc_cur_ps_pkt =
			sfsc->sfsc_rx_pl.head->iov[0].iov_base;
	ps_pkt = sfsc->sfsc_cur_ps_pkt;

	caplen = ps_pkt->ps_cap_len;
	if (caplen > p->snapshot)
		caplen = p->snapshot;

	rc = sfsc_process_buffer(p, callback, user,
				 sc_packed_packet_payload(ps_pkt),
				 ps_pkt->ps_ts_sec, ps_pkt->ps_ts_nsec,
				 ps_pkt->ps_orig_len, caplen);

	sfsc->sfsc_cur_ps_pkt = sc_packed_packet_next(ps_pkt);
	if (sfsc->sfsc_cur_ps_pkt == ps_pkt ||
	    (uintptr_t)sfsc->sfsc_cur_ps_pkt >=
	    (uintptr_t)sfsc->sfsc_rx_pl.head->iov[0].iov_base +
	    sfsc->sfsc_rx_pl.head->iov[0].iov_len) {
		sc_forward(sfsc->sfsc_rx_node, sfsc->sfsc_rx_free_link,
			   sc_packet_list_pop_head(&sfsc->sfsc_rx_pl));
		sfsc->sfsc_cur_ps_pkt = NULL;
	}

	return rc;
}

static inline int
sfsc_process_pkt_normal(pcap_t *p, struct pcap_sfsc *sfsc,
			pcap_handler callback, u_char *user)
{
	struct sc_packet* pkt;
	int caplen, rc;

	assert( ! (sfsc->sfsc_rx_pl.head->flags & SC_PACKED_STREAM) );

	pkt = sc_packet_list_pop_head(&sfsc->sfsc_rx_pl);
	caplen = pkt->iov[0].iov_len;
	if (caplen > p->snapshot)
		caplen = p->snapshot;

	rc = sfsc_process_buffer(p, callback, user, pkt->iov[0].iov_base,
				 pkt->ts_sec, pkt->ts_nsec,
				 pkt->frame_len, caplen);

	/* ?? todo: can we batch these up? */
	sc_forward(sfsc->sfsc_rx_node, sfsc->sfsc_rx_free_link, pkt);
	return rc;
}

static int
sfsc_process_first(pcap_t *p, struct pcap_sfsc *sfsc,
		   pcap_handler callback, u_char *user)
{
	if (sfsc->sfsc_rx_pl.head->flags & SC_PACKED_STREAM) {
		sfsc->sfsc_process = sfsc_process_pkt_packed;
		if (sfsc->sfsc_recv_batch == RECV_BATCH_UNSET)
			sfsc->sfsc_recv_batch = RECV_BATCH_DEFAULT_PACKED;
		log(p, LL_INF, "sfsc: [%s] packed recv_batch=%d\n",
		    p->opt.source, sfsc->sfsc_recv_batch);
	} else {
		sfsc->sfsc_process = sfsc_process_pkt_normal;
		if (sfsc->sfsc_recv_batch == RECV_BATCH_UNSET)
			sfsc->sfsc_recv_batch = RECV_BATCH_DEFAULT;
		log(p, LL_INF, "sfsc: [%s] normal recv_batch=%d\n",
		    p->opt.source, sfsc->sfsc_recv_batch);
	}
	return sfsc->sfsc_process(p, sfsc, callback, user);
}

static int
sfsc_read(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
{
	struct pcap_sfsc *sfsc = p->priv;
	struct timespec timeout = { 0, 0 };
	bool poll_did_something = false, idle = false;
	int rc, n = 0;

	if (sc_packet_list_is_empty(&sfsc->sfsc_rx_pl)) {
		do {
			poll_did_something =
				sc_thread_poll(sfsc->sfsc_rx_app_thrd);
		} while (poll_did_something &&
			 sc_packet_list_is_empty(&sfsc->sfsc_rx_pl));
		sfsc->sfsc_recv_batch_i = 0;
	}

	while (1) {
		/* Consume available packets. */
		if (!sc_packet_list_is_empty(&sfsc->sfsc_rx_pl)) {
			do {
				if (sfsc->sfsc_recv_batch_i >=
				    sfsc->sfsc_recv_batch)
					break;
				rc = sfsc->sfsc_process(p, sfsc, callback,
							user);
				++(sfsc->sfsc_recv_batch_i);
				if ((n += rc) == cnt &&
				    !PACKET_COUNT_IS_UNLIMITED(cnt))
					goto out;
			} while (!sc_packet_list_is_empty(&sfsc->sfsc_rx_pl));
			idle = false;
		} else if (sfsc->sfsc_nonblocking || n > 0) {
			goto out;
		} else if (sfsc->sfsc_timeout > 0) {
			struct timespec now;
			TEST( clock_gettime(CLOCK_MONOTONIC, &now) == 0 );
			if (idle) {
				if (now.tv_sec > timeout.tv_sec ||
				    (now.tv_sec == timeout.tv_sec &&
				     now.tv_nsec > timeout.tv_nsec))
					goto out;
			} else {
				idle = true;
				timeout = now;
				timeout.tv_sec += sfsc->sfsc_timeout / 1000;
				timeout.tv_nsec +=
					(sfsc->sfsc_timeout % 1000) * 1000000;
				if (timeout.tv_nsec >= 1000000000) {
					timeout.tv_sec += 1;
					timeout.tv_nsec -= 1000000000;
				}
			}
			if (sfsc->sfsc_sleep)
				usleep(1);
		} else if (sfsc->sfsc_sleep) {
			usleep(1);
		}

		if (p->break_loop) {
			/* ?? Seems to be some disagreement as to correct
			 * behaviour here.  We (and SNF) follow the man
			 * page.  But linux and DAG behaviour is different.
			 */
			if (n == 0) {
				p->break_loop = 0;
				n = PCAP_ERROR_BREAK;
			}
			goto out;
		}

		/* Poll for new packets. */
		do {
			poll_did_something = sc_thread_poll(sfsc->sfsc_rx_app_thrd);
		} while (poll_did_something &&
			 sc_packet_list_is_empty(&sfsc->sfsc_rx_pl));
		sfsc->sfsc_recv_batch_i = 0;
	}

out:
	if (sfsc->sfsc_selectable_fd &&
	    sc_packet_list_is_empty(&sfsc->sfsc_rx_pl) &&
	    !poll_did_something)
		sc_thread_waitable_fd_prime(sfsc->sfsc_rx_app_thrd);
	return n;
}

static int
sfsc_setfilter(pcap_t *p, struct bpf_program *fp)
{
	if (!p)
		return -1;
	if (!fp) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
			 "%s: No filter specified", __func__);
		return -1;
	}

	/* Make our private copy of the filter */

	if (install_bpf_program(p, fp) < 0)
		return -1;

	return (0);
}

static int
sfsc_try_send(pcap_t *p, const void *buf _U_, size_t size _U_)
{
	struct pcap_sfsc* sfsc = p->priv;
	struct sfsc_pool_node_state *ps = sfsc->sfsc_pool_node->nd_private;
	struct sc_packet_list list;
	struct sc_packet* pkt;
	struct sc_iovec_ptr iovp;
	int ret;

	__sc_packet_list_init(&list);
	ret = sc_pool_get_packets(&list, ps->pool, 1, 1);
	if ( ret <= 0 )
		return -1;

	pkt = list.head;
	pkt->iov[0].iov_len = 0;

	sc_iovec_ptr_init_buf(&iovp, (void*)buf, size);
	ret = sc_packet_append_iovec_ptr(pkt, ps->pool, &iovp, size);
	if ( ret != 0 ) {
		sc_pool_return_packets(ps->pool, &list);
		return -1;
	}

	assert(sc_packet_bytes(pkt) == size);
	sc_forward(sfsc->sfsc_pool_node, ps->next_hop, pkt);
	sc_thread_poll(sfsc->sfsc_inj_thread);
	return size;
}


static int
sfsc_inject(pcap_t *p, const void *buf _U_, size_t size _U_)
{
	struct pcap_sfsc* sfsc = p->priv;
	int ret;

	if (!sfsc->sfsc_inj_node) {
		snprintf(p->errbuf, PCAP_ERRBUF_SIZE,
			 "%s: injection not available", __func__);
		return -1;
	}

	do {
		ret = sfsc_try_send(p, buf, size);
		if (ret >= 0)
			return ret;
		sc_thread_poll(sfsc->sfsc_inj_thread);
	} while ( ! sfsc->sfsc_nonblocking );

	return err(p, LL_TRA, "%s: would block", __func__);
}


static bool
sfsc_mk_source_node(pcap_t *p, struct sc_thread *thread,
		    struct sc_attr *attr, struct sc_node *next_hop)
{
	struct pcap_sfsc *sfsc = p->priv;
	struct sc_session *scs = sc_thread_get_session(thread);
	const char *node_spec;
	struct sc_node* node;

	TEST( sc_match_prefix(sfsc->sfsc_device, "sc:", &node_spec) );
	TEST( sc_attr_set_int(attr, "unpack_packed_stream", 0) == 0 );
	sfsc_log(p, LL_INF, "%s: [%s] node_spec=%s\n", __func__,
		 p->opt.source, node_spec);
	TRY_SC( sc_node_alloc_from_str, (&node, attr, thread, node_spec) );
	TEST(sc_node_add_link(node, "", next_hop, NULL) == 0);
	return true;
fail:
	return false;
}


static int
sfsc_activate_tx(pcap_t *p, struct sc_vi* vi)
{
	struct pcap_sfsc* sfsc = p->priv;
	struct sc_session* scs = sfsc->sfsc_session;
	struct sc_arg injector_args[] = {
		SC_ARG_STR("interface", sc_vi_get_interface_name(vi)),
	};
	struct sc_node* injector;
	struct sc_node* pool_node;
	struct sc_thread* inj_thrd;
	struct sc_attr* attr;
	char* name;

	TEST(sc_attr_alloc(&attr) == 0);
	asprintf(&name, "libpcap_tx:%s", sc_vi_get_interface_name(vi));
	TEST(sc_attr_set_str(attr, "group_name", name) == 0);
	free(name);
	TEST(sc_attr_set_int(attr, "managed", 0) == 0);
	TEST(sc_thread_alloc(&inj_thrd, attr, scs) == 0);
	TEST(sc_node_alloc_named(&injector, attr, inj_thrd, "sc_injector",
				 NULL, injector_args,
				 sizeof(injector_args) /
				 sizeof(injector_args[0])) == 0);
	TEST(sc_node_alloc(&pool_node, attr, inj_thrd,
			   &sfsc_pool_node_sc_node_factory, NULL, 0) == 0);
	TEST(sc_node_add_link(pool_node, "", injector, "") == 0);

	sfsc->sfsc_inj_thread = inj_thrd;
	sfsc->sfsc_pool_node = pool_node;
	sfsc->sfsc_inj_node = injector;
	sc_attr_free(attr);
	return 0;
}


/* There are two options for how we set up our sc_threads, to allow control
 * over how we utilise cpu cores.
 *
 * In the unmanaged case we create no extra threads, and all work is
 * performed within the pcap application thread.  We use sc_threads to
 * logically structure the solar_capture objects that we use, and to allow
 * a single send and a single read to be performed concurrently.
 *
 * In the managed case we create a solar capture managed thread to perform
 * capture.  The pcap application thread interacts via an unmanaged thread
 * and mailbox.
 *
 * Unmanaged:
 * injector thread(u)    |    capture app thread(u)
 *                       --------------------------------
 *                       |     capture thread(u)
 *
 * Managed:
 * injector app thread(u)    |    capture app thread(u)
 * ----------------------------------------------------
 *              injector and capture thread(m)
 *
 */
static int
sfsc_activate(pcap_t* p)
{
	struct pcap_sfsc* sfsc = p->priv;
	struct sc_stream* stream;
	struct sc_thread* cap_thrd;
	struct sc_thread* app_thrd;
	struct sc_session* scs = NULL;
	struct sc_node* deliver_node;
	struct sc_attr* attr;
	struct sc_attr* attr_um;
	struct sc_vi* vi = NULL;
	int rc;
	const char* thread_env;
	int managed_thread = 1;
	int affinity = -1;
	char* name;

	TEST(sc_attr_alloc(&attr) == 0);
	TEST(sc_attr_alloc(&attr_um) == 0);
	asprintf(&name, "libpcap_rx:%s", p->opt.source);
	TEST(sc_attr_set_str(attr, "group_name", name) == 0);
	TEST(sc_attr_set_str(attr_um, "group_name", name) == 0);
	free(name);
	TEST(sc_attr_set_int(attr_um, "managed", 0) == 0);

	switch( p->opt.tstamp_type ) {
	case PCAP_TSTAMP_HOST:
	case PCAP_TSTAMP_HOST_LOWPREC:
	case PCAP_TSTAMP_HOST_HIPREC:
		TEST(sc_attr_set_int(attr, "force_sw_timestamps", 1) == 0);
		break;
	case PCAP_TSTAMP_ADAPTER:
	case PCAP_TSTAMP_ADAPTER_UNSYNCED:
		TEST(sc_attr_set_int(attr, "require_hw_timestamps", 1) == 0);
		break;
	default:
		/* ?? fixme: We should have a way to override behaviour via
		 * environment or config file.  Default will give unsynced
		 * h/w timestamps...
		 */
		break;
	}

	/* SC_PCAP_THREAD can be specified in two ways:
	 * Specifying a comma separated list of interface=int specifies a
	 * specific affinity for each interface.
	 * Specifying a single int applies that affinity to each interface.
	 *
	 * If an affinity is specified for an interface, either as part of
	 * all interfaces, or specifically, then a managed thread with that
	 * affinity will be used.
	 */
	thread_env = getenv("SC_PCAP_THREAD");
	if( !thread_env ) {
		managed_thread = 0;
	}
	else {
		char *affinity_str, *device_str, *endptr;
		TEST(asprintf(&device_str, "%s=", p->opt.source) > 0);
		affinity_str = strstr(thread_env, device_str);
		free(device_str);

		if( affinity_str ) {
			affinity_str = strchr(affinity_str, '=');
			affinity_str++;
		}
		else {
			affinity_str = (char*)thread_env;
		}

		affinity = strtol(affinity_str, &endptr, 0);
		if( (strlen(affinity_str) == 0) || (affinity_str == endptr) )
			managed_thread = 0;
	}

	sfsc_log(p, LL_INF, "%s: [%s] threaded=%d affinity=%d\n",
		 __func__, p->opt.source, managed_thread, affinity);

	TRY_SC( sc_session_alloc, (&scs, attr) );
	TRY_SC( sc_thread_alloc, (&app_thrd, attr_um, scs) );

	if( managed_thread ) {
		TEST( sc_attr_set_int(attr, "affinity_core", affinity) == 0 );
		asprintf(&name, "libpcap_cap:%s", p->opt.source);
		free(name);
		if (sfsc->sfsc_sleep)
			TEST( sc_attr_set_int(attr, "busy_wait", 0) == 0 );
		TRY_SC( sc_thread_alloc, (&cap_thrd, attr, scs) );
	} else {
		cap_thrd = app_thrd;
	}

	TEST( sc_node_alloc_named(&deliver_node, attr, app_thrd,
				  "sc_append_to_list", NULL, NULL, 0) == 0 );

	if (!sc_match_prefix(sfsc->sfsc_device, "sc:", NULL)) {
		TEST( sc_attr_set_int(attr, "unpack_packed_stream", 0) == 0 );
		TRY_SC( sc_vi_alloc, (&vi, attr, cap_thrd, sfsc->sfsc_device) );

		/* NB. Don't add a stream if we're being invoked from
		 * pcap_findalldevs(), because if we do we risk preventing
		 * another process from adding an incompatible stream if
		 * invoked at the same time (bug58527).
		 */
		if (!pcap_in_findalldevs) {
			TEST( sc_stream_alloc(&stream, attr, scs) == 0 );
			TEST( sc_stream_all(stream) == 0 );
			TRY_SC( sc_vi_add_stream, (vi, stream) );
			TEST( sc_stream_free(stream) == 0 );
		}

		TEST( sc_vi_set_recv_node(vi, deliver_node, NULL) == 0 );
	}
	else if (!pcap_in_findalldevs) {
		if (!sfsc_mk_source_node(p, cap_thrd, attr, deliver_node))
			goto fail;
	}

	sfsc->sfsc_session = scs;
	sfsc->sfsc_inj_node = NULL;
	if (vi) {
		/* Only set up tx if vi is in use. */
		rc = sfsc_activate_tx(p, vi);
		if (rc < 0)
			goto fail;
	}

	TRY_SC( sc_session_prepare, (scs) );

	struct sc_append_to_list* atl = deliver_node->nd_private;
	__sc_packet_list_init(&sfsc->sfsc_rx_pl);
	atl->append_to = &(sfsc->sfsc_rx_pl);
	sfsc->sfsc_rx_free_link = atl->free_link;
	sfsc->sfsc_rx_node = deliver_node;
	sfsc->sfsc_rx_app_thrd = app_thrd;

	if (sfsc->sfsc_inj_thread)
		sc_thread_poll_timers(sfsc->sfsc_inj_thread);
	sc_thread_poll_timers(sfsc->sfsc_rx_app_thrd);

	TRY_SC( sc_session_go, (scs) );

	sc_attr_free(attr);
	sc_attr_free(attr_um);

	/* If user hasn't specified a buffer size use the arbitrary value of
	 * 64k.
	 */
	if( p->opt.buffer_size == 0 )
		p->opt.buffer_size = 0x10000;

	/* "select()" and "poll()" don't work (yet?).
	 */
	p->selectable_fd = -1;
	p->linktype = DLT_EN10MB;
	p->read_op = sfsc_read;
	p->inject_op = sfsc_inject;
	p->setfilter_op = sfsc_setfilter;
	p->setdirection_op = sfsc_setdirection;
	p->set_datalink_op = sfsc_set_datalink;
	p->stats_op = sfsc_pcap_stats;
	p->cleanup_op = sfsc_platform_cleanup;
	p->get_selectable_fd_op = sfsc_get_selectable_fd;
	p->fileno_op = sfsc_get_selectable_fd;
	sfsc->sfsc_stat.ps_recv = 0;
	sfsc->sfsc_stat.ps_drop = 0;
	sfsc->sfsc_stat.ps_ifdrop = 0;
	if (sfsc->sfsc_nonblocking)
		sfsc->sfsc_timeout = 0;
	else
		sfsc->sfsc_timeout = p->opt.timeout;
	sfsc->sfsc_cur_ps_pkt = NULL;
	pcap_do_addexit(p);
	pcap_add_to_pcaps_to_close(p);

	return 0;

fail:
	sc_attr_free(attr);
	sc_attr_free(attr_um);
	if( scs != NULL )
		sc_session_destroy(scs);
	return -1;
}

int
sfsc_findalldevs(pcap_if_t **devlistp, char *errbuf)
{
	/*
	 * There are no platform-specific devices since each device
	 * exists as a regular Ethernet device.
	 */
	return 0;
}


static int sfsc_can_handle(pcap_t *p, const char *device,
			   char *ebuf, int *is_ours)
{
	struct sc_session *scs;
	struct sc_thread *thrd;
	struct sc_attr *attr;
	struct sc_vi *vi;
	int rc;

	*is_ours = 1;

	if (sc_match_prefix(device, "sc:", NULL))
		return 1;
	if (getenv("SC_PCAP_VETO_VI") != NULL) {
		/* Only allow captures from a node.  Used by CSS. */
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "sfsc: capture on '%s' "
			 "vetoed by SC_PCAP_VETO_VI", device);
		return 0;
	}

	TEST(sc_attr_alloc(&attr) == 0);
	if (attr->log_level == SC_LL_INFO)
		attr->log_level = SC_LL_NONE;
	if ((rc = sc_session_alloc(&scs, attr)) != 0) {
		sc_attr_free(attr);
		snprintf(ebuf, PCAP_ERRBUF_SIZE, "%s: sc_session_alloc failed:"
			 " %s", __func__, strerror(errno));
		log(p, LL_INF, "%s: sc_session_alloc failed: %s\n",
		    __func__, strerror(errno));
		return 0;
	}
	TEST(sc_thread_alloc(&thrd, attr, scs) == 0);
	rc = sc_vi_alloc(&vi, attr, thrd, device);
	sc_attr_free(attr);
	if (rc != 0) {
		struct sc_session_error* e = sc_session_error_get(scs);
		log(p, LL_INF, "%s: sc_vi_alloc(%s) failed (%d, %s)\n",
		    __func__, device, e ? e->err_errno : -1,
		    e ? e->err_msg : "no-error-info");
		if( e )
			sc_session_error_free(scs, e);
		*is_ours = 0;
	}
	sc_session_destroy(scs);
	return *is_ours;
}


pcap_t *
sfsc_create(const char *device, char *ebuf, int *is_ours)
{
	struct pcap_sfsc* sfsc;
	const char* s;
	pcap_t *p;

	*is_ours = 0;
	p = pcap_create_common(device, ebuf, sizeof(struct pcap_sfsc));
	if (p == NULL)
		return NULL;

	sfsc = p->priv;
	memset(sfsc, 0, sizeof(*sfsc));
	sfsc->sfsc_device = sfsc_get_device(device);
	sfsc->sfsc_log_level = LL_ERR;
	if ((s = getenv("SC_PCAP_LOG_LEVEL")) != NULL)
		sfsc->sfsc_log_level = atoi(s);
	sfsc->sfsc_recv_batch = RECV_BATCH_UNSET;
	if ((s = getenv("SC_PCAP_RECV_BATCH")) != NULL)
		sfsc->sfsc_recv_batch = atoi(s);
	if ((s = getenv("SC_PCAP_SPIN")) != NULL)
		sfsc->sfsc_sleep = (atoi(s) == 0);
	sfsc->sfsc_log_file = stderr;
	if ((s = getenv("SC_PCAP_LOG_FILE")) != NULL) {
		sfsc->sfsc_log_file = fopen(s, "w");
		if (sfsc->sfsc_log_file == NULL ) {
			fprintf(stderr, "%s: could not open SC_PCAP_LOG_FILE="
				"%s\n", __func__, s);
			abort();
		}
	}

	sfsc_log(p, LL_INF, "%s: [%s] sfsc_device=%s\n",
		 __func__, device, sfsc->sfsc_device);

	if (!sfsc_can_handle(p, sfsc->sfsc_device, ebuf, is_ours))
		return NULL;

	p->tstamp_type_list = NULL;
	p->tstamp_precision_list = NULL;

	p->tstamp_type_count = 3;
	p->tstamp_type_list = malloc(p->tstamp_type_count *
				     sizeof(p->tstamp_type_list[0]));
	if( p->tstamp_type_list == NULL )
		goto err;
	p->tstamp_type_list[0] = PCAP_TSTAMP_HOST;
	p->tstamp_type_list[1] = PCAP_TSTAMP_ADAPTER;
	p->tstamp_type_list[2] = PCAP_TSTAMP_ADAPTER_UNSYNCED;
	/* ?? TODO: Would be nice to be able to query whether clock on a
	 * given interface is synced.
	 *
	 * Also want to be able to query whether hardware timestamps are
	 * available on an interface.  At the moment we assume they are,
	 * and we'll generate an error later if not.
	 */

	p->tstamp_precision_count = 2;
	p->tstamp_precision_list = malloc(p->tstamp_precision_count *
					  sizeof(p->tstamp_precision_list));
	if( p->tstamp_precision_list == NULL )
		goto err;
	p->tstamp_precision_list[0] = PCAP_TSTAMP_PRECISION_MICRO;
	p->tstamp_precision_list[1] = PCAP_TSTAMP_PRECISION_NANO;

	/* Option to request nanosec precision via environment. */
	if( (s = getenv("SC_PCAP_NANOSEC")) != NULL && atoi(s) != 0 )
		p->opt.tstamp_precision = PCAP_TSTAMP_PRECISION_NANO;

	p->activate_op = sfsc_activate;
	p->getnonblock_op = sfsc_getnonblock;
	p->setnonblock_op = sfsc_setnonblock;
	sfsc->sfsc_process = sfsc_process_first;
	sfsc->sfsc_nonblocking = false;
	return p;

err:
	free(p->tstamp_type_list);
	free(p->tstamp_precision_list);
	free(p);
	return NULL;
}
