/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \node{sc_writer}
 *
 * \brief Node that writes packets to a file in pcap format.
 *
 * \nodedetails
 * The sc_writer node writes incoming packets to a file.
 *
 * By default O_DIRECT and asynchronous-I/O are used to maximise
 * performance if the underlying filesystem supports those features.
 *
 * \nodeargs
 * Argument         | Optional? | Default | Type           | Description
 * ---------------- | --------- | ------- | -------------- | --------------------------------------------------------------------------------------------------------------------------------
 * filename         | No        |         | ::SC_PARAM_STR | Name of file to write to, or filename template when using file rotation
 * format           | Yes       | pcap    | ::SC_PARAM_STR | File format.  One of: pcap (microsecond timestamps) or pcap-ns (nanosecond timestamps).
 * on_error         | Yes       | exit    | ::SC_PARAM_STR | What to do if an error is generated.  One of: exit, abort, message or silent.
 * append           | Yes       | 0       | ::SC_PARAM_INT | Set to 1 to append if file exists.  (Not compatible with file rotation).
 * rotate_seconds   | Yes       | 0       | ::SC_PARAM_INT | Rotate to a new file every n seconds.
 * rotate_file_size | Yes       | 0       | ::SC_PARAM_INT | Rotate to a new file when file exceeds given size in bytes.
 * snap             | Yes       | 0       | ::SC_PARAM_INT | Maximum number of bytes of packet data to store.  By default whole packets are stored.
 * sync_on_close    | Yes       | 0       | ::SC_PARAM_INT | Set to 1 to cause an fsync() when a file is closed.
 *
 * \namedinputlinks
 * Input links may be named, in which case the packets are forwarded to a matching named output link.
 *
 * \outputlinks
 * Link           | Description
 * -------------- | -----------------------------------
 *  ""            | Packets from all inputs are forwarded to this link.
 *  "#packed"     | Buffers containing the on-disk format are forwarded to this link (if they are generated).
 *  NAME          | If NAME matches the name of an input link, then input packets are forwarded to the corresponding output link.
 *
 * \internal
 * TODO: Need to add arg to control O_DIRECT and document it.
 * \endinternal
 *
 * \nodestatscopy{sc_writer}
 *
 * \cond NODOC
 */

/* This is needed for asprintf(). */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#include <sc_internal.h>
#include <sc_internal/builtin_nodes.h>
#include "sc_pcap.h"
#include "sc_writer.h"
#define SC_TYPE_TEMPLATE  <sc_writer_types_tmpl.h>
#define SC_DECLARE_TYPES  sc_writer_stats_declare
#include <solar_capture/declare_types.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/time.h>
#include <assert.h>
#include <limits.h>


#define WRITE_BLOCK      64
#define IO_BUF_LEN       (WRITE_BLOCK * 2)



/* Per-file state. */
struct writer_file {
  struct sc_dlist             link;

  struct sc_thread*          thread;
  char*                      filename_template;
  char*                      filename;
  int                        filename_len;

  enum ts_type               ts_type;
  int                        snap;
  int                        rotate_secs;
  int64_t                    rotate_file_size;
  int                        append;

  struct iovec               iovecs[IO_BUF_LEN];
  struct pcap_rec_hdr        hdrs[WRITE_BLOCK];
  int                        iovec_count;
  int                        hdr_count;
  int                        iovec_byte_count;
  int                        file_byte_count;
  int                        fd;
  int                        file_index;
  int                        refs;
  int                        error;
};


/* Per-node state.  Multiple nodes can share a single file.  This makes it
 * possible for packets from multiple interfaces to be written into a
 * single file.
 */
struct writer_node {
  struct sc_node*            node;
  struct writer_file*        file;
  const struct sc_node_link* next_hop;
  const struct sc_node_link* next_hop_after_error;
  enum on_error              on_error;
  struct sc_callback*        rotate_cb;
  struct sc_writer_stats*    stats;
};


/* List of open files. */
static struct sc_dlist writer_files;


static struct sc_session* wn_tg(struct writer_node* wn)
{
  return sc_thread_get_session(sc_node_get_thread(wn->node));
}


static void writer_error(struct writer_node* wn, int err)
{
  wn->file->error = errno;
  switch( wn->on_error ) {
  case ON_ERROR_EXIT:
    exit(1);
  case ON_ERROR_ABORT:
    abort();
  case ON_ERROR_MESSAGE:
  case ON_ERROR_SILENT:
    break;
  }
}


static void writer_flush(struct writer_node* wn)
{
  struct writer_file* st = wn->file;

  if( st->error == 0 && writev(st->fd, st->iovecs, st->iovec_count) < 0 ) {
    if( wn->on_error != ON_ERROR_SILENT )
      sc_err(wn_tg(wn), "sc_writer: ERROR: write to '%s' failed (%d %s)\n",
             st->filename, errno, strerror(errno));
    writer_error(wn, errno);
  }
  st->iovec_count = st->hdr_count = 0;
}


static inline void put_data(struct writer_node* wn, const void* data, unsigned len,
                     unsigned* bytes_left)
{
  struct writer_file* st = wn->file;

  if( bytes_left != NULL ) {
    if( len > *bytes_left )
      len = *bytes_left;
    *bytes_left -= len;
  }
  st->iovecs[st->iovec_count].iov_base = (void*) data;
  st->iovecs[st->iovec_count].iov_len = len;
  ++st->iovec_count;
  st->iovec_byte_count += len;
  st->file_byte_count += len;
  if( st->iovec_count == IO_BUF_LEN )
    writer_flush(wn);
}


static inline void put_iov(struct writer_node* wn, const struct iovec* iov,
                    unsigned* bytes_left)
{
  put_data(wn, iov->iov_base, iov->iov_len, bytes_left);
}


static inline int pcap_put_header(struct writer_node* wn, struct sc_packet* pkt)
{
  struct writer_file* st = wn->file;
  struct pcap_rec_hdr* h = &st->hdrs[st->hdr_count++];
  int incl_len = sc_packet_bytes(pkt);
  incl_len = (incl_len <= st->snap) ? incl_len : st->snap;
  h->ts_sec = pkt->ts_sec;
  h->ts_subsec = (st->ts_type == ts_micro) ?
    pkt->ts_nsec / 1000 : pkt->ts_nsec;
  h->incl_len = incl_len;
  h->orig_len = pkt->frame_len;
  put_data(wn, h, sizeof(*h), NULL);
  return incl_len;
}


static int sc_writer_open_file(struct writer_node* wn, int in_prep)
{
  struct writer_file* st = wn->file;

  if( st->rotate_secs ) {
    struct timespec ts;
    struct tm tm;
    sc_timer_get_expiry_time(wn->rotate_cb, &ts);
    strftime(st->filename, st->filename_len,
             st->filename_template, localtime_r(&ts.tv_sec, &tm));
  }
  else {
    strcpy(st->filename, st->filename_template);
  }

  if( st->rotate_file_size ) {
    char file_index_str[20];
    sprintf(file_index_str, "%d", st->file_index);
    ++st->file_index;

    char buf[st->filename_len];
    const char* needle = "$i";
    const char* p = strstr(st->filename, needle);
    if( p ) {
      memcpy(buf, st->filename, p - st->filename);
      buf[p - st->filename] = '\0';
      strcat(buf, file_index_str);
      strcat(buf, p + strlen(needle));
      strcpy(st->filename, buf);
    }
    else
      strcat(st->filename, file_index_str);
  }

  if( st->fd >= 0 ) {
    writer_flush(wn);
    close(st->fd);
  }

  int flags;
  if( st->append )
    flags = O_WRONLY | O_APPEND;  /* NB. don't create */
  else
    flags = O_WRONLY | O_CREAT | O_TRUNC;
 open_again:
  st->fd = open(st->filename, flags,
                S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);
  if( st->fd < 0 ) {
    if( errno == ENOENT && st->append ) {
      flags = O_WRONLY | O_CREAT | O_TRUNC;
      goto open_again;
    }
    if( wn->on_error != ON_ERROR_SILENT )
      sc_err(wn_tg(wn), "sc_writer: ERROR: failed to open(%s, %x) (%d,%s)\n",
             st->filename, flags, errno, strerror(errno));
    if( ! in_prep )
      writer_error(wn, errno);
    return -1;
  }

  /* Reset error flag so we can start writing again.  (To restart again
   * after error you obviously need to set on_error appropriately and be
   * using rotate_seconds).
    */
  st->error = 0;

  /* Possibly not correct if appending, but it doesn't really make sense to
   * append when rotating files...
   */
  st->file_byte_count = 0;

  if( flags & O_TRUNC ) {
    /* Write pcap header */
    struct pcap_file_hdr hdr = {
      .magic_number = st->ts_type == ts_micro? PCAP_MAGIC: PCAP_NSEC_MAGIC,
      /* As of 14-09-2012, according to libpcap-1.3.0 from www.tcpdump.org,
       * this is the current version of the pcap file format.  This is also
       * known to work with tcpdump on RHEL-6.2, tcpdump version
       * 4.1-PRE-CVS_2009_12_11, libpcap version 1.0.0.
       */
      .version_major = 2,
      .version_minor = 4,
      .thiszone = 0,
      .sigfigs = 0,
      .snap = st->snap,
      .network = 1,
    };
    put_data(wn, &hdr, sizeof(hdr), NULL);
    writer_flush(wn);
  }
  return 0;
}


static void sc_writer_on_rotate(struct sc_callback* cb, void* event_info)
{
  struct writer_node* wn = cb->cb_private;
  struct writer_file* st = wn->file;
  st->file_index = 0;
  if( sc_writer_open_file(wn, 0) == 0 )
    sc_timer_push_back_ns(cb, (int64_t) st->rotate_secs * 1000000000);
  else
    writer_error(wn, errno);
}


static void sc_writer_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct writer_node* wn = node->nd_private;
  struct writer_file* st = wn->file;
  struct sc_packet_list written;
  struct sc_packet* pkt;
  unsigned bytes_left;
  int i;
  sc_packet_list_init(&written);

  while( ! sc_packet_list_is_empty(pl) ) {
    if( st->rotate_file_size && st->file_byte_count >= st->rotate_file_size )
      if( sc_writer_open_file(wn, 0) < 0 ) {
        writer_error(wn, errno);
        goto out;
      }

    pkt = sc_packet_list_pop_head(pl);
    bytes_left = pcap_put_header(wn, pkt);
    wn->stats->link_bytes += pkt->frame_len;
    wn->stats->cap_bytes += bytes_left + sizeof(struct pcap_rec_hdr);
    for( i = 0; bytes_left && i < pkt->iovlen; ++i )
      put_iov(wn, &pkt->iov[i], &bytes_left);
    __sc_packet_list_append(&written, pkt);
  }

  if( st->iovec_count )
    writer_flush(wn);

 out:
  if( ! sc_packet_list_is_empty(&written) ) {
    sc_packet_list_finalise(&written);
    sc_forward_list(node, wn->next_hop, &written);
  }
  if( ! sc_packet_list_is_empty(pl) )
    sc_forward_list(node, wn->next_hop_after_error, pl);
}


static void sc_writer_end_of_stream(struct sc_node* node)
{
  struct writer_node* wn = node->nd_private;
  sc_node_link_end_of_stream(node, wn->next_hop);
  sc_node_link_end_of_stream(node, wn->next_hop_after_error);
}


static int sc_writer_prep(struct sc_node* node,
                          const struct sc_node_link*const* links, int n_links)
{
  struct writer_node* wn = node->nd_private;
  struct writer_file* st = wn->file;

  wn->next_hop = sc_node_prep_get_link_or_free(node, "");
  wn->next_hop_after_error = sc_node_prep_get_link(node, "after_error");
  if( wn->next_hop_after_error == NULL )
    wn->next_hop_after_error = wn->next_hop;
  if( sc_node_prep_check_links(node) < 0 )
    return -1;
  if( st->fd < 0 ) {
    /* We're the first node using this file. */
    if( st->rotate_secs )
      sc_timer_expire_after_ns(wn->rotate_cb, 0);
    if( sc_writer_open_file(wn, 1) < 0 )
      return -1;
    if( st->rotate_secs )
      sc_timer_push_back_ns(wn->rotate_cb,
                            (int64_t) st->rotate_secs * 1000000000);
  }
  return 0;
}


static int sc_writer_init(struct sc_node* node, const struct sc_attr* attr,
                          const struct sc_node_factory* factory)
{
  if( attr->legacy_writer != 1 )
    return sc_node_init_delegate(node, attr, &sc_perf_writer_sc_node_factory,
                                 NULL, -1);

  if( writer_files.next == NULL )
    sc_dlist_init(&writer_files);

  static struct sc_node_type* nt;
  if( nt == NULL ) {
    SC_TRY(sc_node_type_alloc(&nt, NULL, factory));
    nt->nt_pkts_fn = sc_writer_pkts;
    nt->nt_prep_fn = sc_writer_prep;
    nt->nt_end_of_stream_fn = sc_writer_end_of_stream;
  }
  sc_writer_stats_declare(sc_thread_get_session(sc_node_get_thread(node)));
  node->nd_type = nt;

  struct writer_file* st;
  st = sc_thread_calloc(sc_node_get_thread(node), sizeof(*st));
  st->thread = sc_node_get_thread(node);
  st->fd = -1;
  struct writer_node* wn;
  wn = sc_thread_calloc(st->thread, sizeof(*wn));
  wn->file = st;
  wn->node = node;
  node->nd_private = wn;

  const char* s;
  if( sc_node_init_get_arg_str(&s, node, "filename", NULL) < 0 )
    goto err;
  if( s == NULL ) {
    sc_node_set_error(node, EINVAL,
                      "%s: ERROR: required arg 'filename' missing\n", __func__);
    goto err;
  }
  st->filename_template = strdup(s);
  st->filename_len = strlen(st->filename_template) + 80;
  st->filename = malloc(st->filename_len);
  free(node->nd_name);
  SC_TEST(asprintf(&node->nd_name, "sc_writer(%s)", st->filename_template) > 0);

  if( sc_node_init_get_arg_str(&s, node, "format", "pcap") < 0 )
    goto err;
  if( ! ts_type_from_str(s, &st->ts_type) ) {
    sc_node_set_error(node, EINVAL, "%s: ERROR: bad format '%s'; expected one "
                      "of: pcap pcap-ns\n", __func__, s);
    goto err;
  }

  if( sc_node_init_get_arg_str(&s, node, "on_error", "exit") < 0 )
    goto err;
  if( ! on_error_from_str(s, &wn->on_error) ) {
    sc_node_set_error(node, EINVAL, "%s: ERROR: bad on_error '%s'; expected "
                      "one of: exit abort message silent\n", __func__, s);
    goto err;
  }

  if( sc_node_init_get_arg_int(&st->snap, node, "snap", 0)     < 0 ||
      sc_node_init_get_arg_int(&st->append, node, "append", 0) < 0 ||
      sc_node_init_get_arg_int(&st->rotate_secs, node,
                               "rotate_seconds", 0)            < 0 ||
      sc_node_init_get_arg_int64(&st->rotate_file_size, node,
                               "rotate_file_size", 0)          < 0  )
    goto err;
  if( st->snap == 0 )
    st->snap = MAX_SNAPLEN;
  else if( st->snap < 0 ) {
    sc_node_set_error(node, EINVAL, "%s: ERROR: bad snap %d; expected >= 0\n",
                      __func__, st->snap);
    goto err;
  }

  if( st->rotate_file_size < 0 )
    return sc_node_set_error(node, EINVAL,
                             "sc_writer: ERROR: rotate_file_size must "
                             "be >= 0\n");

  /* See if this file has already been opened. */
  struct writer_file* st2;
  SC_DLIST_FOR_EACH_OBJ(&writer_files, st2, link)
    if( ! strcmp(st->filename_template, st2->filename_template) ) {
      if( st2->thread != st->thread ) {
        sc_node_set_error(node, EINVAL, "%s: ERROR: file(%s) opened for "
                          "thread(%s) and thread(%s)\n", __func__,
                          st->filename_template, st2->thread->name,
                          st->thread->name);
        goto err;
      }
      if( st2->ts_type != st->ts_type                  ||
          st2->append != st->append                    ||
          st2->rotate_secs != st->rotate_secs          ||
          st2->rotate_file_size != st->rotate_file_size ) {
        sc_node_set_error(node, EINVAL, "%s: ERROR: file(%s) opened with "
                          "conflicting options\n", __func__,
                          st->filename_template);
        goto err;
      }
      free(st->filename_template);
      free(st->filename);
      sc_thread_mfree(st->thread, st);
      st = st2;
      ++(st->refs);
      wn->file = st;
      goto success;
    }

  /* New file. */
  if( st->rotate_secs ) {
    SC_TEST(sc_callback_alloc(&wn->rotate_cb, attr, st->thread) == 0);
    wn->rotate_cb->cb_private = wn;
    wn->rotate_cb->cb_handler_fn = sc_writer_on_rotate;
  }
  sc_dlist_push_head(&writer_files, &st->link);
 success:
  sc_node_export_state(node, "sc_writer_stats",
                       sizeof(struct sc_writer_stats), &wn->stats);
  sc_node_add_info_str(node, "filename", st->filename_template);
  return 0;

 err:
  free(st->filename_template);
  free(st->filename);
  sc_thread_mfree(sc_node_get_thread(node), wn);
  sc_thread_mfree(sc_node_get_thread(node), st);
  return -1;
}


const struct sc_node_factory sc_writer_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_writer",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_writer_init,
};

/** \endcond NODOC */
