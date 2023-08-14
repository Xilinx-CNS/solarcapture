/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/** \cond NODOC
 *
 * NB. Doxygen documentation is in sc_writer.c.  We expect users to
 * instantiate these nodes via sc_writer.
 *
 * This file implements a high performance writer. On initialisation, up to
 * four nodes are created.
 *
 *       ^
 *       |
 * SC_PERF_WRITER  - - > SC_PCAP_PACKER -> SC_DISK_WRITER -> SC_FWD_EOS
 *
 * sc_perf_writer and sc_disk_writer are implemented in this file.
 *
 * sc_perf_writer forwards packets along the normal path, but before doing so,
 * calls into sc_pcap_packer to create packed pcap buffers. These are then
 * forwarded to the disk_writer and fwd_eos nodes.
 * Since disk writing is now happening outside the normal packet stream, end
 * of stream notifications need to be handled in a special way. On
 * initialisation, sc_perf_writer passes its outgoing link to sc_fwd_eos.
 * On receiving an end of stream notification, instead of passing it on as
 * normal, sc_perf_writer invokes an end of stream handler on sc_pcap_packer.
 * Once EOS propagates to sc_fwd_eos, it is linked back to the node that
 * follows sc_perf_writer.
 *
 * sc_disk_writer can operate in one of two modes: sync and async.
 * Common functionality is in sc_disk_writer_ functions, while mode specific
 * functions are named sc_async_writer_ and sc_sync_writer_
 *
 */

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif
#include <inttypes.h>
#include <sc_internal.h>
#include <sc_internal/builtin_nodes.h>
#include <solar_capture/nodes/subnode_helper.h>
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
#include <dlfcn.h>
#include <dirent.h>
#include <libaio.h>

#define MAX_SUBMIT 128
#define MAX_REAP   128
#define N_IOS      512

#define ALLOC_STRIDE (64*1024*1024)
#define WC_SIZE      (4096)


enum writer_state {
  WS_RUN,            /*  Running and submitting writes */
  WS_DRAIN_WC,       /*  Waiting for submitted IOs to complete before the WC
                          buffer can be reused */
  WS_DRAIN_ROTATE,   /*  Waiting for submitted IOs to complete before emitting
                          filename (if required) */
  WS_EMIT_FILENAME,  /*  Waiting till filename has been emitted before moving
                          on to next file */
};


/* Per-file state. */
struct perf_writer_file {
  struct sc_dlist            link;

  struct sc_node*            perf_writer;
  struct sc_node*            disk_writer;
  struct sc_node*            pcap_packer;
  struct sc_node*            eos_fwd;

  struct sc_thread*          thread;
  struct sc_subnode_helper*  snh_postrotate;
  char*                      filename_template;
  char*                      filename_next;
  char*                      filename_current;
  char*                      filename_final;
  char*                      filename_rotated;
  char*                      partial_suffix;
  int                        filename_len;

  int                        rotate_secs;
  int64_t                    rotate_file_size;
  int                        rotate_file_pad;
  int                        append;
  uint64_t                   file_size;
  uint64_t                   file_write_offset;

  int                        fd;
  int                        refs;
  int                        error;

  /* Async specific state */
  struct sc_dlist            submitted_async_ios;
  uint64_t                   alloc_till;
  enum writer_state          writer_state;
  unsigned                   wc_fill;
  void*                      wc_buffer;
  unsigned                   pkt_base_offset;
};


/* Each async io request will be for at most a single packet.  Currently the
 * assumption is that each packet only has a single iov to write.  This is true
 * since this node ensures that packets are coming via an sc_pcap_packer.
 */
struct sc_async_io {
  struct sc_dlist link;
  struct iocb iocb;
  struct sc_packet* pkt;
};


/* Per-node state.  Multiple nodes can share a single file.  This makes it
 * possible for packets from multiple interfaces to be written into a
 * single file.
 */
struct disk_writer_node {
  struct sc_node*              node;
  struct perf_writer_file*     file;
  struct sc_packet_list        write_backlog;
  const struct sc_node_link*   next_hop;
  const struct sc_node_link*   next_hop_after_error;
  struct sc_callback*          backlog_cb;
  struct sc_callback*          postrotate_cb;
  enum on_error                on_error;
  struct sc_disk_writer_stats* stats;
  bool                         async;
  bool                         first_time;
  bool                         sync_on_close;
  /* Async specific state */
  struct sc_dlist              free_async_ios;
  io_context_t                 io_ctx;
};


struct perf_writer_node {
  struct sc_node*            node;
  struct perf_writer_file*   file;
  struct sc_writer_stats*    stats;
  struct sc_attr*            attr;
  char**                     link_names;
  unsigned                   n_links;
  bool                       all_out_link_added;
  bool                       named_out_link_added;
  bool                       owns_file;
  bool                       eos_pending;
};


static int sc_disk_writer_open_file(struct disk_writer_node* wn, bool in_prep,
                                    bool first_time);
static void sc_disk_writer_first_open(struct disk_writer_node* wn);

static void sc_async_writer_submit_wc_buffer(struct sc_node* node);

/* List of open files. */
static struct sc_dlist writer_files;
static int (*fallocate_fn)(int, int, off_t, off_t);

static struct sc_session* wn_tg(struct disk_writer_node* wn)
{
  return sc_thread_get_session(sc_node_get_thread(wn->node));
}


static void writer_set_last_error(struct disk_writer_node* wn,
                                  int err, const char* func)
{
  wn->stats->last_error = err;
  sc_stats_set_str(wn->stats->error_func, func);
}


static int writer_error(struct disk_writer_node* wn, bool in_prep,
                        const char* func, const char* fmt, ...)
  __attribute__((format(printf,4,5)));

static int writer_error(struct disk_writer_node* wn, bool in_prep,
                        const char* func, const char* fmt, ...)
{
  if( wn->on_error != ON_ERROR_SILENT ) {
    va_list va;
    va_start(va, fmt);
    if( in_prep )
      sc_node_set_errorv(wn->node, errno, fmt, va);
    else
      sc_errv(wn_tg(wn), fmt, va);
    va_end(va);
  }
  wn->file->error = errno;
  wn->stats->current_error = errno;
  writer_set_last_error(wn, errno, func);
  switch( wn->on_error ) {
  case ON_ERROR_EXIT:
    exit(1);
  case ON_ERROR_ABORT:
    abort();
  case ON_ERROR_MESSAGE:
  case ON_ERROR_SILENT:
    break;
  }
  return -1;
}


static void writer_update_stats(struct disk_writer_node* wn)
{
  wn->stats->writer_state = wn->file->writer_state;
  wn->stats->backlog_pkts = wn->write_backlog.num_pkts;
  wn->stats->wc_fill = wn->file->wc_fill;
  wn->stats->pkt_base_offset = wn->file->pkt_base_offset;
  if( wn->stats->backlog_pkts ) {
    struct sc_packet* pkt = wn->write_backlog.head;
    wn->stats->head_iov_len = pkt->iov[0].iov_len;
    wn->stats->head_flags = pkt->flags;
  }
  else {
    wn->stats->head_iov_len = -1;
    wn->stats->head_flags = -1;
  }
}


/* emit name of file just rotated out */
static void
sc_disk_writer_emit_postrotate_filename(struct disk_writer_node* wn)
{
  struct perf_writer_file* st = wn->file;
  SC_TEST(st->writer_state == WS_EMIT_FILENAME);
  if( !st->snh_postrotate ) {
    st->writer_state = WS_RUN;
    return;
  }

  struct sc_packet_list pl;
  __sc_packet_list_init(&pl);
  if( sc_pool_get_packets(&pl, st->snh_postrotate->sh_pool, 1, 1) != 1 ) {
    sc_pool_on_threshold(st->snh_postrotate->sh_pool,
                         wn->postrotate_cb, 1);
    return;
  }
  struct sc_packet* pkt = pl.head;
  SC_TEST( pkt->iov[0].iov_len > strlen(st->filename_rotated) );
  strcpy(pkt->iov[0].iov_base, st->filename_rotated);
  /* Including null termination in length */
  pkt->iov[0].iov_len = strlen(st->filename_rotated) + 1;
  pkt->frame_len = strlen(st->filename_rotated) + 1;
  pkt->iovlen = 1;
  sc_forward2(st->snh_postrotate->sh_links[0], pkt);
  st->writer_state = WS_RUN;
}


static void sc_disk_writer_postrotate_cb(struct sc_callback* cb,
                                         void * event_info)
{
  struct sc_node* node = cb->cb_private;
  struct disk_writer_node* wn = node->nd_private;
  sc_disk_writer_emit_postrotate_filename(wn);
  writer_update_stats(wn);
}


static void sc_async_writer_switch_file(struct disk_writer_node* wn)
{
  struct perf_writer_file* st = wn->file;

  ftruncate(st->fd, st->file_write_offset);
  st->file_size = st->file_write_offset;
  /* Filename for next file was set when submitting last request for
   * current file. So we can go ahead and open it.
   */
  sc_disk_writer_open_file(wn, 0, false);
  /* Cannot go straight to WS_RUN since emit_postrotate_filename may run
   * out of buffers.
   */
  st->writer_state = WS_EMIT_FILENAME;
  sc_disk_writer_emit_postrotate_filename(wn);
}


static void sc_async_writer_reap(struct sc_node* node, int min_events)
{
  struct disk_writer_node* wn = node->nd_private;
  struct perf_writer_file* st = wn->file;
  struct io_event events[MAX_REAP];
  struct sc_packet_list reaped_pkts;
  int num_events;
  int i;
  struct sc_async_io* async_io;
  sc_packet_list_init(&reaped_pkts);

  num_events = io_getevents(wn->io_ctx, min_events, MAX_REAP, events,
                            NULL);
  SC_TEST( num_events >= 0 );

  for( i = 0; i < num_events; i++ ) {
    async_io = (struct sc_async_io*)events[i].data;
    if( (int64_t) events[i].res < 0 ) { /* res is actually unsigned (!!) */
      writer_error(wn, false, "reap", "sc_async_writer: ERROR: async write "
                   "failed rc=%ld (%s)\n", events[i].res,
                   strerror(-events[i].res));
    }
    if( async_io->pkt )
      sc_packet_list_append(&reaped_pkts, async_io->pkt);
    /* Removing async_io from submitted list for file and returning to free list */
    sc_dlist_remove(&async_io->link);
    sc_dlist_push_head(&wn->free_async_ios, &async_io->link);
    --wn->stats->in_flight_ios;
  }

  /* If we're waiting on a file rotate we may have an outstanding WC
   * buffer to flush if there were no free IOs when we received the
   * rotate request. */
  if( num_events > 0 && st->writer_state == WS_DRAIN_ROTATE && st->wc_fill > 0 )
    sc_async_writer_submit_wc_buffer(node);

  if( sc_dlist_is_empty(&st->submitted_async_ios) ) {
    if( st->writer_state == WS_DRAIN_WC ) {
      ftruncate(st->fd, st->file_write_offset);
      st->file_size = st->file_write_offset;
      st->writer_state = WS_RUN;
    }
    else if( st->writer_state == WS_DRAIN_ROTATE ) {
      sc_async_writer_switch_file(wn);
     }
   }

  if( !sc_packet_list_is_empty(&reaped_pkts) ) {
    wn->stats->in_flight_pkts -= reaped_pkts.num_pkts;
    sc_forward_list(node, wn->next_hop, &reaped_pkts);
  }
}


static void sc_sync_writer_write_pkt(struct disk_writer_node* wn, struct sc_packet * pkt)
{
  struct perf_writer_file* st = wn->file;
  struct perf_writer_node* pn = st->perf_writer->nd_private;
  /* Since this node redirects all incoming links via an sc_pcap_packer node,
   * we know that only iov[0] will contain any data.
   */
  assert(pkt->iovlen == 1);
  if( st->error == 0 ) {
    ssize_t len = pkt->iov[0].iov_len;
    ssize_t rc = write(st->fd, pkt->iov[0].iov_base, len);
    if( rc < len ) {
      writer_error(wn, false, "write", "sc_sync_writer: ERROR: write to '%s' "
                   "failed len=%zu rc=%zd errno=%d (%s)\n", st->filename_current,
                   len, rc, errno, strerror(errno));
      if( rc < 0 )
        rc = 0;
    }
    pn->stats->write_bytes += rc;
    st->file_write_offset = st->file_write_offset + rc;
  }
}


static int sc_create_dirs(struct disk_writer_node* wn, const char* filename_in,
                          bool in_prep)
{
  char* filename = strdup(filename_in);
  int rc = 0;
  SC_TEST( filename != NULL );
  char* slash = strchr(filename + 1, '/'); /* skip starting / if there is one */
  while( slash != NULL ) {
    *slash = '\0';
    rc = mkdir(filename, (S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|
                          S_IWGRP|S_IXGRP|S_IROTH|S_IWOTH|S_IXOTH));
    *slash = '/';
    if( rc < 0 && errno != EEXIST ) {
      rc = writer_error(wn, in_prep, "mkdir", "sc_perf_writer: ERROR: failed "
                        "to create directory '%s'\n", filename);
      break;
    }
    rc = 0;
    slash = strchr(slash + 1, '/');
  }
  free(filename);
  return rc;
}


static void sc_disk_writer_close_file(struct disk_writer_node* wn)
{
  struct perf_writer_file* st = wn->file;

  DIR* dirp;
  if( wn->sync_on_close ) {
    if( fsync(st->fd) != 0 )
      goto err_1;
    /* syncing the entry in the directory as well */
    char* end = strrchr(st->filename_final, '/');
    if( end == NULL ) {
      dirp = opendir(".");
    }
    else if( end == st->filename_final ) {
      dirp = opendir("/");
    }
    else {
      *end = '\0';
      dirp = opendir(st->filename_final);
      *end = '/';
    }
    if( dirp == NULL )
      goto err_1;
    int dfd;
    if( (dfd = dirfd(dirp)) == -1 ||
        fsync(dfd) == -1 )
      goto err_2;
    closedir(dirp);
  }
 out:
  close(st->fd);
  st->fd = -1;
  if( st->partial_suffix[0] ) {
    int rc = rename(st->filename_current, st->filename_final);
    if( rc < 0 )
      writer_error(wn, false, "rename", "sc_perf_writer: ERROR: rename(%s, %s) "
                   "failed (%d %s)\n", st->filename_current, st->filename_final,
                   errno, strerror(errno));
  }
  return;

 err_2:
  closedir(dirp);
 err_1:
  if( wn->on_error != ON_ERROR_SILENT )
    sc_err(wn_tg(wn), "sc_writer: ERROR: fsync when closing '%s'"
           "failed (%d %s)\n", st->filename_current, errno, strerror(errno));
  goto out;
}


static int sc_disk_writer_open_file(struct disk_writer_node* wn, bool in_prep,
                                    bool first_time)
{
  /* If in_prep is true then we set an SC error; otherwise we just log
   * errors via sc_err() (depending on the on_error arg).
   *
   * NB. At time of writing in_prep can never be true, but I've kept it in
   * case useful in future.
   */
  struct perf_writer_file* st = wn->file;
  SC_TEST( ! in_prep || first_time );
  SC_TEST( ! st->append || wn->async == 0 );

  if( st->fd >= 0 )
    sc_disk_writer_close_file(wn);

  st->file_write_offset = 0;
  st->file_size = 0;
  sc_dlist_init(&st->submitted_async_ios);

  /* Create the dirs */
  if( sc_create_dirs(wn, st->filename_next, in_prep) != 0 )
    return -1;

  /* Create the file */
  int flags;
  if( st->append )
    flags = O_WRONLY | O_APPEND;  /* NB. don't create just append */
  else
    flags = O_WRONLY | O_CREAT | O_TRUNC;

  if( wn->async )
    flags |= O_DIRECT;

 open_again:
  strcpy(st->filename_final, st->filename_next);
  sprintf(st->filename_current, "%s%s", st->filename_final, st->partial_suffix);
  st->fd = open(st->filename_current, flags,
                S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);
  if( st->fd < 0 ) {
    writer_set_last_error(wn, errno, "open");
    if( errno == ENOENT && st->append ) {
      flags = O_WRONLY | O_CREAT | O_TRUNC;
      goto open_again;
    }
    if( first_time && errno == EINVAL && wn->async ) {
      wn->async = false;
      flags &= ~O_DIRECT;
      goto open_again;
    }
    return writer_error(wn, in_prep, "open", "sc_perf_writer: ERROR: failed to "
                        "open(%s, %x) (%d %s)\n", st->filename_current, flags,
                        errno, strerror(errno));
  }

  if( wn->async ) {
    if( fallocate_fn != NULL &&
        fallocate_fn(st->fd, 0, 0, ALLOC_STRIDE) != 0) {
      close(st->fd);
      st->fd = -1;
      if( first_time ) {
        sc_trace(wn_tg(wn), "%s: fallocate() for '%s' failed (%d %s)\n",
                 __func__, st->filename_current, errno, strerror(errno));
        wn->async = false;
        flags &= ~O_DIRECT;
        writer_set_last_error(wn, errno, "fallocate");
        goto open_again;
      }
      else {
        return writer_error(wn, in_prep, "fallocate", "sc_perf_writer: ERROR: "
                            "fallocate() failed for '%s' (%d %s)\n",
                            st->filename_current, errno, strerror(errno));
      }
    }
    st->file_size  = ALLOC_STRIDE;
    st->alloc_till = ALLOC_STRIDE;
  }
  /* Reset error flag so we can start writing again.  (To restart again
   * after error you obviously need to set on_error appropriately and be
   * using file rotation).
   */
  st->error = 0;
  wn->stats->current_error = 0;
  return 0;
}


static void sc_async_writer_submit_wc_buffer(struct sc_node* node)
{
  struct disk_writer_node* wn = node->nd_private;
  struct perf_writer_file* st = wn->file;
  SC_TEST( ! sc_dlist_is_empty(&wn->free_async_ios) );
  struct sc_async_io* async_io =
    SC_CONTAINER(struct sc_async_io, link,
                 sc_dlist_pop_head(&wn->free_async_ios));
  ++wn->stats->in_flight_ios;
  async_io->pkt = NULL;
  io_prep_pwrite(&async_io->iocb, st->fd, st->wc_buffer,
                 WC_SIZE, st->file_write_offset);
  st->file_write_offset = st->file_write_offset + st->wc_fill;
  async_io->iocb.data = async_io;
  st->wc_fill = 0;
  sc_dlist_push_tail(&st->submitted_async_ios, &async_io->link);
  struct iocb *iocbs_to_submit[1];
  iocbs_to_submit[0] = &async_io->iocb;
  int rc = io_submit(wn->io_ctx, 1, iocbs_to_submit);
  if( rc != 1 ) {
    errno = -rc;
    writer_error(wn, false, "io_submit", "sc_perf_writer: ERROR: io_submit "
                 "failed for '%s' (rc=%d)\n", st->filename_current, rc);
  }
}


static void sc_async_writer_handle_rotate(struct sc_node* node, struct sc_packet* pkt)
{
  struct disk_writer_node* wn = node->nd_private;
  struct perf_writer_file* st = wn->file;

  /* We can safely set the filename for the next file to be opened because
   * we will not consume any incoming packets until it is used.
   */
  SC_TEST(pkt->metadata != NULL);
  strcpy(st->filename_rotated, st->filename_next);
  strcpy(st->filename_next, (const char*) pkt->metadata);
  free(pkt->metadata);

  /* NOTE: If we are unable to submit the WC now, we will
   * do so in sc_async_writer_reap once we have a free IO */
  if( st->wc_fill && ! sc_dlist_is_empty(&wn->free_async_ios) )
    sc_async_writer_submit_wc_buffer(node);

  /* If we have any outstanding IOs we must wait for them to
   * complete before we can switch to a new output file. */
  if( sc_dlist_is_empty(&st->submitted_async_ios) )
    sc_async_writer_switch_file(wn);
  else
    st->writer_state = WS_DRAIN_ROTATE;
}


static void sc_async_writer_copy_to_wc_buffer(struct perf_writer_file* st,
                                              void* src, size_t len)
{
  SC_TEST( st->writer_state == WS_RUN );
  SC_TEST(st->wc_fill + len <= WC_SIZE);
  memcpy((char*)st->wc_buffer + st->wc_fill, src, len);
  st->wc_fill += len;
}


static void sc_async_writer_submit_list(struct sc_node* node,
                                        struct sc_packet_list* pl)
{
  struct disk_writer_node* wn = node->nd_private;
  struct perf_writer_file* st = wn->file;
  struct perf_writer_node* pn = st->perf_writer->nd_private;
  int n_reqs = 0;
  struct iocb *iocbs_to_submit[MAX_SUBMIT];

  if( ((int64_t)(st->file_write_offset) > (int64_t)st->file_size - ALLOC_STRIDE/8 )) {
    st->alloc_till = ALIGN_FWD(st->file_size + 1, ALLOC_STRIDE);
    fallocate_fn(st->fd, 0, st->file_size, st->alloc_till - st->file_size);
    st->file_size = st->alloc_till;
  }
  while( ! sc_packet_list_is_empty(pl) &&
         n_reqs < MAX_SUBMIT &&
         ! sc_dlist_is_empty(&wn->free_async_ios) ) {
    /* Only writing the first iov for the packet. The reap logic relies on this
     * being true. Since this node redirects all incoming links via an
     * sc_pcap_packer node, we know that only iov[0] will contain any data.
     */
    struct sc_packet* pkt = sc_packet_list_pop_head(pl);
    assert(pkt->iovlen == 1);
    if( st->wc_fill ) {
      /* we have stuff to write out before the current packet */
      if( pkt->iov[0].iov_len - st->pkt_base_offset <= (WC_SIZE - st->wc_fill) ) {
        /* current packet fits entirely in WC buffer. Copy and free */
        sc_async_writer_copy_to_wc_buffer(st,(char*)pkt->iov[0].iov_base + st->pkt_base_offset,
                                          pkt->iov[0].iov_len);
        st->pkt_base_offset = 0;
        if( pkt->flags & SC_FILE_ROTATE ) {
          sc_async_writer_handle_rotate(node, pkt);
          sc_forward(node, wn->next_hop, pkt);
          break;
        }
        else {
          sc_forward(node, wn->next_hop, pkt);
          continue;
        }
      }
      else {
        /* packet is larger than WC buffer. We need to copy the start of the
         * packet to the WC buffer and issue a write
         */
        int old_fill = st->wc_fill;
        sc_async_writer_copy_to_wc_buffer(st, (char*)pkt->iov[0].iov_base +
                                          st->pkt_base_offset,
                                          WC_SIZE - st->wc_fill);
        st->pkt_base_offset = WC_SIZE - old_fill;
        /* We haven't copied the entire packet, so pushing it back onto the
         * backlog
         */
        sc_packet_list_push_head(pl, pkt);
        sc_async_writer_submit_wc_buffer(node);
        /* We cannot reuse the WC buffer until the write
         * of its current contents has completed */
        st->writer_state = WS_DRAIN_WC;
        break;
      }
    }
    SC_TEST(st->wc_fill == 0);
    int write_size = pkt->iov[0].iov_len - st->pkt_base_offset;
    int packet_tail = write_size % WC_SIZE;
    write_size -= packet_tail;
    if( packet_tail ) {
      SC_TEST(st->writer_state == WS_RUN);
      /* Partial packet. We need to copy to wc buffer */
      SC_TEST(st->wc_fill == 0);
      sc_async_writer_copy_to_wc_buffer(st, (char*)pkt->iov[0].iov_base +
                                        st->pkt_base_offset + write_size,
                                        packet_tail);
      SC_TEST(st->wc_fill == packet_tail);
    }
    if( write_size > 0 ) {
      struct sc_async_io* async_io =
        SC_CONTAINER(struct sc_async_io, link,
                     sc_dlist_pop_head(&wn->free_async_ios));
      async_io->pkt = pkt;
      SC_TEST(((uintptr_t)pkt->iov[0].iov_base +
               st->pkt_base_offset) % 4096 == 0);
      SC_TEST((write_size % 4096) == 0);
      io_prep_pwrite(&async_io->iocb, st->fd,
                     (char*)async_io->pkt->iov[0].iov_base + st->pkt_base_offset,
                     write_size, st->file_write_offset);
      async_io->iocb.data = async_io;
      pn->stats->write_bytes += write_size;
      st->file_write_offset = st->file_write_offset + write_size;
      iocbs_to_submit[n_reqs] = &async_io->iocb;
      sc_dlist_push_tail(&st->submitted_async_ios, &async_io->link);
      n_reqs++;
    }
    st->pkt_base_offset = 0;

    if( pkt->flags & SC_FILE_ROTATE ) {
      sc_async_writer_handle_rotate(node, pkt);
      if( write_size == 0 ) /* Entire packet has been copied to wc buffer */
        sc_forward(node, wn->next_hop, pkt);
      break;
    }
    if( write_size == 0 ) /* Entire packet has been copied to wc buffer */
      sc_forward(node, wn->next_hop, pkt);
  }

  if( n_reqs > 0 ) {
    wn->stats->in_flight_ios += n_reqs;
    wn->stats->in_flight_pkts += n_reqs;
    int rc = io_submit(wn->io_ctx, n_reqs, iocbs_to_submit);
    if( rc != n_reqs ) {
      errno = -rc;
      writer_error(wn, false, "io_submit", "sc_perf_writer: ERROR: io_submit "
                   "failed for '%s' (rc=%d)\n", st->filename_current, rc);
    }
  }
}


/* Submit write requests for up to MAX_SUBMIT packets from the backlog every
 * time the callback is invoked in async mode.
 */
static void sc_async_writer_backlog_cb(struct sc_callback* cb,
                            void * event_info)
{
  struct sc_node* node = cb->cb_private;
  struct disk_writer_node* wn = node->nd_private;
  struct perf_writer_file* st = wn->file;

  if( !sc_dlist_is_empty(&st->submitted_async_ios) )
    sc_async_writer_reap(node, 0);

  if( !sc_packet_list_is_empty(&wn->write_backlog) &&
      st->writer_state == WS_RUN )
    sc_async_writer_submit_list(node, &wn->write_backlog);

  /* If we have writes to submit, schedule as soon as possible, but if we're
   * only waiting to reap completions, we can wait longer.
   */
  if( !sc_packet_list_is_empty(&wn->write_backlog) )
    sc_timer_expire_after_ns(wn->backlog_cb, 1);
  else if( !sc_dlist_is_empty(&st->submitted_async_ios) )
    sc_timer_expire_after_ns(wn->backlog_cb, 1000*1000);
  writer_update_stats(wn);
}


void sc_sync_writer_backlog_batch(struct sc_node* node, int batch_size)
{
  struct sc_packet_list written;
  struct sc_packet* pkt;
  sc_packet_list_init(&written);
  int n=0;
  struct disk_writer_node* wn = node->nd_private;
  struct perf_writer_file* st = wn->file;
  while( st->writer_state == WS_RUN &&
         n < batch_size && !sc_packet_list_is_empty(&wn->write_backlog) ) {
    pkt = sc_packet_list_pop_head(&wn->write_backlog);
    sc_sync_writer_write_pkt(wn, pkt);
    if( pkt->flags & SC_FILE_ROTATE ) {
      SC_TEST(pkt->metadata != NULL);
      strcpy(st->filename_rotated, st->filename_next);
      strcpy(st->filename_next, (const char*) pkt->metadata);
      free(pkt->metadata);
      if( sc_disk_writer_open_file(wn, false, false) < 0 )
        goto out;
      /* emit_postrotate_filename may run out of buffers.
       */
      st->writer_state = WS_EMIT_FILENAME;
      sc_disk_writer_emit_postrotate_filename(wn);
    }
    __sc_packet_list_append(&written, pkt);
    n++;
  }

 out:
  if( ! sc_packet_list_is_empty(&written) ) {
    sc_packet_list_finalise(&written);
    sc_forward_list(node, wn->next_hop, &written);
  }

}


/* Write one packet from the backlog to disk everytime the callback is invoked
 * in sync mode.
 */
static void sc_sync_writer_backlog_cb(struct sc_callback* cb,
                            void * event_info)
{
  struct sc_node* node = cb->cb_private;
  struct disk_writer_node* wn = node->nd_private;
  sc_sync_writer_backlog_batch(node, 1);
  if( !sc_packet_list_is_empty(&wn->write_backlog) )
    sc_timer_expire_after_ns(wn->backlog_cb,1);
  writer_update_stats(wn);
}


/* When packets are received, we add them to the backlog and schedule a callback
 * to handle the backlog. The callback is handled by the appropriate function
 * depending on the mode.
 */
void sc_disk_writer_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct disk_writer_node* wn = node->nd_private;
  struct perf_writer_file* st = wn->file;

  if( wn->first_time) {
    /* The first packet received from sc_pcap_packer will be empty and will
     * contain the name for the file to be written.
     */
    SC_TEST(pl->head->iovlen == 0);
    SC_TEST(pl->head->flags & SC_FILE_ROTATE);
    SC_TEST(pl->head->metadata != NULL);
    strcpy(st->filename_next, (const char*) pl->head->metadata);
    free(pl->head->metadata);
    sc_disk_writer_first_open(wn);
    wn->first_time = false;
    struct sc_packet* pkt = sc_packet_list_pop_head(pl);
    sc_forward(node, wn->next_hop, pkt);
  }

  if( !sc_packet_list_is_empty(pl) )
    sc_packet_list_append_list(&wn->write_backlog, pl);

  if( !sc_packet_list_is_empty(&wn->write_backlog) )
    sc_timer_expire_after_ns(wn->backlog_cb,1);

  writer_update_stats(wn);
}


void sc_disk_writer_end_of_stream(struct sc_node* node)
{
  struct disk_writer_node* wn = node->nd_private;
  struct perf_writer_file* st = wn->file;

  if( wn->async ) {
    /* Keep submitting writes until we get through backlog */
    while( ! sc_packet_list_is_empty(&wn->write_backlog) ) {
      sc_async_writer_reap(node, 0);
      SC_TEST(wn->write_backlog.head->iov[0].iov_len > 0);
      if( st->writer_state == WS_RUN )
        sc_async_writer_submit_list(node,&wn->write_backlog);
      writer_update_stats(wn);
    }

    /* Tidy up file before exiting */
    if( st->wc_fill ) {
      /* We may need to wait for an IO to free up
       * before we can submit the WC buffer */
      if( sc_dlist_is_empty(&wn->free_async_ios) )
        sc_async_writer_reap(node, 1);
      sc_async_writer_submit_wc_buffer(node);
    }

    /* Reap until file has no outstanding requests */
    while( !sc_dlist_is_empty(&st->submitted_async_ios) ) {
      sc_async_writer_reap(node, 1);
      writer_update_stats(wn);
    }
    ftruncate(st->fd, st->file_write_offset);
  } else {
    if( !sc_packet_list_is_empty(&wn->write_backlog) )
      sc_sync_writer_backlog_batch(node, wn->write_backlog.num_pkts);
  }
  sc_disk_writer_close_file(wn);
  writer_update_stats(wn);
  sc_node_link_end_of_stream(node, wn->next_hop);
  sc_node_link_end_of_stream(node, wn->next_hop_after_error);
}


static void sc_disk_writer_first_open(struct disk_writer_node* wn)
{
  struct perf_writer_file* st = wn->file;

  if( sc_disk_writer_open_file(wn, false, true) < 0 )
    return;

  struct stat f_stat;
  if( fstat( st->fd, &f_stat) ) {
    writer_error(wn, false, "sc_perf_writer: ERROR: fstat(%s) failed (%d %s)\n",
                 st->filename_current, errno, strerror(errno));
    return;
  }

  /* If file is appended to, and is not empty to start with, then we have to
   * tell the pcap packer not to generate a file header for the first buffer
   */
  st->file_write_offset = st->append ? f_stat.st_size : 0;
  sc_pcap_packer_set_file_byte_count(st->pcap_packer, st->file_write_offset);

  /* If file isn't a regular file or io_setup fails, do not use
   * async writes.
   */
  int rc = 0, n_concurrent_ios = N_IOS;
  if( wn->async && ( ! S_ISREG(f_stat.st_mode) ||
                     (rc = io_setup(n_concurrent_ios, &wn->io_ctx)) != 0 ) ) {
    sc_trace(wn_tg(wn), "%s: isreg=%d io_setup=%d\n", __func__,
             !!S_ISREG(f_stat.st_mode), rc);
    wn->async = false;
    if( S_ISREG(f_stat.st_mode) )
      writer_set_last_error(wn, -rc, "io_setup");
    /* Re-open the file without O_DIRECT. */
    if( sc_disk_writer_open_file(wn, false, true) < 0 )
      return;
  }

  if( wn->async ) {
    /* Redundantly initialise this pointer to prevent a compiler warning
     * on gcc 4.9.2.
     * (The init is redundant because posix_memalign will initialise it
     * or SC_TRY will abort). */
    void* async_ios = 0;
    int i;
    sc_dlist_init(&wn->free_async_ios);
    wn->stats->n_ios = n_concurrent_ios;
    SC_TEST( posix_memalign(&async_ios, 4096,
                            sizeof(struct sc_async_io) * n_concurrent_ios)
             == 0 );
    SC_TEST( posix_memalign(&st->wc_buffer, 4096, WC_SIZE) == 0 );
    for( i=0; i<n_concurrent_ios; i++) {
      struct sc_dlist* link = &((struct sc_async_io*)
                                ((char*)async_ios +
                                 sizeof(struct sc_async_io)*i))->link;
      sc_dlist_init(link);
      sc_dlist_push_head(&wn->free_async_ios, link);
    }
    wn->backlog_cb->cb_handler_fn = sc_async_writer_backlog_cb;
  }
  else {
    wn->backlog_cb->cb_handler_fn = sc_sync_writer_backlog_cb;
  }
  wn->stats->async_mode = wn->async;
}


static int sc_check_path(struct sc_node* node, const char* full_path,
                         char* start_point)
{
  /* It is conventional to treat multiple '/' as single '/'. */
  while( start_point[0] == '/' )
    ++start_point;
  if( start_point[0] == '\0' )
    return sc_node_set_error(node, EINVAL, "sc_perf_writer: ERROR: bad file "
                             "path '%s'\n", full_path);

  char* slash = strchr(start_point, '/');
  if( slash == NULL ) {
    /* Check file part */
    if( euidaccess(full_path, W_OK) < 0 ) {
      if( errno != ENOENT )
        /* File exists but we don't have write permission, probably. */
        return sc_node_set_error(node, errno, "sc_perf_writer: ERROR: cannot "
                                 "write to '%s'\n", full_path);
      /* File doesn't exist; check we can create. */
      int fd = open(full_path, O_WRONLY | O_CREAT,
                    S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);
      if( fd < 0 )
        return sc_node_set_error(node, errno, "sc_perf_writer: ERROR: could "
                                 "not open('%s')\n", full_path);
      /* Succeeded. Now close and remove test file. */
      SC_TRY( close(fd) );
      SC_TRY( unlink(full_path) );
    }
    return 0;
  }

  *slash = '\0';
  int mkdir_rc = mkdir(full_path, (S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|
                                   S_IWGRP|S_IXGRP|S_IROTH|S_IWOTH|S_IXOTH));
  *slash = '/';
  if( mkdir_rc < 0 && errno != EEXIST )
    return sc_node_set_error(node, errno, "sc_perf_writer: ERROR: cannot "
                             "create directory '%s'\n", full_path);
  int err = sc_check_path(node, full_path, slash);
  return err;
}


int sc_disk_writer_prep(struct sc_node* node,
                        const struct sc_node_link*const* links, int n_links)
{
  struct disk_writer_node* wn = node->nd_private;
  struct perf_writer_file* st = wn->file;

  wn->next_hop = sc_node_prep_get_link_or_free(node, "");
  wn->next_hop_after_error = sc_node_prep_get_link(node, "after_error");
  sc_packet_list_init(&wn->write_backlog);

  if( wn->next_hop_after_error == NULL )
    wn->next_hop_after_error = wn->next_hop;
  if( sc_node_prep_check_links(node) < 0 )
    return -1;

  if( fallocate_fn == NULL || st->append )
    wn->async = false;

  /* A file has a unique sc_disk_writer node associated with it. So the file
   * must not be previously opened.
   */

  SC_TEST( st->fd < 0 );

  /* Sanity check on file destination */
  int name_length = strlen(wn->file->filename_template) + 80;
  char* sanity_check_name = malloc(name_length);
  SC_TEST( sanity_check_name != NULL );
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  int rc = sc_pcap_filename(sanity_check_name, name_length,
                            wn->file->filename_template, true, false, ts,
                            st->rotate_file_pad, 0);
  if( rc == 0 ) {
    /* NOTE: If the pcap filename is in a directory that does not
     * exist, sc_check_path will create that directory. This can
     * potentially leave behind an unused directory if doing
     * time-based rotation and the directory varies with time, but
     * we must live with this as deleting the directory opens up
     * a number of hard-to-fix race conditions (see bug 68412)
     */
    rc = sc_check_path(node, sanity_check_name, sanity_check_name);
  }
  else {
    rc = sc_node_set_error(node, ENAMETOOLONG, "sc_perf_writer: ERROR: "
                           "filename too long after expansion of '%s' "
                           "(max %d)\n", wn->file->filename_template,
                           name_length);
  }
  free(sanity_check_name);
  return rc;
}



int sc_disk_writer_init(struct sc_node* node, const struct sc_attr* attr,
                          const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    SC_TRY(sc_node_type_alloc(&nt, NULL, factory));
    nt->nt_pkts_fn = sc_disk_writer_pkts;
    nt->nt_prep_fn = sc_disk_writer_prep;
    nt->nt_end_of_stream_fn = sc_disk_writer_end_of_stream;
  }
  node->nd_type = nt;

  int on_error, sync_on_close;
  if( sc_node_init_get_arg_int(&on_error, node, "on_error", 0)           < 0 ||
      sc_node_init_get_arg_int(&sync_on_close, node, "sync_on_close", 0) < 0  )
    return -1;
  struct sc_object* obj;
  if( sc_node_init_get_arg_obj(&obj, node, "file", 0) < 0 )
    return -1;

  struct disk_writer_node* wn;
  wn = sc_thread_calloc(sc_node_get_thread(node), sizeof(*wn));
  node->nd_private = wn;
  wn->file = NULL;
  wn->node = node;
  wn->async = (attr->force_sync_writer == 0);
  wn->first_time = true;
  wn->io_ctx = 0;
  wn->on_error = on_error;
  wn->sync_on_close = sync_on_close;
  wn->file = sc_opaque_get_ptr(obj);
  SC_TEST( wn->file != NULL );

  SC_TRY( sc_callback_alloc(&wn->backlog_cb, attr, sc_node_get_thread(node)) );
  wn->backlog_cb->cb_private = node;

  SC_TEST(sc_callback_alloc(&wn->postrotate_cb, attr, sc_node_get_thread(node)) == 0);
  wn->postrotate_cb->cb_private = node;
  wn->postrotate_cb->cb_handler_fn = sc_disk_writer_postrotate_cb;

  sc_node_export_state(node, "sc_disk_writer_stats",
                       sizeof(struct sc_disk_writer_stats), &wn->stats);
  wn->stats->async_mode = -1;  /* don't know yet! */
  wn->stats->current_error = 0;
  wn->stats->last_error = 0;
  wn->stats->in_flight_ios = 0;
  wn->stats->in_flight_pkts = 0;
  writer_update_stats(wn);
  sc_node_add_info_str(node, "filename", wn->file->filename_template);
  sc_node_add_info_str(node, "partial_suffix", wn->file->partial_suffix);
  return 0;
}


const struct sc_node_factory sc_disk_writer_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_disk_writer",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_disk_writer_init,
};


static unsigned sc_perf_writer_get_link_index(struct perf_writer_node* wn,
                                              const char* link_name)
{
  unsigned i = wn->n_links;

  if( link_name != NULL )
    for( i = 0; i < wn->n_links; ++i )
      if( wn->link_names[i] != NULL && !strcmp(link_name, wn->link_names[i]) )
        break;

  if( i == wn->n_links ) {
    SC_REALLOC(&wn->link_names, ++wn->n_links);
    if( link_name == NULL )
      wn->link_names[i] = NULL;
    else
      wn->link_names[i] = strdup(link_name);
  }

  return i;
}


static char* sc_perf_writer_construct_link_name(struct perf_writer_node* wn,
                                                unsigned link_index)
{
  char* name_out;
  unsigned ni_id = SC_NODE_IMPL_FROM_NODE(wn->node)->ni_id;

  SC_TEST( link_index < wn->n_links );
  if( wn->link_names[link_index] == NULL )
    SC_TEST( asprintf(&name_out, "%d/%d", ni_id, link_index) );
  else
    SC_TEST( asprintf(&name_out, "%d:%s", ni_id, wn->link_names[link_index]) );

  return name_out;
}


static struct sc_node* sc_perf_writer_select_subnode(struct sc_node* node,
                                                     const char* name,
                                                     char** new_name_out)
{
  struct perf_writer_node* wn = node->nd_private;
  if( wn->all_out_link_added ) {
    sc_node_set_error(node, EINVAL, "%s: ERROR: Incoming link added after "
                      "outgoing link\n", __func__);
    return NULL;
  }
  SC_TEST(wn->file);
  SC_TEST(wn->file->pcap_packer);
  unsigned link_index = sc_perf_writer_get_link_index(wn, name);
  *new_name_out = sc_perf_writer_construct_link_name(wn, link_index);
  return wn->file->pcap_packer;
}


static int sc_perf_writer_add_link(struct sc_node* from_node,
                                   const char* link_name,
                                   struct sc_node* to_node,
                                   const char* to_name_opt)
{
  struct perf_writer_node* wn = from_node->nd_private;
  struct disk_writer_node* dw = wn->file->disk_writer->nd_private;
  int rc = 0;
  if( !strcmp(link_name, "postrotate-filename") ) {
    /* Only creating one link per output file. Swallowing up any further
     * attempts.  So if multiple sc_writers share a file, only the first
     * postrotate link will be connected.
     */
    if( wn->file->snh_postrotate )
      return 0;
    struct sc_arg args[] = {
      SC_ARG_INT("with_pool", 1),
      SC_ARG_INT("with_free_link", 0),
    };
    struct sc_node* snh_node;
    SC_TRY( sc_attr_set_from_fmt(wn->attr, "name", "%s.postrotate_sh",
                                 from_node->nd_name) );
    SC_TRY( sc_node_alloc_named(&snh_node, wn->attr,
                                sc_node_get_thread(from_node),
                                "sc_subnode_helper", NULL,
                                args, sizeof(args) / sizeof(args[0])) );
    wn->file->snh_postrotate = sc_subnode_helper_from_node(snh_node);
    dw->sync_on_close = 1;
    rc = sc_node_add_link(snh_node, "", to_node, to_name_opt);
  }
  else if( ! strcmp(link_name, "") ) {
    /* Default output gets all input.  This matches the behaviour of the
     * original sc_writer.
     */
    char* new_name;
    unsigned i;

    if( wn->all_out_link_added || wn->named_out_link_added )
      return sc_node_set_error(from_node, EINVAL, "%s: ERROR: \"\" must be "
                               "the only outgoing link\n", __func__);

    wn->all_out_link_added = true;
    for( i = 0; i < wn->n_links; ++i ) {
      new_name = sc_perf_writer_construct_link_name(wn, i);
      rc = sc_node_add_link(wn->file->pcap_packer, new_name,
                            to_node, to_name_opt);
      free(new_name);
      if( rc < 0 )
        break;
    }
  }
  else if( ! strcmp(link_name, "#packed") ) {
    /* This output gets the pcap formatted buffers. */
    rc = sc_node_add_link(wn->file->eos_fwd, "", to_node, to_name_opt);
  }
  else {
    /* Otherwise link_name should be the name of an input. */
    if( wn->all_out_link_added )
      return sc_node_set_error(from_node, EINVAL, "%s: ERROR: Cannot mix named "
                               "and \"\" outgoing links\n", __func__);
    wn->named_out_link_added = true;
    unsigned i;
    for( i = 0; i < wn->n_links; ++i) {
      if( wn->link_names[i] != NULL && ! strcmp(link_name, wn->link_names[i]) ) {
        char* new_name = sc_perf_writer_construct_link_name(wn, i);
        rc = sc_node_add_link(wn->file->pcap_packer, new_name,
                              to_node, to_name_opt);
        free(new_name);
        break;
      }
    }
    if( i == wn->n_links ) {
      return sc_node_set_error(from_node, EINVAL, "%s: ERROR: No matching "
                               "incoming link '%s'\n", __func__, link_name);
    }
  }
  return rc < 0 ? sc_node_fwd_error(from_node, rc) : rc;
}


int sc_perf_writer_prep(struct sc_node* node,
                        const struct sc_node_link*const* links, int n_links)
{
  struct perf_writer_node* wn = node->nd_private;
  if( wn->owns_file )
    sc_pcap_packer_redirect_eos(wn->file->pcap_packer, wn->file->eos_fwd);
  return 0;
}


int sc_perf_writer_init(struct sc_node* node, const struct sc_attr* attr,
                          const struct sc_node_factory* factory)
{
  if( writer_files.next == NULL )
    sc_dlist_init(&writer_files);

  if( fallocate_fn == NULL )
    fallocate_fn = dlsym(RTLD_DEFAULT, "fallocate");

  static struct sc_node_type* nt;
  if( nt == NULL ) {
    SC_TRY(sc_node_type_alloc(&nt, NULL, factory));
    nt->nt_prep_fn = sc_perf_writer_prep;
    nt->nt_select_subnode_fn = sc_perf_writer_select_subnode;
    nt->nt_add_link_fn = sc_perf_writer_add_link;
  }
  sc_writer_stats_declare(sc_thread_get_session(sc_node_get_thread(node)));
  node->nd_type = nt;

  const char* arg_filename;
  if( sc_node_init_get_arg_str(&arg_filename, node, "filename", NULL) < 0 )
    return -1;
  if( arg_filename == NULL )
    return sc_node_set_error(node, EINVAL, "%s: ERROR: required arg 'filename' "
                             "missing\n", __func__);

  const char* partial_suffix;
  if( sc_node_init_get_arg_str(&partial_suffix, node,
                               "partial_suffix", NULL) < 0 )
    return -1;

  const char* on_error_str;
  enum on_error arg_on_error;
  if( sc_node_init_get_arg_str(&on_error_str, node, "on_error", "exit") < 0 )
    return -1;
  if( ! on_error_from_str(on_error_str, &arg_on_error) )
    return sc_node_set_error(node, EINVAL, "%s: ERROR: bad on_error '%s'; "
                             "expected one of: exit abort message silent\n",
                             __func__, on_error_str);

  const char* arg_format;
  if( sc_node_init_get_arg_str(&arg_format, node, "format", "pcap") < 0 )
    return -1;

  int arg_snap, arg_sync, arg_discard_mask, arg_append;
  int arg_rotate_secs, arg_rotate_file_pad;
  int64_t arg_rotate_file_size;
# define get_arg_int     sc_node_init_get_arg_int
# define get_arg_int64   sc_node_init_get_arg_int64
  if( get_arg_int(&arg_append, node, "append", 0)                       < 0 ||
      get_arg_int(&arg_rotate_secs, node, "rotate_seconds", 0)          < 0 ||
      get_arg_int64(&arg_rotate_file_size, node, "rotate_file_size", 0) < 0 ||
      get_arg_int(&arg_rotate_file_pad, node, "rotate_file_pad", 0)     < 0 ||
      get_arg_int(&arg_snap, node, "snap", 0)                           < 0 ||
      get_arg_int(&arg_discard_mask, node, "discard_mask", 0)           < 0 ||
      get_arg_int(&arg_sync, node, "sync_on_close", 0)                  < 0  )
    return -1;
# undef get_arg_int
# undef get_arg_int64

  if( arg_append && (arg_rotate_secs || arg_rotate_file_size) )
    return sc_node_set_error(node, EINVAL, "%s: ERROR: append is not "
                             "compatible with file rotation\n", __func__);

  if( arg_rotate_file_size < 0 )
    return sc_node_set_error(node, EINVAL,
                             "sc_perf_writer: ERROR: rotate_file_size must "
                             "be >= 0\n");

  if( arg_rotate_file_pad < 0 )
    return sc_node_set_error(node, EINVAL,
                             "sc_perf_writer: ERROR: rotate_file_pad must "
                             "be >= 0\n");

  struct perf_writer_node* wn;
  wn = sc_thread_calloc(sc_node_get_thread(node), sizeof(*wn));
  wn->node = node;
  wn->eos_pending = false;
  wn->attr = sc_attr_dup(attr);
  node->nd_private = wn;

  struct perf_writer_file* st;
  st = sc_thread_calloc(sc_node_get_thread(node), sizeof(*st));
  st->thread = sc_node_get_thread(node);
  st->fd = -1;
  st->perf_writer = node;
  st->append = arg_append;
  st->rotate_secs = arg_rotate_secs;
  st->rotate_file_size = arg_rotate_file_size;
  st->rotate_file_pad = arg_rotate_file_pad;
  if( partial_suffix == NULL ) {
    if( st->rotate_secs || st->rotate_file_size )
      partial_suffix = ".partial";
    else
      partial_suffix = "";
  }
  st->partial_suffix = strdup(partial_suffix);
  st->filename_template = strdup(arg_filename);
  st->filename_len = strlen(arg_filename) + 80;
  st->filename_next = malloc(st->filename_len);
  st->filename_final = malloc(st->filename_len);
  st->filename_current = malloc(st->filename_len + strlen(partial_suffix));
  st->filename_rotated = malloc(st->filename_len);
  free(node->nd_name);
  SC_TEST(asprintf(&node->nd_name, "sc_writer(%s)", st->filename_template) > 0);

  /* See if this file has already been opened. */
  struct perf_writer_file* st2;
  SC_DLIST_FOR_EACH_OBJ(&writer_files, st2, link)
    if( ! strcmp(st->filename_template, st2->filename_template) ) {
      if( st2->thread != st->thread ) {
        sc_node_set_error(node, EINVAL, "%s: ERROR: file(%s) opened for "
                          "thread(%s) and thread(%s)\n", __func__,
                          st->filename_template, st2->thread->name,
                          st->thread->name);
        goto err;
      }
      if( st2->append != st->append                       ||
          st2->rotate_secs != st->rotate_secs             ||
          st2->rotate_file_size != st->rotate_file_size   ||
          strcmp(st2->partial_suffix, st->partial_suffix)  ) {
        sc_node_set_error(node, EINVAL, "%s: ERROR: file(%s) opened with "
                          "conflicting options\n", __func__,
                          st->filename_template);
        goto err;
      }
      free(st->filename_template);
      free(st->filename_next);
      free(st->filename_current);
      free(st->filename_final);
      free(st->partial_suffix);
      sc_thread_mfree(st->thread, st);
      st = st2;
      ++(st->refs);
      /* We've found an existing file. In this case, we don't need to create
       * an sc_pcap_packer or sc_disk writer. Instead, we use the ones already
       * associated with this file.
       */
      goto success;
    }

  /* For a new file, we have to create a pcap_packer and disk_writer.
   */

  sc_dlist_push_head(&writer_files, &st->link);
  wn->owns_file = true;

  struct sc_arg pcap_packer_args[] = {
    SC_ARG_INT("snap", arg_snap),
    SC_ARG_STR("on_error", on_error_str),
    SC_ARG_INT("rotate_seconds", st->rotate_secs),
    SC_ARG_INT("rotate_file_size", st->rotate_file_size),
    SC_ARG_INT("rotate_file_pad", st->rotate_file_pad),
    SC_ARG_STR("filename", st->filename_template),
    SC_ARG_STR("format", arg_format),
    SC_ARG_INT("wait_for_byte_count", 1),
    SC_ARG_INT("discard_mask", arg_discard_mask)
  };

  SC_TRY( sc_attr_set_from_fmt(wn->attr, "name", "%s.packer", node->nd_name) );

  int rc = sc_node_alloc(&st->pcap_packer, wn->attr, sc_node_get_thread(node),
                         &sc_pcap_packer_sc_node_factory, pcap_packer_args,
                         sizeof(pcap_packer_args)/sizeof(pcap_packer_args[0]));
  if( rc < 0 ) {
    goto err;
  }

  struct sc_object* writer_file;
  sc_opaque_alloc(&writer_file, st);

  struct sc_arg disk_writer_args[] = {
    SC_ARG_INT("on_error", arg_on_error),
    SC_ARG_INT("sync_on_close", arg_sync),
    SC_ARG_OBJ("file", writer_file)
  };

  SC_TRY( sc_attr_set_from_fmt(wn->attr, "name", "%s.disk_writer",
                               node->nd_name) );
  rc = sc_node_alloc(&st->disk_writer, wn->attr, sc_node_get_thread(node),
                     &sc_disk_writer_sc_node_factory, disk_writer_args,
                     sizeof(disk_writer_args)/sizeof(disk_writer_args[0]));
  if( rc < 0 ) {
    goto err;
  }
  sc_opaque_free(writer_file);

  SC_TRY( sc_attr_set_from_fmt(wn->attr, "name", "%s.eos_fwd",
                               node->nd_name) );
  rc = sc_node_alloc(&st->eos_fwd, wn->attr, sc_node_get_thread(node),
                     &sc_eos_fwd_node_factory, NULL, 0);
  if( rc < 0 ) {
    goto err;
  }

  /* Connecting pcap_packer to disk_writer...
   */
  rc = sc_node_add_link(st->pcap_packer, "", st->disk_writer,"");
  if( rc < 0 )
    goto err;

  /*... and disk writer to eos_fwd.*/
  rc = sc_node_add_link(st->disk_writer, "", st->eos_fwd, "");
  if( rc < 0 )
    goto err;

  st->writer_state = WS_RUN;

 success:
  sc_node_export_state(node, "sc_writer_stats",
                       sizeof(struct sc_writer_stats), &wn->stats);

  wn->file = st;
  return 0;

 err:
  return -1;
}


const struct sc_node_factory sc_perf_writer_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_perf_writer",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_perf_writer_init,
};

/** \endcond NODOC */
