/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \node{sc_fd_reader}
 *
 * \brief Reads data from a file or file descriptor.
 *
 * \nodedetails
 * This node reads data from a file in the filesystem, or from a file
 * descriptor, and passes the data to its output link.
 *
 * By default each output buffer contains data from a single read() call.
 * This may be less than a full buffers worth if the file descriptor is a
 * socket or pipe.  Set fill_buffers=1 to ensure that each buffer is filled
 * completely before releasing it to the output.
 *
 * If the input file descriptor is a datagram socket or similar (and
 * fill_buffers=0) then each output packet will contain a single datagram.
 *
 * \nodeargs
 * Argument      | Optional? | Default | Type           | Description
 * ------------- | --------- | ------- | -------------- | -------------------------------------------------------------------------------------------------------
 * filename      | Yes       |         | ::SC_PARAM_STR | The name of a file to read data from.  (If fd is also set then this name is just informational).
 * fd            | Yes       |         | ::SC_PARAM_INT | File descriptor to read data from.
 * signal_eof    | Yes       | 1       | ::SC_PARAM_INT | Set to 0 to prevent this node from signalling end-of-stream when the whole file has been read.
 * close_on_eof  | Yes       | 1       | ::SC_PARAM_INT | Whether to close the file descriptor when the whole file has been read.
 * fill_buffers  | Yes       | 0       | ::SC_PARAM_INT | Whether or not to completely fill output packets.
 * repeat        | Yes       | 0       | ::SC_PARAM_INT | If set to true, when we reach the end of the file, we seek to the beginning again and keep reading.
 * repeat_offset | Yes       | 0       | ::SC_PARAM_INT | Offset to seek to if repeating.  (This can be used to skip a per-file header).
 *
 * \cond NODOC
 */

/* This is needed for asprintf(). */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#include <sc_internal.h>
#include <sc_internal/builtin_nodes.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


struct sc_fd_reader {
  struct sc_node*            node;
  struct sc_attr*            attr;
  const struct sc_node_link* next_hop;
  const struct sc_node_link* next_hop_free_unused;
  struct sc_callback*        readable_cb;
  struct sc_callback*        pool_cb;
  char*                      filename;
  int                        fd;
  int                        is_file;
  struct sc_pool*            pool;
  struct sc_packet*          pkt;
  int                        pkt_fill;
  int                        signal_eof;
  int                        close_on_eof;
  int                        repeat;
  int                        repeat_offset;
  int                        fill_buffers;
};


static int poll_op(struct sc_fd_reader* fr, int op, unsigned events)
{
  if( fr->is_file ) {
    switch( op ) {
    case EPOLL_CTL_ADD:
      sc_timer_expire_after_ns(fr->readable_cb, 1);
      break;
    case EPOLL_CTL_MOD:
      if( events )
        sc_timer_expire_after_ns(fr->readable_cb, 1);
      break;
    case EPOLL_CTL_DEL:
      break;
    }
    return 0;
  }
  else {
    return sc_epoll_ctl(sc_node_get_thread(fr->node),
                        op, fr->fd, events, fr->readable_cb);
  }
}


static void sc_fd_reader_readable(struct sc_callback* cb, void* event_info)
{
  int n_bytes;
  struct sc_fd_reader* fr = cb->cb_private;
  if( fr->pkt == NULL ) {
    struct sc_packet_list pl;
    __sc_packet_list_init(&pl);
    if( sc_pool_get_packets(&pl, fr->pool, 1, 1) != 1 ) {
      poll_op(fr, EPOLL_CTL_MOD, 0);
      sc_pool_on_threshold(fr->pool, fr->pool_cb, 1);
      return;
    }
    fr->pkt = pl.head;
  }
  int rc;
 read_again:
  n_bytes = fr->pkt->iov[0].iov_len - fr->pkt_fill;
  rc = read(fr->fd, (char*) fr->pkt->iov[0].iov_base + fr->pkt_fill, n_bytes);
  if( rc > 0 ) {
    fr->pkt_fill += rc;
    if( ! fr->fill_buffers || rc == n_bytes ) {
      fr->pkt->iov[0].iov_len = fr->pkt_fill;
      fr->pkt->frame_len = fr->pkt_fill;
      sc_forward(fr->node, fr->next_hop, fr->pkt);
      fr->pkt = NULL;
      fr->pkt_fill = 0;
    }
  }
  else if( rc < 0 ) {
    switch( errno ) {
    case EAGAIN:
      break;
    case EPIPE:
    case ECONNRESET:
      goto eof;
    default:
      fprintf(stderr, "sc_fd_reader: read failed: %d %s\n",
              errno, strerror(errno));
      poll_op(fr, EPOLL_CTL_DEL, 0);
      return;
    }
  }
  else {
    /* EOF. */
    /* ?? todo: add option to poll file in case it is extended */
    if( fr->repeat ) {
      SC_TEST(lseek(fr->fd, fr->repeat_offset, SEEK_SET) == 0);
      goto read_again;
    }
  eof:
    poll_op(fr, EPOLL_CTL_DEL, 0);
    fr->pkt->iov[0].iov_len = fr->pkt_fill;
    fr->pkt->frame_len = fr->pkt_fill;
    if( fr->pkt_fill > 0 )
      sc_forward(fr->node, fr->next_hop, fr->pkt);
    else
      sc_forward(fr->node, fr->next_hop_free_unused, fr->pkt);
    fr->pkt = NULL;
    if( fr->signal_eof ) {
      sc_node_link_end_of_stream(fr->node, fr->next_hop);
      sc_node_link_end_of_stream(fr->node, fr->next_hop_free_unused);
    }
    if( fr->close_on_eof ) {
      close(fr->fd);
      fr->fd = -1;
    }
    return;
  }
  if( fr->is_file )
    sc_timer_expire_after_ns(fr->readable_cb, 1);
}


static void sc_fd_reader_pool_cb(struct sc_callback* cb, void* event_info)
{
  struct sc_fd_reader* fr = cb->cb_private;
  assert(fr->pkt == NULL);
  poll_op(fr, EPOLL_CTL_MOD, EPOLLIN);
}


static int sc_fd_reader_prep(struct sc_node* node,
                             const struct sc_node_link*const* links,
                             int n_links)
{
  struct sc_fd_reader* fr = node->nd_private;
  if( (fr->next_hop = sc_node_prep_get_link(node, "")) == NULL )
    return sc_node_set_error(node, EINVAL,
                             "sc_fd_reader: ERROR: no next hop\n");
  fr->next_hop_free_unused = sc_node_prep_get_link_or_free(node, NULL);
  int rc = sc_node_prep_check_links(node);
  if( rc < 0 )
    return rc;
  rc = sc_node_prep_get_pool(&fr->pool, fr->attr, node, NULL, 0);
  if( rc < 0 )
    return sc_node_fwd_error(node, rc);
  poll_op(fr, EPOLL_CTL_ADD, EPOLLIN);
  return 0;
}


static int sc_fd_reader_init(struct sc_node* node, const struct sc_attr* attr,
                             const struct sc_node_factory* factory)
{
  int close_fd = -1;

  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_prep_fn = sc_fd_reader_prep;
  }
  node->nd_type = nt;

  struct sc_fd_reader* fr;
  fr = sc_thread_calloc(sc_node_get_thread(node), sizeof(*fr));
  node->nd_private = fr;
  fr->node = node;

  const char* filename;
  if( sc_node_init_get_arg_str(&filename, node, "filename", NULL) < 0 )
    goto error;
  if( sc_node_init_get_arg_int(&fr->fd, node, "fd", -1) < 0 )
    goto error;
  if( sc_node_init_get_arg_int(&fr->signal_eof, node, "signal_eof", 1) < 0 )
    goto error;
  if( sc_node_init_get_arg_int(&fr->close_on_eof, node, "close_on_eof", 1) < 0 )
    goto error;
  if( sc_node_init_get_arg_int(&fr->repeat, node, "repeat", 0) < 0 )
    goto error;
  if( sc_node_init_get_arg_int(&fr->repeat_offset,
                               node, "repeat_offset", 0) < 0 )
    goto error;
  if( sc_node_init_get_arg_int(&fr->fill_buffers, node, "fill_buffers", 0) < 0 )
    goto error;

  if( fr->fd >= 0 ) {
    if( filename != NULL )
      fr->filename = strdup(filename);
    else
      SC_TEST(asprintf(&fr->filename, "<%d", fr->fd) > 0);
  }
  else if( filename != NULL ) {
    if( (fr->fd = open(filename, O_RDONLY | O_NONBLOCK)) < 0 ) {
      sc_node_set_error(node, errno, "sc_fd_reader: ERROR: could not open "
                        "file '%s'\n", filename);
      goto error;
    }
    fr->filename = strdup(filename);
    close_fd = fr->fd;
  }
  else {
    sc_node_set_error(node, EINVAL, "sc_fd_reader: ERROR: bad fd=%d and no "
                      "filename\n", fr->fd);
    goto error;
  }

  struct stat stat;
  SC_TRY(fstat(fr->fd, &stat));
  fr->is_file = !! S_ISREG(stat.st_mode);
  if( ! fr->is_file ) {
    int flags = fcntl(fr->fd, F_GETFL);
    if( flags >= 0 && ! (flags & O_NONBLOCK) )
      fcntl(fr->fd, F_SETFL, flags | O_NONBLOCK);
  }

  SC_TEST(sc_callback_alloc(&fr->readable_cb, attr,
                            sc_node_get_thread(node)) == 0);
  fr->readable_cb->cb_private = fr;
  fr->readable_cb->cb_handler_fn = sc_fd_reader_readable;
  SC_TEST(sc_callback_alloc(&fr->pool_cb, attr, sc_node_get_thread(node)) == 0);
  fr->pool_cb->cb_private = fr;
  fr->pool_cb->cb_handler_fn = sc_fd_reader_pool_cb;
  fr->attr = sc_attr_dup(attr);
  SC_TRY(sc_attr_set_int(fr->attr, "private_pool", 1));
  return 0;

 error:
  free(fr->filename);
  if( close_fd >= 0 )
    close(close_fd);
  sc_thread_mfree(sc_node_get_thread(node), fr);
  return -1;
}


const struct sc_node_factory sc_fd_reader_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_fd_reader",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_fd_reader_init,
};

/** \endcond NODOC */
