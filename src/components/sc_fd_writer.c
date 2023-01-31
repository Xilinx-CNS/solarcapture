/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \node{sc_fd_writer}
 *
 * \brief Write data to a file descriptor.
 *
 * \nodedetails
 * This node writes the raw contents of each incoming packet to a file
 * descriptor.  It can be used to write data into a file, socket, pipe etc.
 *
 * The contents of each ::sc_packet arriving at this node is written with a
 * single writev() call (or equivalent).  If the file descriptor is a
 * datagram socket then each ::sc_packet generates a single datagram.
 *
 * If the file descriptor supports non-blocking writes then this node uses
 * epoll to avoid blocking the thread.
 *
 * \nodeargs
 * Argument      | Optional? | Default | Type           | Description
 * ------------- | --------- | ------- | -------------- | -------------------------------------------------------------------------------------------------------
 * fd            | No        |         | ::SC_PARAM_INT | File descriptor to write data to.
 * close_on_eos  | Yes       | 0       | ::SC_PARAM_INT | Whether to close the file descriptor when the end-of-stream signal is received.
 *
 * \outputlinks
 * Link | Description
 * ---- | --------------------------------------------------------------
 * ""   | Input packets are forwarded to this output once written.
 *
 * \cond NODOC
 */

#include <sc_internal.h>

#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/stat.h>


struct sc_fd_writer_node {
  struct sc_node*             node;
  const struct sc_node_link*  next_hop;
  int                         fd;
  struct sc_iovec_ptr         iovec;

  struct sc_callback*         epoll_cb;
  bool                        epoll_enabled;
  struct sc_packet_list       backlog;

  bool                        is_file;
  bool                        eos_seen;
  int                         close_on_eos;
};


static void sc_fd_writer_toggle_epoll(struct sc_fd_writer_node* wn)
{
  wn->epoll_enabled = ! wn->epoll_enabled;
  int op = wn->epoll_enabled ? EPOLL_CTL_ADD : EPOLL_CTL_DEL;
  SC_TRY( sc_epoll_ctl(sc_node_get_thread(wn->node), op,
                       wn->fd, EPOLLOUT, wn->epoll_cb) );
}


static void sc_fd_writer_forward_eos(struct sc_fd_writer_node* wn)
{
  if( wn->close_on_eos )
    close(wn->fd);
  sc_node_link_end_of_stream(wn->node, wn->next_hop);
}


static inline bool sc_fd_writer_do_write(struct sc_fd_writer_node* wn)
{
  SC_TEST( wn->iovec.iovlen > 0 );
  int n_bytes = writev(wn->fd, wn->iovec.iov, wn->iovec.iovlen);
  bool more_work = true;
  if( n_bytes < 0 ) {
    struct sc_session* tg = sc_thread_get_session(sc_node_get_thread(wn->node));
    sc_err(tg, "ERROR: %s: Failed to write data to fd %d (is_file=%d rc=%d "
           "errno=%d)\n", __func__, wn->fd, wn->is_file, n_bytes, errno);
    exit(1);
  }
  sc_iovec_ptr_skip(&wn->iovec, n_bytes);
  if( ! sc_iovec_ptr_bytes(&wn->iovec) ) {
    sc_forward(wn->node, wn->next_hop, sc_packet_list_pop_head(&wn->backlog));
    more_work = ! sc_packet_list_is_empty(&wn->backlog);
    if( more_work )
      sc_iovec_ptr_init_packet(&wn->iovec, wn->backlog.head);
  }
  return more_work;
}


static void sc_fd_writer_writable(struct sc_callback* cb, void* event_info)
{
  struct sc_fd_writer_node* wn = cb->cb_private;
  if( ! sc_fd_writer_do_write(wn) ) {
    sc_fd_writer_toggle_epoll(wn);
    if( wn->eos_seen)
      sc_fd_writer_forward_eos(wn);
  }
}


static void sc_fd_writer_pkts(struct sc_node* node,
                              struct sc_packet_list* pl)
{
  struct sc_fd_writer_node* wn = node->nd_private;
  sc_packet_list_append_list(&wn->backlog, pl);
  if( wn->iovec.iovlen == 0 )
    sc_iovec_ptr_init_packet(&wn->iovec, wn->backlog.head);
  if( wn->is_file )
    while( sc_fd_writer_do_write(wn) )
      ;
  else if( ! wn->epoll_enabled )
    sc_fd_writer_toggle_epoll(wn);
}


static void sc_fd_writer_end_of_stream(struct sc_node* node)
{
  struct sc_fd_writer_node* wn = node->nd_private;
  wn->eos_seen = true;
  if( sc_packet_list_is_empty(&wn->backlog) )
    sc_fd_writer_forward_eos(wn);
}


static int sc_fd_writer_prep(struct sc_node* node,
                             const struct sc_node_link*const* links,
                             int n_links)
{
  struct sc_fd_writer_node* wn = node->nd_private;
  wn->next_hop = sc_node_prep_get_link_or_free(node, "");
  return sc_node_prep_check_links(node);
}


static int sc_fd_writer_init(struct sc_node* node, const struct sc_attr* attr,
                             const struct sc_node_factory* factory)
{
  struct sc_thread* thread = sc_node_get_thread(node);
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    SC_TRY(sc_node_type_alloc(&nt, NULL, factory));
    nt->nt_pkts_fn = sc_fd_writer_pkts;
    nt->nt_prep_fn = sc_fd_writer_prep;
    nt->nt_end_of_stream_fn = sc_fd_writer_end_of_stream;
  }
  node->nd_type = nt;

  struct sc_fd_writer_node* wn;
  wn = sc_thread_calloc(thread, sizeof(*wn));
  wn->node = node;
  node->nd_private = wn;

  if( sc_node_init_get_arg_int(&wn->fd, node, "fd", -1) < 0 )
    return -1;
  if( wn->fd == -1 )
    return sc_node_set_error(node, EINVAL, "%s: ERROR: Missing required "
                             "argument 'fd'\n", __func__);

  if( sc_node_init_get_arg_int(&wn->close_on_eos, node, "close_on_eos", 0) < 0 )
    return -1;

  SC_TEST( sc_callback_alloc(&wn->epoll_cb, attr, thread) == 0 );
  wn->epoll_cb->cb_private = wn;
  wn->epoll_cb->cb_handler_fn = sc_fd_writer_writable;

  struct stat stat;
  SC_TRY(fstat(wn->fd, &stat));
  wn->is_file = !! S_ISREG(stat.st_mode);

  sc_packet_list_init(&wn->backlog);

  return 0;
}


const struct sc_node_factory sc_fd_writer_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_fd_writer",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_fd_writer_init,
};

/** \endcond NODOC */
