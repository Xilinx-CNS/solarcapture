/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \node{sc_reader}
 *
 * \brief Converts PCAP file format to SolarCapture packets on output.
 *
 * \nodedetails
 * This node converts PCAP file format to SolarCapture packets on output.
 *
 * The input can either be a file on disk (by setting the "filename" arg)
 * or a file descriptor (by setting the "fd" arg).  Alternatively if
 * neither are given then the input packets are interpreted as a binary
 * stream of PCAP formatted packets and de-encapsulated.
 *
 * By default the input is streamed to the output.  If prefill=all-input
 * then the node only starts emitting packets when it has read in the whole
 * input file.  Note that if the packet pool is not large enough to buffer
 * the whole input then an error message will be emitted and the process
 * will exit.
 *
 * If prefill=all-buffers then the node starts emitting packets when it has
 * read in the whole input file, or when the packet pool is exhausted,
 * whichever happens first.
 *
 * \nodeargs
 * Argument   | Optional? | Default | Type           | Description
 * ---------- | --------- | ------- | -------------- | ----------------------------------------------------------------------------------------------------------------
 * filename   | Yes       |         | ::SC_PARAM_STR | The name of a PCAP file to read packet data from.  (If fd is also set then this name is just informational).
 * fd         | Yes       |         | ::SC_PARAM_INT | File descriptor to read PCAP formatted packet data from.
 * prefill    | Yes       | "none"  | ::SC_PARAM_STR | Whether to stream input to output or buffer.  One of: "none", "all-input" or "all-buffers".
 * signal_eof | Yes       | 1       | ::SC_PARAM_INT | Set to 0 to prevent this node from signalling end-of-stream at the end of the file.
 *
 * \outputlinks
 * Link     | Description
 * -------- | ---------------------------------------------------------------------------------
 *  ""      | The unpacked stream of packets with one ::sc_packet per packet in the PCAP.
 *  "input" | The PCAP format stream.
 *
 * \cond NODOC
 */

#include <sc_internal.h>
#include <sc_internal/builtin_nodes.h>
#include "sc_pcap.h"

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
#include <byteswap.h>


enum reader_state {
  rs_file_header,
  rs_rec_header,
  rs_frame,
  rs_err,
};


enum rd_mode {
  rm_stream,
  rm_all_input,
  rm_fill_buffers,
};


struct reader_node {
  struct sc_node*            node;
  struct sc_attr*            attr;
  struct reader_file*        file;
  const struct sc_node_link* free_input_hop;
  const struct sc_node_link* free_bufs_hop;
  const struct sc_node_link* next_hop;
  struct sc_pool*            pool;
  struct sc_callback*        pool_cb;
  struct pcap_file_hdr       file_hdr;
  enum rd_mode               mode;
  int                        signal_eof;

  enum reader_state          state;
  struct sc_packet_list      in_pl;
  struct sc_iovec_ptr        in_iovp;
  struct pcap_rec_hdr        rec_hdr;
  int                        bytes_needed;
  struct sc_packet_list      out_pl;
  struct sc_packet*          pkt;
  int                        eof;
};


static void sc_reader_err(struct reader_node* rd, const char* fmt, ...)
  __attribute__ ((format (printf, 2, 3)));

static void sc_reader_err(struct reader_node* rd, const char* fmt, ...)
{
  struct sc_session* tg = sc_thread_get_session(sc_node_get_thread(rd->node));
  va_list va;
  va_start(va, fmt);
  sc_errv(tg, fmt, va);
  va_end(va);

  if( rd->pkt != NULL ) {
    sc_forward(rd->node, rd->free_bufs_hop, rd->pkt);
    rd->pkt = NULL;
  }

  sc_node_link_end_of_stream(rd->node, rd->free_bufs_hop);
  if( sc_packet_list_is_empty(&rd->out_pl) )
      sc_node_link_end_of_stream(rd->node, rd->next_hop);
  rd->state = rs_err;
}


static int is_supported(const struct pcap_file_hdr* pfh)
{
  switch( pfh->magic_number ) {
  case PCAP_MAGIC:
  case PCAP_MAGIC_BSWAP:
  case PCAP_NSEC_MAGIC:
  case PCAP_NSEC_MAGIC_BSWAP:
    break;
  default:
    return -1;
  }
  return 0;
}


static int sc_reader_get_pkt(struct reader_node* rd)
{
  /* Ensure we have a packet buffer to write into and return true.  If no
   * buffers available, request callback and return false.
   */
  if( rd->pkt == NULL ) {
    struct sc_packet_list pl;
    __sc_packet_list_init(&pl);
    if( sc_pool_get_packets(&pl, rd->pool, 1, 1) != 1 ) {
      sc_pool_on_threshold(rd->pool, rd->pool_cb, 1);
      return 0;
    }
    rd->pkt = pl.head;
    rd->pkt->iov[0].iov_len = 0;
    rd->pkt->ts_sec = rd->rec_hdr.ts_sec;
    rd->pkt->ts_nsec = rd->rec_hdr.ts_subsec;
  }
  return 1;
}


static void sc_reader_input_consumed(struct reader_node* rd)
{
  assert(sc_iovec_ptr_bytes(&rd->in_iovp) == 0);
  sc_forward(rd->node, rd->free_input_hop, sc_packet_list_pop_head(&rd->in_pl));
  if( ! sc_packet_list_is_empty(&rd->in_pl) ) {
    sc_iovec_ptr_init_packet(&rd->in_iovp, rd->in_pl.head);
  }
  else if( rd->eof ) {
    if( rd->pkt != NULL ) {
      if( rd->pkt->frame_len > 0 )
        fprintf(stderr, "%s: [%s] ERROR: input truncated state=%d "
                "bytes_needed=%d\n", __func__, rd->node->nd_name,
                (int) rd->state, rd->bytes_needed);//??
      sc_forward(rd->node, rd->free_bufs_hop, rd->pkt);
      rd->pkt = NULL;
    }
  }
}


static int sc_reader_do_frame(struct reader_node* rd)
{
  if( ! sc_reader_get_pkt(rd) )
    return 0;

  int fl_b4 = rd->pkt->frame_len;
  int rc = sc_packet_append_iovec_ptr(rd->pkt, rd->pool, &rd->in_iovp,
                                      rd->bytes_needed);
  if( rd->pkt->frame_len - fl_b4 == rd->bytes_needed ) {
    rd->pkt->ts_sec = rd->rec_hdr.ts_sec;
    rd->pkt->ts_nsec = rd->rec_hdr.ts_subsec;
    rd->pkt->frame_len = rd->rec_hdr.orig_len;
    __sc_packet_list_append(&rd->out_pl, rd->pkt);
    rd->pkt = NULL;
    rd->state = rs_rec_header;
    rd->bytes_needed = sizeof(rd->rec_hdr);
  }
  else {
    rd->bytes_needed -= rd->pkt->frame_len - fl_b4;
    if( rc == 0 ) {  /* All copied. */
      sc_reader_input_consumed(rd);
    }
    else if( rc == -1 ) {  /* Out of buffers for now. */
      sc_pool_on_threshold(rd->pool, rd->pool_cb, 1);
      return 0;
    }
    else if( rc == -2 ) {  /* Too big! */
      /* ?? handle this case! */
      SC_TEST(0);
    }
  }
  return 1;
}


static void sc_reader_do_rec_hdr(struct reader_node* rd)
{
  int n, off = sizeof(rd->rec_hdr) - rd->bytes_needed;
  n = sc_iovec_ptr_copy_out((char*) &rd->rec_hdr + off, &rd->in_iovp,
                            rd->bytes_needed);
  if( n == rd->bytes_needed ) {
    switch( rd->file_hdr.magic_number ) {
    case PCAP_MAGIC_BSWAP:
    case PCAP_NSEC_MAGIC_BSWAP:
      rd->rec_hdr.ts_sec = bswap_32(rd->rec_hdr.ts_sec);
      rd->rec_hdr.ts_subsec = bswap_32(rd->rec_hdr.ts_subsec);
      rd->rec_hdr.incl_len = bswap_32(rd->rec_hdr.incl_len);
      rd->rec_hdr.orig_len = bswap_32(rd->rec_hdr.orig_len);
      if( rd->file_hdr.magic_number == PCAP_MAGIC_BSWAP )
        rd->rec_hdr.ts_subsec *= 1000;
      break;
    case PCAP_MAGIC:
      rd->rec_hdr.ts_subsec *= 1000;
      break;
    default:
      break;
    }
    rd->state = rs_frame;
    if( rd->rec_hdr.incl_len > INT32_MAX )
      sc_reader_err(rd, "%s: [%s] ERROR: Out-of-range incl_len=%d in pcap "
                    "packet header\n", __func__, rd->node->nd_name,
                    rd->rec_hdr.incl_len);
    else
      rd->bytes_needed = rd->rec_hdr.incl_len;
  }
  else {
    rd->bytes_needed -= n;
    sc_reader_input_consumed(rd);
  }
}


static void sc_reader_do_file_hdr(struct reader_node* rd)
{
  int n, off = sizeof(rd->file_hdr) - rd->bytes_needed;
  n = sc_iovec_ptr_copy_out((char*) &rd->file_hdr + off, &rd->in_iovp,
                            rd->bytes_needed);
  if( n == rd->bytes_needed ) {
    /* ?? todo: work out how to do this more elegantly! */
    SC_TEST(is_supported(&rd->file_hdr) == 0);
    rd->state = rs_rec_header;
    rd->bytes_needed = sizeof(rd->rec_hdr);
  }
  else {
    rd->bytes_needed -= n;
    sc_reader_input_consumed(rd);
  }
}


static inline int sc_reader_can_forward(struct reader_node* rd)
{
  switch( rd->mode ) {
  case rm_stream:
    return 1;
  case rm_all_input:
    if( rd->eof ) {
      rd->mode = rm_stream;
      return 1;
    }
    if( sc_callback_is_active(rd->pool_cb) ) {
      fprintf(stderr, "sc_reader: ERROR: [%s] Unable to buffer entire input -- "
              "not enough buffers available (pkts_so_far=%d total_bufs=%d)\n",
              rd->node->nd_name, rd->out_pl.num_pkts,
              rd->out_pl.num_pkts + rd->out_pl.num_frags);
      exit(1);
    }
    return 0;
  case rm_fill_buffers:
    if( rd->eof || sc_callback_is_active(rd->pool_cb) ) {
      rd->mode = rm_stream;
      return 1;
    }
    return 0;
  default:
    assert(0);
  }
  return 1;
}


static void sc_reader_go(struct reader_node* rd)
{
  while( ! sc_packet_list_is_empty(&rd->in_pl) ) {
    switch( rd->state ) {
    case rs_frame:
      if( sc_reader_do_frame(rd) == 0 )
        goto out;
      break;
    case rs_rec_header:
      sc_reader_do_rec_hdr(rd);
      break;
    case rs_file_header:
      sc_reader_do_file_hdr(rd);
      break;
    case rs_err:
      sc_forward_list(rd->node, rd->free_input_hop, &rd->in_pl);
      sc_packet_list_init(&rd->in_pl);
      break;
    default:
      assert(0);
      break;
    }
  }

 out:
  if( ! sc_packet_list_is_empty(&rd->out_pl) && sc_reader_can_forward(rd) ) {
    __sc_forward_list(rd->node, rd->next_hop, &rd->out_pl);
    __sc_packet_list_init(&rd->out_pl);
    if( rd->state == rs_err )
      sc_node_link_end_of_stream(rd->node, rd->next_hop);
  }
  if( rd->eof && rd->signal_eof && sc_packet_list_is_empty(&rd->in_pl) ) {
    SC_TEST( sc_packet_list_is_empty(&rd->out_pl) );
    sc_node_link_end_of_stream(rd->node, rd->free_input_hop);
    sc_node_link_end_of_stream(rd->node, rd->free_bufs_hop);
    sc_node_link_end_of_stream(rd->node, rd->next_hop);
  }
}


static void sc_reader_buffers_available(struct sc_callback* cb,
                                        void* event_info)
{
  struct reader_node* rd = cb->cb_private;
  assert(rd->state == rs_frame);
  sc_reader_go(rd);
}


static void sc_reader_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct reader_node* rd = node->nd_private;

  SC_TEST(rd->eof == 0);
  int was_empty = sc_packet_list_is_empty(&rd->in_pl);
  sc_packet_list_append_list(&rd->in_pl, pl);
  if( was_empty )
    sc_iovec_ptr_init_packet(&rd->in_iovp, rd->in_pl.head);
  sc_reader_go(rd);
}


static void sc_reader_end_of_stream(struct sc_node* node)
{
  struct reader_node* rd = node->nd_private;
  SC_TEST(rd->eof == 0);
  rd->eof = 1;
  sc_reader_go(rd);
}


static int sc_reader_prep(struct sc_node* node,
                          const struct sc_node_link*const* links, int n_links)
{
  struct reader_node* rd = node->nd_private;
  int rc;

  rd->free_input_hop = sc_node_prep_get_link_or_free(node, "input");
  rd->free_bufs_hop = sc_node_prep_get_link_or_free(node, NULL);
  if( (rd->next_hop = sc_node_prep_get_link(node, "")) == NULL )
    return sc_node_set_error(node, EINVAL,
                             "sc_reader: ERROR: no next hop\n");
  if( sc_node_prep_check_links(node) < 0 )
    return -1;
  const struct sc_node_link* plinks[] = { rd->next_hop, rd->free_bufs_hop };
  rc = sc_node_prep_get_pool(&rd->pool, rd->attr, node, plinks, 2);
  if( rc < 0 )
    return sc_node_fwd_error(node, rc);
  sc_node_prep_does_not_forward(node);
  sc_node_prep_link_forwards_from_node(node, rd->free_input_hop, node);
  return 0;
}


static int sc_reader_init(struct sc_node* node, const struct sc_attr* attr,
                          const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    SC_TRY(sc_node_type_alloc(&nt, NULL, factory));
    nt->nt_pkts_fn = sc_reader_pkts;
    nt->nt_prep_fn = sc_reader_prep;
    nt->nt_end_of_stream_fn = sc_reader_end_of_stream;
  }
  node->nd_type = nt;

  struct reader_node* rd;
  rd = sc_thread_calloc(sc_node_get_thread(node), sizeof(*rd));
  rd->node = node;
  node->nd_private = rd;

  const char* mode;
  if( sc_node_init_get_arg_str(&mode, node, "prefill", NULL) < 0 )
    goto error;
  if( mode == NULL || ! strcmp(mode, "none") )
    rd->mode = rm_stream;
  else if( ! strcmp(mode, "all-input") )
    rd->mode = rm_all_input;
  else if( ! strcmp(mode, "all-buffers") )
    rd->mode = rm_fill_buffers;
  else {
    sc_node_set_error(node, EINVAL, "sc_reader: ERROR: bad mode '%s'; "
                      "expected one of: none, all-input, all-buffers\n", mode);
    goto error;
  }
  if( sc_node_init_get_arg_int(&rd->signal_eof, node, "signal_eof", 1) < 0 )
    goto error;

  const char* filename;
  if( sc_node_init_get_arg_str(&filename, node, "filename", NULL) < 0 )
    goto error;
  int fd;
  if( sc_node_init_get_arg_int(&fd, node, "fd", -1) < 0 )
    goto error;
  if( filename || fd >= 0 ) {
    struct sc_arg args[2];
    int n_args = 0;
    if( filename ) {
      args[n_args].name = "filename";
      args[n_args].type = SC_PARAM_STR;
      args[n_args].val.str = filename;
      ++n_args;
    }
    if( fd >= 0 ) {
      args[n_args].name = "fd";
      args[n_args].type = SC_PARAM_INT;
      args[n_args].val.i = fd;
      ++n_args;
    }
    struct sc_node* fdr;
    struct sc_attr* fdr_attr = sc_attr_dup(attr);
    sc_attr_set_int(fdr_attr, "n_bufs_tx", 2);
    sc_attr_set_int(fdr_attr, "n_bufs_tx_min", 2);
    sc_attr_set_int(fdr_attr, "buf_size", 64*1024);
    int rc = sc_node_alloc(&fdr, fdr_attr, sc_node_get_thread(node),
                           &sc_fd_reader_sc_node_factory, args, n_args);
    sc_attr_free(fdr_attr);
    if( rc < 0 ) {
      sc_node_fwd_error(node, rc);
      goto error;
    }
    SC_TRY(sc_node_add_link(fdr, "", node, NULL));
  }

  SC_TEST(sc_callback_alloc(&rd->pool_cb, attr, sc_node_get_thread(node)) == 0);
  rd->pool_cb->cb_private = rd;
  rd->pool_cb->cb_handler_fn = sc_reader_buffers_available;
  sc_packet_list_init(&rd->in_pl);
  sc_packet_list_init(&rd->out_pl);
  rd->state = rs_file_header;
  rd->bytes_needed = sizeof(rd->file_hdr);
  rd->attr = sc_attr_dup(attr);
  SC_TRY(sc_attr_set_int(rd->attr, "private_pool", 1));
  return 0;

 error:
  sc_thread_mfree(sc_node_get_thread(node), rd);
  return -1;
}


const struct sc_node_factory sc_reader_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_reader",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_reader_init,
};

/** \endcond NODOC */
