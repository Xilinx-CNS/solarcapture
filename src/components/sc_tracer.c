/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \node{sc_tracer}
 *
 * \brief Write debug trace to standard error.
 *
 * \nodedetails
 * This node forwards its input to its output, and prints debug traces to
 * the standard error stream.  A message is emitted for each packet buffer
 * forwarded, giving various information about the packet buffer.
 *
 * The following output formats are available:
 * - `trace`: ::sc_packet metadata, in human-readable format
 * - `hexdump`: payload, as a hexadecimal dump
 * - `print`: payload, as printed strings.
 *
 * \nodeargs
 * Argument      | Optional? | Default | Type           | Description
 * ------------- | --------- | ------- | -------------- | -------------------------------------------------------------------------------------------------------
 * mode          | Yes       | trace   | ::SC_PARAM_STR | Either "trace", "hexdump", or "print".
 *
 * \cond NODOC
 */
#include <sc_internal.h>
#include <sc_internal/builtin_nodes.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>

struct sc_tracer;
typedef void (sc_tracer_pkt_fn)(struct sc_tracer*, struct sc_packet*);

struct sc_tracer {
  struct sc_node*            node;
  const struct sc_node_link* next_hop;
  FILE*                      fp;
  struct timespec            prev_ts;
  sc_tracer_pkt_fn*          pkt_fn;
};


static void sc_tracer_trace_pkt(struct sc_tracer* st, struct sc_packet* pkt)
{
  int i;
  uint64_t ipg_ns = (pkt->ts_sec - st->prev_ts.tv_sec) * (uint64_t) 1000000000;
  ipg_ns += pkt->ts_nsec - st->prev_ts.tv_nsec;
  st->prev_ts.tv_sec = pkt->ts_sec;
  st->prev_ts.tv_nsec = pkt->ts_nsec;
  struct sc_pkt* p = SC_PKT_FROM_PACKET(pkt);
  fprintf(st->fp, "  PKT: p%d frame_len=%d iovlen=%d frags_n=%d "
          "ts=%"PRIu64".%09"PRIu32" flags=%s%s%s%s%s%s ipg_ns=%"PRIu64"\n",
          p->sp_pkt_pool_id, pkt->frame_len, pkt->iovlen, pkt->frags_n,
          pkt->ts_sec, pkt->ts_nsec,
          (pkt->flags & SC_CSUM_ERROR)     ? "Csum"     : "",
          (pkt->flags & SC_CRC_ERROR)      ? "Crc"      : "",
          (pkt->flags & SC_TRUNCATED)      ? "Trunc"    : "",
          (pkt->flags & SC_MCAST_MISMATCH) ? "McastMis" : "",
          (pkt->flags & SC_UCAST_MISMATCH) ? "UcastMis" : "",
          (pkt->flags & SC_PACKED_STREAM)  ? "PackedStream" : "",
          ipg_ns);
  for( i = 0; i < pkt->iovlen; ++i )
    fprintf(st->fp, "    iov[%d] len=%d\n", i, (int) pkt->iov[i].iov_len);
}


static void sc_tracer_hexdump_pkt(struct sc_tracer* st, struct sc_packet* pkt)
{
  int i, j;
  fprintf(st->fp, "[%s] packet (frame_len=%d iov_len=%lu):\n",
          st->node->nd_name, pkt->frame_len, pkt->iov[0].iov_len);

  SC_TEST(pkt->iovlen == 1);
  uint8_t* data = (uint8_t*) pkt->iov[0].iov_base;
  int len = pkt->iov[0].iov_len;
  int extra = (len % 16) ? 16 - (len % 16) : 0;
  char line[128]; /* max line length is ~70 bytes */
  bool zero_line = false;
  bool skipping = false;

  char* buf = line;
  for( i = 0; i <= len + extra; ++i ) {
    if( ! (i % 16) ) {
      if( buf != line ) {
        if( zero_line && i < len + extra) {
          if( ! skipping )
            fprintf(st->fp, "...\n");
          skipping = true;
        }
        else {
          fprintf(st->fp, "%s\n", line);
          zero_line = true;
          skipping = false;
        }
        buf = line;
      }
      buf += sprintf(buf, "%04x ", i);
    }
    else if( ! (i % 8) )
      buf += sprintf(buf, " ");
    if( i < len ) {
      if( data[i] )
        zero_line = false;
      buf += sprintf(buf, "%02x ", data[i]);
    }
    else {
      buf += sprintf(buf, "   ");
    }
    if( i % 16 == 15 ) {
      for( j = i - 15; j <= i; ++j ) {
        char c = j < len ? data[j] : ' ';
        buf += sprintf(buf, "%c", c < 32 ? '.' : (c > 127 ? '.' : c) );
      }
    }
  }

  fprintf(st->fp, "\n\n");
}


static void sc_tracer_print_pkt(struct sc_tracer* st, struct sc_packet* pkt)
{
  int i;
  for( i = 0; i < pkt->iovlen; ++i )
    fprintf(st->fp, "%*s", (int) pkt->iov[i].iov_len,
            (char*) pkt->iov[i].iov_base);
}

static void sc_tracer_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct sc_tracer* st = node->nd_private;
  struct sc_packet* next;
  struct sc_packet* pkt;

  fprintf(st->fp, "sc_tracer: [%s] num_pkts=%d num_frags=%d\n",
          node->nd_name, pl->num_pkts, pl->num_frags);

  for( next = pl->head; (pkt = next) && ((next = next->next), 1); )
    st->pkt_fn(st, pkt);

  sc_forward_list(node, st->next_hop, pl);
}


static void sc_tracer_end_of_stream(struct sc_node* node)
{
  struct sc_tracer* st = node->nd_private;
  fprintf(st->fp, "sc_tracer: [%s] end-of-stream\n", node->nd_name);
  sc_node_link_end_of_stream(node, st->next_hop);
}


static int sc_tracer_prep(struct sc_node* node,
                          const struct sc_node_link*const* links, int n_links)
{
  struct sc_tracer* st = node->nd_private;
  st->next_hop = sc_node_prep_get_link_or_free(node, "");
  return sc_node_prep_check_links(node);
}


static int sc_tracer_init(struct sc_node* node, const struct sc_attr* attr,
                          const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_prep_fn = sc_tracer_prep;
    nt->nt_pkts_fn = sc_tracer_pkts;
    nt->nt_end_of_stream_fn = sc_tracer_end_of_stream;
  }
  node->nd_type = nt;

  struct sc_tracer* st;
  st = sc_thread_calloc(sc_node_get_thread(node), sizeof(*st));
  node->nd_private = st;
  st->node = node;
  st->fp = stderr;

  const char* tmp;
  if( sc_node_init_get_arg_str(&tmp, node, "mode", "trace" ) < 0 )
    return -1;
  if( !strcmp(tmp, "trace") )
    st->pkt_fn = sc_tracer_trace_pkt;
  else if( !strcmp(tmp, "hexdump") )
    st->pkt_fn = sc_tracer_hexdump_pkt;
  else if( !strcmp(tmp, "print") )
    st->pkt_fn = sc_tracer_print_pkt;
  else
    return sc_node_set_error(node, EINVAL, "ERROR: %s: invalid mode '%s'\n",
                             __func__, tmp);

  return 0;
}


const struct sc_node_factory sc_tracer_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_tracer",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_tracer_init,
};

/** \endcond NODOC */
