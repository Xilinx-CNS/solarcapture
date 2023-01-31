/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#include <sc_internal.h>
#include <sc_internal/builtin_nodes.h>

#include <errno.h>


struct sct_dump_pkts {
  struct sc_node*            node;
  const struct sc_node_link* next_hop;
  const char*                label;
};

static void hexdump(struct sct_dump_pkts* dp, struct sc_packet* pkt) {
  int i, j;
  printf("%s packet (len=%d):", dp->label, (int)pkt->frame_len);

  SC_TEST(pkt->iovlen == 1);
  uint8_t* data = (uint8_t*) pkt->iov[0].iov_base;
  int len = pkt->iov[0].iov_len;
  int extra = (len % 16) ? 16 - (len % 16) : 0;

  for( i = 0; i < len + extra; ++i ) {
    if( ! (i % 16) ) {
      printf("\n%04x ", i);
    }
    else if( ! (i % 8) )
      printf(" ");
    if( i < len )
      printf("%02x ", data[i]);
    else
      printf("   ");
    if( i % 16 == 15 ) {
      for( j = i - 15; j <= i; ++j ) {
        char c = j < len ? data[j] : ' ';
        printf("%c", c < 32 ? '.' : (c > 127 ? '.' : c) );
      }
    }
  }

  printf("\n\n");
}


static void sct_dump_pkts_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct sct_dump_pkts* dp = node->nd_private;
  struct sc_packet* pkt = pl->head;
  while( pkt ) {
    hexdump(dp, pkt);
    pkt = pkt->next;
  }
  sc_forward_list(node, dp->next_hop, pl);
}


static void sct_dump_pkts_end_of_stream(struct sc_node* node)
{
  struct sct_dump_pkts* dp = node->nd_private;
  sc_node_link_end_of_stream(node, dp->next_hop);
}


static int sct_dump_pkts_prep(struct sc_node* node,
                          const struct sc_node_link*const* links, int n_links)
{
  struct sct_dump_pkts* dp = node->nd_private;
  dp->next_hop = sc_node_prep_get_link_or_free(node, "");
  return 0;
}


static int sct_dump_pkts_init(struct sc_node* node, const struct sc_attr* attr,
                          const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_prep_fn = sct_dump_pkts_prep;
    nt->nt_pkts_fn = sct_dump_pkts_pkts;
    nt->nt_end_of_stream_fn = sct_dump_pkts_end_of_stream;
  }
  node->nd_type = nt;

  struct sct_dump_pkts* dp;
  dp = sc_thread_calloc(sc_node_get_thread(node), sizeof(*dp));
  dp->node = node;
  node->nd_private = dp;

  const char* tmp;
  if( sc_node_init_get_arg_str(&tmp, node, "label", "sct_dump_pkts") < 0 )
    return -1;
  dp->label = strdup(tmp);

  return 0;
}


const struct sc_node_factory sct_dump_pkts_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sct_dump_pkts",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sct_dump_pkts_init,
};
