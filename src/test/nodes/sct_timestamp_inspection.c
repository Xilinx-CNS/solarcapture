/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/*
 * test node which logs event to stdout if a timestamp value from
 * before 01-01-1980 00:00:01 is detected
 *
 * How to invoke the node:
 * SC_NODE_PATH=<path to library dir> SC_ATTR="require_hw_timestamps=1" ./solar_capture format=pcap-ns eth2=/dev/null sct_timestamp_inspection:nodelib=sct_timestamp_inspection.so
 *
 */

/* SolarCapture API specific includes */
#define SC_API_VER 1
#include <solar_capture_ext.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>         /* for declaration of PRIu64*/

#define TEN_YEARS_IN_SECS 315576000

static void sct_timestamp_inspection_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  const struct sc_node_link* next_hop = node->nd_private;
  /* put walke in here...*/
  struct sc_packet* walk = pl->head;
  while( walk ) {
    struct sc_packet* next = walk->next;
      /* inspect packet timestamp */
      if( walk->ts_sec < TEN_YEARS_IN_SECS ){
        printf("Seconds is %" PRIu64 ", nanos are %" PRIu32 "\n", walk->ts_sec,walk->ts_nsec);
      }
    walk = next;
  }
  
  sc_forward_list(node, next_hop, pl);
}


static void sct_timestamp_inspection_end_of_stream(struct sc_node* node)
{
  sc_node_link_end_of_stream(node, node->nd_private);
}


static int sct_timestamp_inspection_prep(struct sc_node* node,
                          const struct sc_node_link*const* links, int n_links)
{
  node->nd_private = (void*) sc_node_prep_get_link_or_free(node, "");
  return 0;
}


static int sct_timestamp_inspection_init(struct sc_node* node, const struct sc_attr* attr,
                          const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_prep_fn = sct_timestamp_inspection_prep;
    nt->nt_pkts_fn = sct_timestamp_inspection_pkts;
    nt->nt_end_of_stream_fn = sct_timestamp_inspection_end_of_stream;
  }
  node->nd_type = nt;
  return 0;
}


const struct sc_node_factory sct_timestamp_inspection_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sct_timestamp_inspection",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sct_timestamp_inspection_init,
};
