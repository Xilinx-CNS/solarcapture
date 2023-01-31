/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#define SC_API_VER 1
#include <solar_capture.h>

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <time.h>
#include <stdint.h>
#include <inttypes.h>


struct measure_ipg_state {
  const struct sc_node_link* next_hop;
  int                        iter;
  int                        warmup_iter;
  int                        n;
  int                        exit;
  struct timespec            ts_start;
};


static void measure_ipg_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct measure_ipg_state* st = node->nd_private;

  if( pl->num_pkts == 1 ) {
    sc_forward_list(node, st->next_hop, pl);
    if( st->n == st->warmup_iter ) {
      clock_gettime(CLOCK_REALTIME, &st->ts_start);
    }
    else if( st->n == st->iter + st->warmup_iter ) {
      struct timespec ts_end;
      clock_gettime(CLOCK_REALTIME, &ts_end);
      uint64_t nsec = (ts_end.tv_sec - st->ts_start.tv_sec) * 1000000000llu;
      nsec += ts_end.tv_nsec - st->ts_start.tv_nsec;
      nsec /= st->iter;
      printf("ipg_avg: %"PRId64"\n", nsec);
      if( st->exit )
        exit(0);
    }
    ++st->n;
  }
  else {
    fprintf(stderr, "measure_ipg: ERROR: received more than one packet\n");
    abort();
  }
}


static int measure_ipg_prep(struct sc_node* node,
                            const struct sc_node_link*const* links,
                            int n_links)
{
  struct measure_ipg_state* st = node->nd_private;

  if( (st->next_hop = sc_node_prep_get_link(node, "")) == NULL )
    return sc_node_set_error(node, EINVAL, "measure_ipg: no next hop!\n");

  return sc_node_prep_check_links(node);
}


static int measure_ipg_init(struct sc_node* node, const struct sc_attr* attr,
                           const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_pkts_fn = measure_ipg_pkts;
    nt->nt_prep_fn = measure_ipg_prep;
  }
  node->nd_type = nt;

  struct measure_ipg_state* st;
  st = sc_thread_calloc(sc_node_get_thread(node), sizeof(*st));
  node->nd_private = st;
  if( sc_node_init_get_arg_int(&st->iter, node, "iter", 1000000) < 0 )
    goto error;
  if( sc_node_init_get_arg_int(&st->warmup_iter, node, "warmup", 1000) < 0 )
    goto error;
  if( sc_node_init_get_arg_int(&st->exit, node, "exit", 0) < 0 )
    goto error;

  return 0;

 error:
  free(st);
  return -1;
}


const struct sc_node_factory sct_measure_ipg_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sct_measure_ipg",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = measure_ipg_init,
};
