/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \node{sc_sim_work}
 *
 * \brief Simulate doing CPU intensive work on each packet.
 *
 * \nodedetails
 * Simulate the behaviour of a node that performs CPU intensive work on the
 * packets it handles.
 *
 * \nodeargs
 * Argument      | Optional? | Default | Type           | Description
 * ------------- | --------- | ------- | -------------- | -------------------------------------------------------------------------------------------------------
 * per_packet_ns | Yes       | 0       | ::SC_PARAM_INT | Amount of per-packet work
 * per_batch_ns  | Yes       | 0       | ::SC_PARAM_INT | Amount of per-batch work
 * touch_wrapper | Yes       | 0       | ::SC_PARAM_INT | Whether to touch per-packet wrapper
 * touch_payload | Yes       | 0       | ::SC_PARAM_INT | Whether to read frame data
 *
 * \cond NODOC
 */
#include <sc_internal.h>
#include <sc_internal/builtin_nodes.h>
#include <sc_internal/packed_stream.h>

#include <time.h>


struct sc_sim_work {
  struct sc_node*            node;
  const struct sc_node_link* next_hop;
  int                        pkt_work_ns;
  int                        batch_work_ns;
  int                        touch_wrapper;
  int                        touch_payload;
  uint64_t                   touch_accumulator;
};


static void touch_iov(uint64_t* accum, const struct iovec* iov, int iovlen)
{
  uint64_t sum = 0;
  do {
    const uint8_t* p = iov->iov_base;
    int left = iov->iov_len;
    while( left >= 8 ) {
      sum += *(const uint64_t*) p;
      p += 8;
      left -= 8;
    }
    if( left & 4 ) {
      sum += *(const uint32_t*) p;
      p += 4;
    }
    if( left & 2 ) {
      sum += *(const uint16_t*) p;
      p += 2;
    }
    if( left & 1 )
      sum += *(const uint8_t*) p;
  } while( --iovlen > 0 && (++iov, 1) );
  *accum += sum;
}


static inline void ts_add_ns(struct timespec* ts, int ns)
{
  ts->tv_sec += ns / 1000000000;
  if( (ts->tv_nsec += ns % 1000000000) >= 1000000000 ) {
    ts->tv_nsec -= 1000000000;
    ts->tv_sec += 1;
  }
}


static void sc_sim_work_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct sc_sim_work* st = node->nd_private;
  struct timespec end, now;
  struct sc_packet* next;
  struct sc_packet* pkt;
  int num_pkts;

  clock_gettime(CLOCK_REALTIME, &now);

  if( (st->touch_wrapper || st->pkt_work_ns) &&
      (pl->head->flags & SC_PACKED_STREAM) ) {
    num_pkts = 0;
    for( next = pl->head; (pkt = next) && ((next = next->next), 1); ) {
      if( st->touch_payload )
        touch_iov(&st->touch_accumulator, pkt->iov, pkt->iovlen);
      if( st->touch_wrapper || st->pkt_work_ns ) {
        struct sc_packed_packet* ps_pkt = sc_packet_packed_first(pkt);
        struct sc_packed_packet* ps_end = sc_packet_packed_end(pkt);
        for( ; ps_pkt < ps_end; ps_pkt = sc_packed_packet_next(ps_pkt) )
          ++num_pkts;
      }
    }
  }
  else {
    num_pkts = pl->num_pkts;
    if( st->touch_wrapper )
      for( next = pl->head; (pkt = next) && ((next = next->next), 1); )
        if( st->touch_payload )
          touch_iov(&st->touch_accumulator, pkt->iov, pkt->iovlen);
  }

  end = now;
  ts_add_ns(&end, st->batch_work_ns + num_pkts * st->pkt_work_ns);
  while( ! sc_timespec_le(end, now) )
    clock_gettime(CLOCK_REALTIME, &now);

  sc_forward_list(node, st->next_hop, pl);
}


static void sc_sim_work_end_of_stream(struct sc_node* node)
{
  struct sc_sim_work* st = node->nd_private;
  sc_node_link_end_of_stream(node, st->next_hop);
}


static int sc_sim_work_prep(struct sc_node* node,
                          const struct sc_node_link*const* links, int n_links)
{
  struct sc_sim_work* st = node->nd_private;
  st->next_hop = sc_node_prep_get_link_or_free(node, "");
  return sc_node_prep_check_links(node);
}


static int sc_sim_work_init(struct sc_node* node, const struct sc_attr* attr,
                          const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_prep_fn = sc_sim_work_prep;
    nt->nt_pkts_fn = sc_sim_work_pkts;
    nt->nt_end_of_stream_fn = sc_sim_work_end_of_stream;
  }
  node->nd_type = nt;

  int pkt_work_ns, batch_work_ns, touch_wrapper, touch_payload;
  if( sc_node_init_get_arg_int(&pkt_work_ns, node, "per_packet_ns", 0) < 0 )
    return -1;
  if( sc_node_init_get_arg_int(&batch_work_ns, node, "per_batch_ns", 0) < 0 )
    return -1;
  if( sc_node_init_get_arg_int(&touch_wrapper, node, "touch_wrapper", 0) < 0 )
    return -1;
  if( sc_node_init_get_arg_int(&touch_payload, node, "touch_payload", 0) < 0 )
    return -1;

  struct sc_sim_work* st;
  st = sc_thread_calloc(sc_node_get_thread(node), sizeof(*st));
  node->nd_private = st;
  st->node = node;
  st->pkt_work_ns = pkt_work_ns;
  st->batch_work_ns = batch_work_ns;
  st->touch_wrapper = touch_wrapper | touch_payload;
  st->touch_payload = touch_payload;
  return 0;
}


const struct sc_node_factory sc_sim_work_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_sim_work",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_sim_work_init,
};
/** \endcond NODOC */
