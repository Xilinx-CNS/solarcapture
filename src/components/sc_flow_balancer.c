/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \node{sc_flow_balancer}
 *
 * \brief This node distributes load by spreading packets over its output
 * links while preserving flow affinity.
 *
 * \nodedetails
 * This node either forwards or copies packets from its input to its
 * outputs (see copy_mode).  It attempts to distribute load evenly over the
 * outputs, whilst also preserving flow affinity.  That is, packets from
 * the same flow are directed to the same output, and both directions in a
 * conversation are directed to the same output.
 *
 * NB. Both directions in a TCP conversation are directed to the same
 * output only if the communicating hosts have different IP addresses.
 * That should always be true unless you are analysing packets on a
 * loopback interface.
 *
 * The flow key always includes VLAN ID and ether_type.  For IPv4 packets
 * it also includes the IP addresses and protocol, and for TCP it includes
 * the port numbers.
 *
 * The input can be in normal or packed-stream format.  When
 * copy_mode=copy, the output is in packed-stream format.  When
 * copy_mode=zc the output is normal format.
 *
 * When mode=round-robin new flows are assigned to each output in
 * round-robin order.  When mode=estimate an estimate of the current load
 * experienced by each output is maintained, and new flows are directed to
 * the output with the lowest estimated load.
 *
 * \nodeargs
 * Argument            | Optional? | Default  | Type           | Description
 * ------------------- | --------- | -------- | -------------- | --------------------------------------------------------------------------------------------------------------------------------
 * copy_mode           | No        |          | ::SC_PARAM_STR | Copy from input to output ('copy') or use zero-copy ('zc').
 * mode                | No        |          | ::SC_PARAM_STR | Balancing mode; 'estimate' or 'round-robin'.
 * flow_table_capacity | Yes       | 1024     | ::SC_PARAM_INT | Initial capacity of the flow table.
 * flush_ns            | Yes       | 10000000 | ::SC_PARAM_INT | Flush timeout when copy_mode=copy.
 * max_grow_attempts   | Yes       | 3        | ::SC_PARAM_INT | The maximum number of attempts the flow balancer will make when trying to grow the hash table.
 *
 * \outputlinks
 * An outgoing link named "input" is treated specially: It receives the
 * input packets when copy_mode=copy.
 *
 * \nodestatscopy{sc_flow_balancer}
 *
 * \cond NODOC
 */

/* NOTES / TODO:
 * - Look at effect of alphas.  Can we auto-tune?
 * - Consider option to use non-temporal stores when copying packet if we
 *     detect that consumer is significantly behind.
 * - Detect whether consumer is on same numa node or different, and if on
 *     different node use non-temporal stores for copy
 * - Detect whether output is connected to a consumer.  If not, don't send
 *     packets that way.  (Perhaps have sc_shm_broadcast send messages?)
 * - Need to think about how big output pools should be and provide way to
 *     configure.
 * - Make packed-stream on output a non-default option
 * - Make timeouts, alpha etc. tunable
 */

#include <sc_internal.h>
#include <sc_internal/builtin_nodes.h>
#include <sc_internal/packed_stream.h>
#include <solar_capture/nodes/subnode_helper.h>
#include <solar_capture/hash_table.h>

#define SC_TYPE_TEMPLATE <sc_flow_balancer_types_tmpl.h>
#define SC_DECLARE_TYPES sc_flow_balancer_stats_declare
#include <solar_capture/declare_types.h>

#include <errno.h>
#include <assert.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>


#define N_FLOW_TYPES  2


#define IS_TCP            0x40

#define FB_ET_OTHER       0
#define FB_ET_IP4         1
#define FB_ET_IP6         2
#define FB_IPP_OTHER      0
#define FB_IPP_TCP        1


#if __BYTE_ORDER == __LITTLE_ENDIAN
# define HTONS_CONST(x)  ((uint16_t) (((x) >> 8) | ((x) << 8)))
#else
# define HTONS_CONST(x)  (x)
#endif

#define PTR_SUB(p1, p2)  ((uintptr_t) (p1) - (uintptr_t) (p2))


#ifdef NDEBUG
static inline void __no_tracef(const char* fmt, ...) { }
#define tracef(fmt, ...)        __no_tracef(fmt, __VA_ARGS__)
#define trace(str)              do{ (void) (str); }while(0)
#else
# define tracef(fmt, ...)       fprintf(stderr, "%-24s "fmt"\n",        \
                                        __func__, __VA_ARGS__)
# define trace(str)             fprintf(stderr, "%-24s %s\n", __func__, (str))
#endif


struct flow_key {
  uint32_t ip[2];
  uint16_t port[2];
  unsigned vlan_id  :12;
  unsigned eth_type :2;
  unsigned ip_proto :2;
} __attribute__((packed));


typedef uint16_t  fb_tstamp_t;


struct flow_state {
  uint8_t          output_id;
  uint8_t          flow_type;
  fb_tstamp_t      last_pkt_tstamp;
  struct sc_dlist  link;
} __attribute__((packed));


struct pkt_info {
  struct flow_key  key;
  uint8_t          tcp_flags;
};


struct fb_output {
  struct sc_subnode_helper*  snh;
  struct sc_packet*          pkt;
  struct sc_flow_balancer_output_stats* stats;
  struct sc_callback*        flush_timer;
  unsigned                   fbo_id;

  uint64_t                   work_accum;
  uint64_t                   load_added;
};


struct flow_balancer {
  struct sc_attr*            attr;
  struct sc_thread*          thread;
  const struct sc_node_link* free_input_hop;
  struct fb_output**         outputs;
  bool                       zero_copy;
  struct sc_hash_table*      flow_table;
  struct sc_callback*        timer;
  struct sc_flow_balancer_stats* stats;
  unsigned                   n_outputs;
  unsigned                   flow_table_capacity;
  uint16_t                   tpid_ne;
  uint16_t                   per_pkt_overhead;
  fb_tstamp_t                timeout[N_FLOW_TYPES];
  struct fb_output*        (*select_output_fn)(struct flow_balancer*);
  uint64_t                   alpha_short;
  uint64_t                   alpha_long;
  uint64_t                   flush_ns;
  int                        n_grow_attempts;

  struct sc_dlist            lru[N_FLOW_TYPES];
  unsigned                   next_output;
  unsigned                   prev_n_flows;
};


static uint64_t fb_output_load_score(const struct fb_output* fbo)
{
  return ( fbo->stats->load_est_long + fbo->load_added );
}


static inline uint64_t exp_mov_avg(uint64_t prev_ma, uint64_t new_sample,
                                   uint64_t alpha_16bit)
{
  return ( ((alpha_16bit * new_sample) >> 16u) +
           (((65536 - alpha_16bit) * prev_ma) >> 16u) );
}


static void fb_output_periodic(struct flow_balancer* fb, struct fb_output* fbo)
{
  struct sc_flow_balancer_output_stats* s = fbo->stats;
  s->load_est_short = exp_mov_avg(s->load_est_short, fbo->work_accum,
                                  fb->alpha_short);
  s->load_est_long = exp_mov_avg(s->load_est_long, fbo->work_accum,
                                 fb->alpha_long);
  s->total_work += fbo->work_accum;
  fbo->work_accum = 0;
  fbo->load_added = 0;
}


static void fb_expire_flows(struct flow_balancer* fb, struct sc_dlist* list,
                            fb_tstamp_t now, fb_tstamp_t timeout)
{
  int n = 0;
  while( ! sc_dlist_is_empty(list) ) {
    struct flow_state* fs = SC_CONTAINER(struct flow_state, link, list->next);
    if( now - fs->last_pkt_tstamp < timeout ) {
      if( n )
        tracef("EXPIRED %d (timeout=%d)", n, timeout);
      return;
    }
    struct fb_output* fbo = fb->outputs[fs->output_id];
    --(fbo->stats->n_flows);
    sc_dlist_remove(&(fs->link));
    int rc = sc_hash_table_del_val(fb->flow_table, fs);
    (void) rc;
    assert( rc == 0 );
    ++n;
  }
}


static void sc_flow_balancer_periodic(struct sc_callback* cb, void* event_info)
{
  struct flow_balancer* fb = cb->cb_private;
  int i;
  for( i = 0; i < N_FLOW_TYPES; ++i )
    fb_expire_flows(fb, &(fb->lru[i]),
                    fb->thread->cur_time.tv_sec, fb->timeout[i]);

  uint64_t work_accum = 0;
  unsigned n_flows = 0;
  for( i = 0; i < fb->n_outputs; ++i ) {
    struct fb_output* fbo = fb->outputs[i];
    work_accum += fbo->work_accum;
    n_flows += fbo->stats->n_flows;
    fb_output_periodic(fb, fbo);
  }
  unsigned avg_n_flows = (fb->prev_n_flows + n_flows) / 2;
  fb->prev_n_flows = n_flows;
  if( avg_n_flows ) {
    uint64_t load_per_flow = work_accum / avg_n_flows;
    fb->stats->avg_flow_load = exp_mov_avg(fb->stats->avg_flow_load,
                                           load_per_flow, fb->alpha_long);
  }

  sc_timer_expire_after_ns(cb, 100*1000*1000);
}


static void get_pkt_info(struct flow_balancer* fb, struct pkt_info* pinf,
                         const void* frame_start, unsigned cap_len)
{
  memset(&(pinf->key), 0, sizeof(pinf->key));
  pinf->tcp_flags = 0;

  const struct ether_header* eth = frame_start;
  const uint16_t* p_ether_type = &eth->ether_type;
  if( *p_ether_type == fb->tpid_ne ) {
    pinf->key.vlan_id = ntohs(p_ether_type[1]) & 0xfff;
    p_ether_type += 2;
  }

  switch( *p_ether_type ) {
  case HTONS_CONST(ETHERTYPE_IP): {
    const struct iphdr* ip4 = (void*) (p_ether_type + 1);
    const uint16_t* l4u16 = (void*) ((uint32_t*) ip4 + ip4->ihl);
    if( PTR_SUB(l4u16, frame_start) <= cap_len ) {
      pinf->key.eth_type = FB_ET_IP4;
      int dir = ip4->saddr < ip4->daddr;
      pinf->key.ip[dir] = ip4->saddr;
      pinf->key.ip[dir^1] = ip4->daddr;
      if( ip4->protocol == IPPROTO_TCP &&
          (ip4->frag_off & htons(0x3fff)) == 0 ) {
        const struct tcphdr* tcp = (void*) l4u16;
        if( PTR_SUB(tcp + 1, frame_start) <= cap_len ) {
          pinf->key.ip_proto = FB_IPP_TCP;
          pinf->key.port[dir] = tcp->source;
          pinf->key.port[dir^1] = tcp->dest;
          pinf->tcp_flags = ((const uint8_t*) l4u16)[13];
          pinf->tcp_flags |= IS_TCP;
        }
      }
      else {
        assert( pinf->key.ip_proto == FB_IPP_OTHER );
        assert( pinf->key.port[0] == 0 );
        assert( pinf->key.port[1] == 0 );
      }
    }
    break;
  }
  default: {
    assert( pinf->key.eth_type == FB_ET_OTHER );
    break;
  }
  }
}


static int try_grow_table(struct flow_balancer* fb, unsigned new_capacity,
                          struct sc_hash_table** new_ft, struct sc_dlist* new_lru)
{
  /* ?? fixme: error handling */
  SC_TEST( sc_hash_table_alloc(new_ft, sizeof(struct flow_key),
                               sizeof(struct flow_state), new_capacity) == 0 );

  int i;
  for( i = 0; i < N_FLOW_TYPES; ++i ) {
    struct flow_state* fs;
    SC_DLIST_FOR_EACH_OBJ(&(fb->lru[i]), fs, link) {
      const void* key = sc_hash_table_val_to_key(fb->flow_table, fs);
      void* val;
      if ( sc_hash_table_get(*new_ft, key, true, &val) != 1 ) {
        /* no need to worry about any previously created new_fs', these are freed with the hash table */
        sc_hash_table_free(*new_ft);
        return -1;
      }
      struct flow_state* new_fs = val;
      new_fs->output_id = fs->output_id;
      new_fs->flow_type = fs->flow_type;
      new_fs->last_pkt_tstamp = fs->last_pkt_tstamp;
      sc_dlist_push_tail(&(new_lru[i]), &(new_fs->link));
    }
  }
  return 0;
}


static void flow_table_grow(struct flow_balancer* fb)
{
  unsigned new_capacity = fb->flow_table_capacity;
  struct sc_hash_table* new_ft;
  struct sc_dlist new_lru[N_FLOW_TYPES];
  bool success = false;
  unsigned i;
  for( i = 0; i < fb->n_grow_attempts; ++i ) {
    new_capacity *= 2;
    SC_TEST( new_capacity > fb->flow_table_capacity );
    tracef("trying new_capacity=%u attempt %d of %d",
      new_capacity, i + 1, fb->n_grow_attempts);
    unsigned j;
    for( j = 0; j < N_FLOW_TYPES; ++j )
      sc_dlist_init(&new_lru[j]);
    if( try_grow_table(fb, new_capacity, &new_ft, new_lru) == 0 ) {
      tracef("Successfully grown hash table to capacity %d", new_capacity);
      success = true;
      break;
    }
  }

  if( !success ) {
    struct sc_session* session = sc_thread_get_session(fb->thread);
    sc_err(session,
      "%s: ERROR: Failed to grow hash table (old capacity = %d, new capacity = %d, attempts = %d)",
      __func__, fb->flow_table_capacity, new_capacity, fb->n_grow_attempts
    );
    SC_TEST( 0 );
  }

  for( i = 0; i < N_FLOW_TYPES; ++i )
    sc_dlist_rehome(&(fb->lru[i]), &(new_lru[i]));
  /* no need to worry about any previously created list elements of fb->lrus', these are freed with the hash table */
  sc_hash_table_free(fb->flow_table);
  fb->flow_table = new_ft;
  fb->flow_table_capacity = new_capacity;
  fb->stats->flow_table_capacity = fb->flow_table_capacity;
}


static struct fb_output* select_output_round_robin(struct flow_balancer* fb)
{
  unsigned output_id = fb->next_output;
  if( ++(fb->next_output) == fb->n_outputs )
    fb->next_output = 0;
  return fb->outputs[output_id];
}


static struct fb_output* select_output_estimate(struct flow_balancer* fb)
{
  unsigned output_id;
  struct fb_output* sel = fb->outputs[0];
  for( output_id = 1; output_id < fb->n_outputs; ++output_id ) {
    struct fb_output* fbo = fb->outputs[output_id];
    if( fb_output_load_score(fbo) < fb_output_load_score(sel) )
      sel = fbo;
  }
  tracef("[%u] score=%u", sel->fbo_id, (unsigned) fb_output_load_score(sel));
  return sel;
}


static struct fb_output* get_output(struct flow_balancer* fb,
                                    struct pkt_info* pinf)
{
  struct fb_output* fbo;
  void* val;
 again:;
  int rc = sc_hash_table_get(fb->flow_table, &(pinf->key), true, &val);
  struct flow_state* fs = val;
  switch( rc ) {
  case 0:  /* found existing flow */
    assert( fs->output_id < fb->n_outputs );
    sc_dlist_remove(&(fs->link));
    sc_dlist_push_tail(&(fb->lru[fs->flow_type]), &(fs->link));
    fs->last_pkt_tstamp = fb->thread->cur_time.tv_sec;
    return fb->outputs[fs->output_id];
  case 1:  /* add new flow */
    fbo = fb->select_output_fn(fb);
    fs->output_id = fbo->fbo_id;
    fs->flow_type = 0;  /*??*/
    sc_dlist_push_tail(&(fb->lru[fs->flow_type]), &(fs->link));
    fs->last_pkt_tstamp = fb->thread->cur_time.tv_sec;
    ++(fbo->stats->n_flows);
    ++(fbo->stats->total_flows);
    fbo->load_added += fb->stats->avg_flow_load;
    return fbo;
  case -ENOSPC:
    flow_table_grow(fb);
    goto again;
  default:
    SC_TEST( 0 );
    return NULL;
  }
}


static void fb_output_emit(struct fb_output* fbo)
{
  void* end = fbo->pkt->iov[0].iov_base;
  fbo->pkt->iov[0].iov_base = SC_PKT_FROM_PACKET(fbo->pkt)->sp_buf;
  fbo->pkt->iov[0].iov_len = PTR_SUB(end, fbo->pkt->iov[0].iov_base);
  sc_forward2(fbo->snh->sh_links[0], fbo->pkt);
  fbo->pkt = NULL;
}


static void fb_output_flush_cb(struct sc_callback* cb, void* event_info)
{
  struct fb_output* fbo = cb->cb_private;
  if( fbo->pkt != NULL )
    fb_output_emit(fbo);
}


static void copy_to_output(struct flow_balancer* fb, struct fb_output* fbo,
                           const void* frame_start, unsigned cap_len,
                           unsigned orig_len, uint64_t ts_sec, uint32_t ts_nsec)
{
  if( fbo->pkt == NULL )
    goto no_pkt;
  if( fbo->pkt->iov[0].iov_len < cap_len + sizeof(struct sc_packed_packet) )
    goto emit;
 have_pkt_and_space:;
  struct sc_packed_packet* ps_pkt = fbo->pkt->iov[0].iov_base;
  ps_pkt->ps_next_offset = cap_len + sizeof(*ps_pkt);
  ps_pkt->ps_pkt_start_offset = sizeof(*ps_pkt);
  ps_pkt->ps_flags = 0; /* ?? fixme */
  ps_pkt->ps_cap_len = cap_len;
  ps_pkt->ps_orig_len = orig_len;
  ps_pkt->ps_ts_sec = ts_sec;
  ps_pkt->ps_ts_nsec = ts_nsec;
  memcpy(ps_pkt + 1, frame_start, cap_len);
  fbo->pkt->iov[0].iov_base = (uint8_t*) ps_pkt + ps_pkt->ps_next_offset;
  fbo->pkt->iov[0].iov_len -= ps_pkt->ps_next_offset;
  return;

 emit:;
  fb_output_emit(fbo);
 no_pkt:;
  struct sc_packet_list pl;
  __sc_packet_list_init(&pl);
  sc_pool_get_packets(&pl, fbo->snh->sh_pool, 1, 1);
  if( sc_packet_list_is_empty(&pl) ) {
    ++(fbo->stats->drops);
    /* ?? todo: option to drop this flow? */
    return;
  }
  fbo->pkt = pl.head;
  fbo->pkt->flags = SC_PACKED_STREAM;
  SC_TEST( fbo->pkt->iov[0].iov_len >= cap_len + sizeof(*ps_pkt) );
  sc_timer_expire_after_ns(fbo->flush_timer, fb->flush_ns);
  goto have_pkt_and_space;
}


static void sc_flow_balancer_copy_pkt(struct flow_balancer* fb,
                                      const void* frame_start, unsigned cap_len,
                                      unsigned orig_len,
                                      uint64_t ts_sec, uint32_t ts_nsec)
{
  struct pkt_info pinf;
  get_pkt_info(fb, &pinf, frame_start, cap_len);
  struct fb_output* fbo = get_output(fb, &pinf);
  fbo->work_accum += fb->per_pkt_overhead + cap_len;
  copy_to_output(fb, fbo, frame_start, cap_len, orig_len, ts_sec, ts_nsec);
}


static void sc_flow_balancer_copy_pkts(struct sc_node* node,
                                       struct sc_packet_list* pl)
{
  struct flow_balancer* fb = node->nd_private;
  struct sc_packet* next;
  struct sc_packet* pkt;

  for( next = pl->head; (pkt = next) && ((next = next->next), 1); )
    if( ! (pkt->flags & SC_PACKED_STREAM) ) {
      assert( pkt->iovlen == 1 );
      sc_flow_balancer_copy_pkt(fb, pkt->iov[0].iov_base, pkt->iov[0].iov_len,
                                pkt->frame_len, pkt->ts_sec, pkt->ts_nsec);
    }
    else {
      struct sc_packed_packet* ps_pkt = sc_packet_packed_first(pkt);
      struct sc_packed_packet* ps_end = sc_packet_packed_end(pkt);
      for( ; ps_pkt < ps_end; ps_pkt = sc_packed_packet_next(ps_pkt) )
        sc_flow_balancer_copy_pkt(fb, sc_packed_packet_payload(ps_pkt),
                                  ps_pkt->ps_cap_len, ps_pkt->ps_orig_len,
                                  ps_pkt->ps_ts_sec, ps_pkt->ps_ts_nsec);
    }
  sc_forward_list2(fb->free_input_hop, pl);
}


static void sc_flow_balancer_zc_pkts(struct sc_node* node,
                                     struct sc_packet_list* pl)
{
  struct flow_balancer* fb = node->nd_private;
  struct sc_packet* next;
  struct sc_packet* pkt;

  for( next = pl->head; (pkt = next) && ((next = next->next), 1); ) {
    assert( ! (pkt->flags & SC_PACKED_STREAM) );
    assert( pkt->iovlen == 1 );
    struct pkt_info pinf;
    get_pkt_info(fb, &pinf, pkt->iov[0].iov_base, pkt->iov[0].iov_len);
    struct fb_output* fbo = get_output(fb, &pinf);
    fbo->work_accum += fb->per_pkt_overhead + pkt->iov[0].iov_len;
    sc_forward2(fbo->snh->sh_links[0], pkt);
  }
}


static void sc_flow_balancer_end_of_stream(struct sc_node* node)
{
  struct flow_balancer* fb = node->nd_private;
  unsigned output_id;
  for( output_id = 0; output_id < fb->n_outputs; ++output_id ) {
    struct fb_output* fbo = fb->outputs[output_id];
    SC_TEST( fbo->snh->sh_n_links == 1 );
    SC_TEST( fbo->snh->sh_free_link == NULL );
    sc_callback_remove(fbo->flush_timer);
    if( fbo->pkt != NULL )
      fb_output_emit(fbo);
    sc_node_link_end_of_stream2(fbo->snh->sh_links[0]);
  }
}


static int sc_flow_balancer_add_link(struct sc_node* from_node,
                                     const char* link_name,
                                     struct sc_node* to_node,
                                     const char* to_name_opt)
{
  struct flow_balancer* fb = from_node->nd_private;

  if( strcmp(link_name, "input") == 0 ) {
    if( fb->zero_copy )
      return sc_node_set_error(from_node, EINVAL, "sc_flow_balancer: ERROR: "
                               "'input' link is not available when "
                               "copy_mode=zc\n");
    else
      return sc_node_add_link(from_node, link_name, to_node, to_name_opt);
  }

  unsigned output_id = (fb->n_outputs)++;
  SC_REALLOC(&fb->outputs, fb->n_outputs);
  struct fb_output* fbo = sc_thread_calloc(fb->thread, sizeof(*fbo));
  SC_TEST( fbo != NULL );
  fb->outputs[output_id] = fbo;
  struct sc_arg args[] = {
    SC_ARG_INT("with_pool", ! fb->zero_copy),
    SC_ARG_INT("with_free_link", 0),
  };
  if( fb->attr->buf_size < 0 )
    fb->attr->buf_size = 65536;
  struct sc_node* snh_node;
  SC_TRY( sc_node_alloc_named(&snh_node, fb->attr,
                              sc_node_get_thread(from_node),
                              "sc_subnode_helper", NULL,
                              args, sizeof(args) / sizeof(args[0])) );
  fbo->snh = sc_subnode_helper_from_node(snh_node);
  int rc = sc_node_add_link(snh_node, "", to_node, to_name_opt);
  if( rc < 0 ) {
    /* ?? fixme: leaking the subnode */
    --(fb->n_outputs);
    return rc;
  }
  sc_node_add_info_int(snh_node, "output_id", output_id);
  sc_node_add_info_str(snh_node, "output_name", link_name);
  sc_node_export_state(snh_node, "sc_flow_balancer_output_stats",
                       sizeof(*(fbo->stats)), &(fbo->stats));
  fbo->stats->n_flows = 0;
  fbo->stats->total_flows = 0;
  fbo->stats->total_work = 0;
  fbo->stats->load_est_short = 0;
  fbo->stats->load_est_long = 0;
  SC_TRY( sc_callback_alloc(&(fbo->flush_timer), fb->attr, fb->thread) );
  fbo->flush_timer->cb_private = fbo;
  fbo->flush_timer->cb_handler_fn = fb_output_flush_cb;
  fbo->pkt = NULL;
  fbo->fbo_id = output_id;
  fbo->work_accum = 0;
  if( fb->zero_copy )
    SC_TRY( sc_node_add_link(from_node, "", snh_node, NULL) );
  return 0;
}


static int sc_flow_balancer_prep(struct sc_node* node,
                                 const struct sc_node_link*const* links,
                                 int n_links)
{
  struct flow_balancer* fb = node->nd_private;
  if( fb->n_outputs == 0 )
    return sc_node_set_error(node, ENOENT,
                             "sc_flow_balancer: no outgoing links!\n");
  int rc;
  if( fb->zero_copy ) {
    /* There are links from this node to the output nodes, but they are
     * never used.  (They are only there to tell SC core that packets
     * arriving at this node can be forwarded out of the output subnodes).
     */
    SC_TEST( n_links == fb->n_outputs );
    rc = 0;
  }
  else {
    fb->free_input_hop = sc_node_prep_get_link_or_free(node, "input");
    rc = sc_node_prep_check_links(node);
  }
  if( rc == 0 )
    sc_timer_expire_after_ns(fb->timer, 100*1000*1000);
  return rc;
}


static int sc_flow_balancer_init(struct sc_node* node,
                                 const struct sc_attr* attr,
                                 const struct sc_node_factory* factory)
{
  struct sc_thread* thread = sc_node_get_thread(node);

  static struct sc_node_type* nt_zc;
  if( nt_zc == NULL ) {
    sc_node_type_alloc(&nt_zc, NULL, factory);
    nt_zc->nt_pkts_fn = sc_flow_balancer_zc_pkts;
    nt_zc->nt_prep_fn = sc_flow_balancer_prep;
    nt_zc->nt_add_link_fn = sc_flow_balancer_add_link;
    nt_zc->nt_end_of_stream_fn = sc_flow_balancer_end_of_stream;
  }
  static struct sc_node_type* nt_copy;
  if( nt_copy == NULL ) {
    sc_node_type_alloc(&nt_copy, NULL, factory);
    nt_copy->nt_pkts_fn = sc_flow_balancer_copy_pkts;
    nt_copy->nt_prep_fn = sc_flow_balancer_prep;
    nt_copy->nt_add_link_fn = sc_flow_balancer_add_link;
    nt_copy->nt_end_of_stream_fn = sc_flow_balancer_end_of_stream;
  }

  sc_flow_balancer_stats_declare(sc_thread_get_session(thread));
  node->nd_type = nt_zc;

  const char* copy_mode;
  if( sc_node_init_get_arg_str(&copy_mode, node, "copy_mode", NULL) < 0 )
    return -1;
  if( copy_mode && ! strcmp(copy_mode, "zc") )
    node->nd_type = nt_zc;
  else if( copy_mode && ! strcmp(copy_mode, "copy") )
    node->nd_type = nt_copy;
  else
    return sc_node_set_error(node, EINVAL, "sc_flow_balancer: required arg "
                             "'copy_mode' missing or bad; expected 'zc' or "
                             "'copy'");

  const char* mode;
  if( sc_node_init_get_arg_str(&mode, node, "mode", NULL) < 0 )
    return -1;
  bool round_robin;
  if( mode && ! strcmp(mode, "round-robin") )
    round_robin = true;
  else if( mode && ! strcmp(mode, "estimate") )
    round_robin = false;
  else
    return sc_node_set_error(node, EINVAL, "sc_flow_balancer: required arg "
                             "'mode' missing or bad; expected 'round-robin' or "
                             "'estimate'");

  int table_size;
  if( sc_node_init_get_arg_int(&table_size, node,
                               "flow_table_capacity", 1024) < 0 )
    return -1;

  int64_t flush_ns;
  if( sc_node_init_get_arg_int64(&flush_ns, node,
                                 "flush_ns", 10*1000*1000) < 0 )
    return -1;

  int n_grow_attempts;
  if( sc_node_init_get_arg_int(&n_grow_attempts, node, "n_grow_attempts", 3) < 0 )
    return -1;
  if( n_grow_attempts < 1 ) {
    sc_node_set_error(node, -EINVAL, "%s: ERROR: n_grow_attempts must be >= 1 (got %d)\n",
                      __func__, n_grow_attempts);
    return -1;
  }

  struct flow_balancer* fb;
  fb = sc_thread_calloc(thread, sizeof(*fb));
  node->nd_private = fb;
  fb->zero_copy = (node->nd_type == nt_zc);

  fb->flow_table_capacity = table_size;
  int rc = sc_hash_table_alloc(&(fb->flow_table), sizeof(struct flow_key),
                               sizeof(struct flow_state),
                               fb->flow_table_capacity);
  if( rc < 0 ) {
    sc_node_set_error(node, -rc, "%s: ERROR: failed to allocate hash table "
                      "(capacity=%u)\n", __func__, fb->flow_table_capacity);
    goto fail;
  }
  fb->thread = thread;
  SC_TEST( fb->attr = sc_attr_dup(attr) );
  /* fb->outputs = NULL; */
  SC_TRY( sc_callback_alloc(&(fb->timer), attr, thread) );
  fb->timer->cb_private = fb;
  fb->timer->cb_handler_fn = sc_flow_balancer_periodic;
  /* fb->n_outputs = 0; */
  fb->tpid_ne = htons(SC_ETHERTYPE_8021Q);
  fb->per_pkt_overhead = 300;  /* ?? todo tunable */
  fb->timeout[0] = 5;  /* ?? todo tunable */
  fb->timeout[1] = 2;  /* ?? todo tunable */
  if( round_robin )
    fb->select_output_fn = select_output_round_robin;
  else
    fb->select_output_fn = select_output_estimate;
  fb->alpha_short = 0.1 * 65536;
  fb->alpha_long = 0.01 * 65536;
  fb->flush_ns = flush_ns;
  /* fb->prev_n_flows = 0; */
  fb->n_grow_attempts = n_grow_attempts;
  int i;
  for( i = 0; i < N_FLOW_TYPES; ++i )
    sc_dlist_init(&(fb->lru[i]));
  /* fb->next_output = 0; */
  sc_node_export_state(node, "sc_flow_balancer_stats",
                       sizeof(*(fb->stats)), &(fb->stats));
  fb->stats->avg_flow_load = 0;
  fb->stats->flow_table_capacity = fb->flow_table_capacity;
  sc_node_add_info_str(node, "copy_mode", copy_mode);
  sc_node_add_info_str(node, "mode", mode);
  return 0;

 fail:
  sc_thread_mfree(thread, fb);
  return -1;
}


const struct sc_node_factory sc_flow_balancer_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_flow_balancer",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_flow_balancer_init,
};

/** \endcond NODOC */
