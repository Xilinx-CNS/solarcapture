/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \node{sc_delay_line}
 *
 * \brief Node to delay upstream packets by a random time within a given time range.
 *
 * \nodedetails
 * Node to delay upstream packets by a random time within a given time range.
 * Randomness is achieved by performing a hash on the destination IP address and
 * can be controlled using the @p num_lines argument.
 *
 * If @p num_lines = 1:
 *   - @p usec/@p msec must be a single value.
 *   - All packets will be delayed by this amount.
 *
 * If @p num_lines > 1:
 *   - @p usec/@p msec must be a range of values \<min_delay\>-\<max_delay\>.
 *   - Non-IP packets are delayed by exactly \<min_delay\>.
 *   - IP packets are assigned a line by hashing the destination IP address.
 *   - For a given line in (0, ..., num_lines-1) the delay is
 *         \<min_delay\> + (\<max_delay\> - \<min_delay\>) * (line / num_lines)
 *
 * \nodeargs
 * Argument   | Optional? | Default | Type           | Description
 * ---------- | --------- | ------- | -------------- | --------------------------------------------------------------------------------------------------------------------------------
 * num_lines  | Yes       | 1       | ::SC_PARAM_INT | Number of lines used in the hash.
 * usec       | Yes       | NULL    | ::SC_PARAM_STR | Set this to a string of the form "\<min_delay\>[-\<max_delay\>]" to set the delay time of the node in microseconds.
 * msec       | Yes       | NULL    | ::SC_PARAM_STR | Set this to a string of the form "\<min_delay\>[-\<max_delay\>]" to set the delay time of the node in milliseconds.
 *
 * Note: One and only one of usec and msec must be set.
 *
 * \namedinputlinks
 * None
 *
 * \outputlinks
 * Link | Description
 * ---- | -----------------------------------
 *  ""  | All packets are sent down this link.
 *
 * \cond NODOC
 */

#include <sc_internal.h>
#include <sc_internal/builtin_nodes.h>
#include <sc_internal/hash.h>

#include <errno.h>
#include <net/ethernet.h>
#include <netinet/ip.h>

#ifndef ETHERTYPE_8021Q
# define ETHERTYPE_8021Q  0x8100
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN
# define HTONS_CONST(x)  ((uint16_t) (((x) >> 8) | ((x) << 8)))
#else
# define HTONS_CONST(x)  (x)
#endif


struct sc_delay_line {
  struct sc_packet_list  pl;
  int                    delay_nsec;
  struct sc_callback*    timer;
  struct sc_delay*       st;
};


struct sc_delay {
  struct sc_node*            node;
  struct sc_thread*          thread;
  const struct sc_node_link* next_hop;
  struct sc_delay_line*      delay_lines;
  int                        num_delay_lines;
  int                        num_active_lines;
  int                        end_of_stream;
};


static void sc_delay_timeout(struct sc_callback* cb, void* event_info)
{
  struct sc_delay_line* dl = cb->cb_private;
  struct sc_delay* st = dl->st;

  struct timespec now;
  sc_thread_get_time(st->thread, &now);

  assert( ! sc_packet_list_is_empty(&(dl->pl)) );
  assert( sc_timespec_le(sc_packet_timespec(dl->pl.head), now) );

  /* Forward packets that are ready to go... */
  do {
    sc_forward(st->node, st->next_hop, __sc_packet_list_pop_head(&(dl->pl)));
    if( sc_packet_list_is_empty(&(dl->pl)) ) {
      __sc_packet_list_init(&(dl->pl));
      --(st->num_active_lines);
      if( st->end_of_stream && st->num_active_lines == 0 )
        sc_node_link_end_of_stream(st->node, st->next_hop);
      return;
    }
  } while( sc_timespec_le(sc_packet_timespec(dl->pl.head), now) );

  /* Reset timer... */
  struct timespec ts = sc_packet_timespec(dl->pl.head);
  sc_timer_expire_at(dl->timer, &ts);
}


static inline int select_line(struct sc_delay* st, const struct sc_packet* pkt)
{
  /* Delay line is selected by hash of destination IP address.  For non-IP
   * packets 0 is returned.
   */
  const struct ether_header* eth = pkt->iov[0].iov_base;
  const uint16_t* p_ether_type = &eth->ether_type;
  if( *p_ether_type == htons(ETHERTYPE_8021Q) )
    p_ether_type += 2;
  switch( *p_ether_type ) {
  case HTONS_CONST(ETHERTYPE_IP): {
    const struct iphdr* ip = (void*) (p_ether_type + 1);
    unsigned hash = sc_hash(&(ip->daddr), sizeof(ip->daddr));
    return hash % st->num_delay_lines;
  }
  default:
    return 0;
  }
}


static void sc_delay_line_add_pkt(struct sc_delay_line* dl,
                                  struct sc_packet* pkt)
{
  pkt->ts_nsec += dl->delay_nsec;
  if( pkt->ts_nsec > 1000000000 ) {
    pkt->ts_nsec -= 1000000000;
    pkt->ts_sec += 1;
  }
  __sc_packet_list_append(&(dl->pl), pkt);
  if( dl->pl.num_pkts == 1 ) {
    struct timespec ts = sc_packet_timespec(pkt);
    sc_timer_expire_at(dl->timer, &ts);
    ++(dl->st->num_active_lines);
  }
}


static void sc_delay_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct sc_delay* st = node->nd_private;
  struct sc_packet* next;
  struct sc_packet* pkt;

  for( next = pl->head; (pkt = next) && ((next = next->next) || 1); ) {
    int line_i = select_line(st, pkt);
    sc_delay_line_add_pkt(st->delay_lines + line_i, pkt);
  }
}


static void sc_delay_end_of_stream(struct sc_node* node)
{
  struct sc_delay* st = node->nd_private;
  assert( ! st->end_of_stream );
  st->end_of_stream = 1;
  if( st->num_active_lines == 0 )
    sc_node_link_end_of_stream(node, st->next_hop);
}


static int sc_delay_prep(struct sc_node* node,
                         const struct sc_node_link*const* links,
                         int n_links)
{
  struct sc_delay* st = node->nd_private;
  st->next_hop = sc_node_prep_get_link_or_free(node, "");
  return sc_node_prep_check_links(node);
}


static int sc_delay_init(struct sc_node* node, const struct sc_attr* attr,
                             const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_prep_fn = sc_delay_prep;
    nt->nt_pkts_fn = sc_delay_pkts;
    nt->nt_end_of_stream_fn = sc_delay_end_of_stream;
  }
  node->nd_type = nt;

  struct sc_thread* thread = sc_node_get_thread(node);
  struct sc_delay* st;
  st = sc_thread_calloc(thread, sizeof(*st));
  node->nd_private = st;
  st->node = node;
  st->thread = thread;

  int num_lines;
  if( sc_node_init_get_arg_int(&num_lines, node, "num_lines", 1) < 0 )
    goto error;
  if( num_lines <= 0 ) {
    sc_node_set_error(node, EINVAL,
                      "sc_delay: bad arg num_lines=%d\n", num_lines);
    goto error;
  }

  const char* s;
  int is_usec = 1;
  if( sc_node_init_get_arg_str(&s, node, "usec", NULL) < 0 )
    goto error;
  if( s == NULL ) {
    is_usec = 0;
    if( sc_node_init_get_arg_str(&s, node, "msec", NULL) < 0 )
      goto error;
  }
  if( s == NULL ) {
    sc_node_set_error(node, EINVAL, "sc_delay: required arg 'usec' or "
                      "'msec' missing\n");
    goto error;
  }
  int min, max;
  char dummy;
  if( num_lines > 1 &&
      sscanf(s, "%d-%d%c", &min, &max, &dummy) == 2 &&
      min >= 0 && min < max ) {
    /* okay */
  }
  else if( num_lines == 1 &&
           sscanf(s, "%d%c", &min, &dummy) == 1 && min >= 0 ) {
    max = min;
  }
  else {
    sc_node_set_error(node, EINVAL, "sc_delay: bad arg %s=%s\n",
                      is_usec ? "usec":"msec", s);
    goto error;
  }
  if( ! is_usec ) {
    min *= 1000;
    max *= 1000;
  }
  if( max > 1000000 ) {
    sc_node_set_error(node, EINVAL, "sc_delay: arg %s=%s too big\n",
                      is_usec ? "usec":"msec", s);
    goto error;
  }

  st->num_delay_lines = num_lines;
  st->delay_lines = sc_thread_calloc(thread,
                                     num_lines * sizeof(st->delay_lines[0]));
  int i;
  for( i = 0; i < num_lines; ++i ) {
    struct sc_delay_line* dl = st->delay_lines + i;
    int usec = min;
    if( i > 0 )  /* avoid divide-by-zero when num_lines==1 */
      usec = min + i * ((float) max - min) / (num_lines - 1);
    dl->delay_nsec = usec * 1000;
    sc_packet_list_init(&(dl->pl));
    SC_TEST(sc_callback_alloc(&(dl->timer), attr, thread) == 0);
    dl->timer->cb_private = dl;
    dl->timer->cb_handler_fn = sc_delay_timeout;
    dl->st = st;
  }

  return 0;


 error:
  sc_thread_mfree(thread, st->delay_lines);
  sc_thread_mfree(thread, st);
  return -1;
}


const struct sc_node_factory sc_delay_line_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_delay_line",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_delay_init,
};

/** \endcond NODOC */
