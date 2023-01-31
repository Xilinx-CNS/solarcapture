/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \page sc_arista7280_64bit_ts_node sc_arista_ts, switch_model=7280, ts_format=64bit
 *
 * \brief Replace SolarCapture timestamp with 64bit timestamp from an Arista 7280
 * switch.
 *
 * \nodedetails
 * This mode is used to decode timestamps added by Arista 7280 series switches.
 *
 * \internal
 * The timestamps provided by the switch are a 64 bit tick field inserted
 * as an ethertype layer.  The lower 34 bits are added to the field on ingress
 * to the switch, the upper 30 on egress.  If the lower 34 bits roll while the
 * packet is in transit then the resulting timestamp will be 4s later than it
 * should be and requires correcting.
 * \endinternal
 *
 * \nodeargs
 * Argument           | Optional? | Default   | Type           | Description
 * ------------------ | --------- | --------- | -------------- | ----------------------------------------------------------------------------------------------------
 * filter_oui         | Yes       |           | ::SC_PARAM_STR | Assume packets with this OUI in the Ethernet source field do not have a switch timestamp.
 * strip_ticks        | Yes       | 1         | ::SC_PARAM_INT | Toggle the option for the node to strip switch timestamps. Set to 0 for off and 1 for on.
 * rollover_window_ms | Yes       | 1000      | ::SC_PARAM_INT | Window before lower bit rollover in which to check packets for the rollover bug.
 * switch_model       | Yes       |           | ::SC_PARAM_STR | Passed through from sc_arista_ts, must be either '7280' or unspecified.
 * ts_format          | Yes       |           | ::SC_PARAM_STR | Passed through from sc_arista_ts, must be either '64bit' or unspecified.
 *
 * \namedinputlinks
 * None
 *
 * \outputlinks
 * Link         | Default            | Description
 * ------------ | ------------------ | ----------------------------------------------------------------------------
 * ""           | free               | Packets with corrected timestamps
 * no_timestamp | default            | Packets with no arista timestamp
 * lldp         | no_timestamp       | Used for LLDP packets
 *
 * LLDP packets are treated specially because they are not timestamped
 * by the switch, and so it is not possible to give them timestamps
 * with the same clock as other packets.
 *
 * \nodestatscopy{sc_arista7280_64bit_ts}
 *
 * \cond NODOC
 */

#include <sc_internal.h>

#define SC_TYPE_TEMPLATE  <sc_arista7280_64bit_ts_types_tmpl.h>
#define SC_DECLARE_TYPES  sc_arista7280_64bit_ts_stats_declare
#include <solar_capture/declare_types.h>

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

#include <sc_arista7280_ts.h>

#define ARISTA7280_64BIT_INGRESS_SEC_BITS 2  /* Number of (lower) bits of seconds field stamped on ingress */
#define ARISTA7280_64BIT_INGRESS_ROLLOVER (1 << ARISTA7280_64BIT_INGRESS_SEC_BITS)


struct sc_arista7280_64bit_ts {
  struct sc_node*                node;
  struct sc_arista7280_64bit_ts_stats* stats;
  const struct sc_node_link* next_hop;
  const struct sc_node_link* next_hop_no_timestamp;
  const struct sc_node_link* next_hop_lldp;

  bool strip_ticks;
  uint32_t rollover_window_ns;
  bool filter_oui;
  uint8_t no_ts_oui[3];

  int64_t *last_good_delta_ns;
};


struct arista7280_64bit_field_packed {
  uint16_t ether_type;
  uint16_t sub_type;
  uint16_t version;
  uint32_t sec;
  uint32_t nsec;
} __attribute__((packed));

static const int arista7280_64bit_field_size = sizeof(struct arista7280_64bit_field_packed);


static inline void pkt_strip_arista7280_64bit(struct sc_packet* pkt)
{
  memmove((uint8_t*)pkt->iov[0].iov_base + MAC_ADDRESSES_SIZE,
          (uint8_t*)pkt->iov[0].iov_base + MAC_ADDRESSES_SIZE + arista7280_64bit_field_size,
          pkt->iov[0].iov_len - MAC_ADDRESSES_SIZE - arista7280_64bit_field_size);
  pkt->iov[0].iov_len -= arista7280_64bit_field_size;
  pkt->frame_len -= arista7280_64bit_field_size;
}

static inline void ps_pkt_strip_arista7280_64bit(struct sc_packed_packet* ps_pkt)
{
  uint8_t* original = sc_packed_packet_payload(ps_pkt);
  ps_pkt->ps_pkt_start_offset += arista7280_64bit_field_size;
  ps_pkt->ps_cap_len -= arista7280_64bit_field_size;
  ps_pkt->ps_orig_len -= arista7280_64bit_field_size;
  memmove(sc_packed_packet_payload(ps_pkt), original, MAC_ADDRESSES_SIZE);
}


static inline int fetch_arista7280_64bit_time(uint8_t* packet_buffer, uint64_t* arista_ns)
{
  /* Arista7280 field is located just after the mac addresses */
  struct arista7280_64bit_field_packed* packed = (void*)(packet_buffer + MAC_ADDRESSES_SIZE);
  if( packed->ether_type != htons(ARISTA7280_ETHERTYPE) ||
      (packed->version != htons(ARISTA7280_PROTOCOL_VERSION_64BIT_TAI) &&
       packed->version != htons(ARISTA7280_PROTOCOL_VERSION_64BIT_UTC)) ||
      packed->sub_type != htons(ARISTA7280_PROTOCOL_SUBTYPE) ||
      ntohl(packed->nsec) >= SC_NS_IN_S )
    return -1;
  *arista_ns = (SC_NS_IN_S * ntohl(packed->sec)) + ntohl(packed->nsec);
  return 0;
}


static inline bool inside_rollover_window(const struct sc_arista7280_64bit_ts* bt,
                                          uint64_t ts_ns)
{
  /* Lower bits of timestamp are stamped on ingress.
   * Check if within rollover_window_ns of next overflow of lower bits.
   * Use fact that ROLLOVER is a round hex number, therefore -1 is a mask.
   */
  uint32_t lower_bits_sec = (ts_ns / SC_NS_IN_S) & (ARISTA7280_64BIT_INGRESS_ROLLOVER - 1);
  uint64_t lower_bits_ns = (ts_ns % SC_NS_IN_S) + (lower_bits_sec * SC_NS_IN_S);
  return lower_bits_ns >= (ARISTA7280_64BIT_INGRESS_ROLLOVER * SC_NS_IN_S) - bt->rollover_window_ns;
}

static inline void fix_rollover_bug(const struct sc_arista7280_64bit_ts* bt,
                                    uint64_t* arista_ns,
                                    uint64_t* nic_ns)
{
  if( *bt->last_good_delta_ns != INT64_MAX ) {
    /* Inside rollover window and have good delta to compute from */
    uint64_t arista_ns_if_rollover = *arista_ns - (ARISTA7280_64BIT_INGRESS_ROLLOVER * SC_NS_IN_S);

    /* Use rollover time if it is closer to NIC time plus delta
     * Safe to use imaxabs on unsigned as difference will be small
     */
    if( imaxabs(arista_ns_if_rollover - (*nic_ns - *bt->last_good_delta_ns)) <
        imaxabs(*arista_ns - (*nic_ns - *bt->last_good_delta_ns)) ) {
      *arista_ns = arista_ns_if_rollover;
    }
  }
}


static inline ts_class process_single_packet(const struct sc_arista7280_64bit_ts* bt,
                                             struct sc_packet* pkt)
{
  /* Single packets do not have CLOCK_SET CLOCK_IN_SYNC flags available.
   * Must classify packet in return code to separate into different output links.
   */
  const struct ether_header* eth = pkt->iov[0].iov_base;
  if( eth->ether_type == htobe16(ETHERTYPE_LLDP) ||
      (bt->filter_oui && ! cmp_oui(eth->ether_shost, bt->no_ts_oui)) ) {
    /* Ignore LLDP packets, leave NIC time but do not mark as invalid.
     * Ignore packets matching the node's oui filter.
     */
    sc_trace(sc_thread_get_session(sc_node_get_thread(bt->node)),
             "%s: Ignoring packet.  (LLDP or oui match).\n", __func__);
    return NO_TIMESTAMP;
  }

  if( pkt->flags & SC_CRC_ERROR ||
      eth->ether_type != htobe16(ARISTA7280_ETHERTYPE) ||
      pkt->frame_len < MAC_ADDRESSES_SIZE + arista7280_64bit_field_size) {
    /* Can't trust arista timestamps from packets with FCS errors.
     * Packets with incorrect ethertype are not arista stamped.
     * Packets too short to contain a arista field have something strange going on.
     */
    sc_trace(sc_thread_get_session(sc_node_get_thread(bt->node)),
             "%s: Bad packet.  (CRC error, bad ethertype or bad packet length).\n", __func__);
    return NO_TIMESTAMP;
  }
  /* Retrieve arista time, check for errors in ts field */
  uint64_t arista_ns;
  if( fetch_arista7280_64bit_time(pkt->iov[0].iov_base, &arista_ns) != 0 ) {
    sc_trace(sc_thread_get_session(sc_node_get_thread(bt->node)),
             "%s: Bad packet.  (Invalid arista 7280 field).\n", __func__);
    return NO_TIMESTAMP;
  }
  /* Deal with rollover, if outside window or cannot compute then assume no rollover */
  uint64_t pkt_ns = pkt->ts_sec * SC_NS_IN_S + pkt->ts_nsec;
  bool is_rollover = inside_rollover_window(bt, arista_ns);
  if( is_rollover )
    fix_rollover_bug(bt, &arista_ns, &pkt_ns);

  /* All checks passed.
   * If not in rollover window update delta, update packet times and strip arista field
   */
  if( !is_rollover )
    *bt->last_good_delta_ns = pkt_ns - arista_ns;

  pkt_ts_from_ns(pkt, arista_ns);
  if( bt->strip_ticks )
    pkt_strip_arista7280_64bit(pkt);

  return GOOD_PACKET;
}


static inline void process_packed_stream_single_packed_packet(const struct sc_arista7280_64bit_ts* bt,
                                                              struct sc_packed_packet* ps_pkt)
{
  const struct ether_header* eth = sc_packed_packet_payload(ps_pkt);
  if( eth->ether_type == htobe16(ETHERTYPE_LLDP) ||
      (bt->filter_oui && ! cmp_oui(eth->ether_shost, bt->no_ts_oui)) ) {
    /* Ignore LLDP packets, leave NIC time but do not mark as invalid.
     * Ignore packets matching the node's oui filter.
     */
    sc_trace(sc_thread_get_session(sc_node_get_thread(bt->node)),
             "%s: Ignoring packet.  (LLDP or oui match).\n", __func__);
    return;
  }

  if( ps_pkt->ps_flags & SC_PS_FLAG_BAD_FCS ||
      eth->ether_type != htobe16(ARISTA7280_ETHERTYPE) ||
      ps_pkt->ps_cap_len < MAC_ADDRESSES_SIZE + arista7280_64bit_field_size) {
    /* Can't trust arista timestamps from packets with FCS errors.
     * Packets with incorrect ethertype are not arista stamped.
     * Packets too short to contain a arista field have something strange going on.
     */
    ps_pkt->ps_flags &= ~SC_PS_FLAG_CLOCK_SET;
    ps_pkt->ps_flags &= ~SC_PS_FLAG_CLOCK_IN_SYNC;
    sc_trace(sc_thread_get_session(sc_node_get_thread(bt->node)),
             "%s: Bad packet.  (CRC error, bad ethertype or bad packet length).\n", __func__);
    return;
  }

  /* Retrieve arista time, check for errors in ts field */
  uint64_t arista_ns;
  if( fetch_arista7280_64bit_time(sc_packed_packet_payload(ps_pkt), &arista_ns) != 0 ) {
    ps_pkt->ps_flags &= ~SC_PS_FLAG_CLOCK_SET;
    ps_pkt->ps_flags &= ~SC_PS_FLAG_CLOCK_IN_SYNC;
    sc_trace(sc_thread_get_session(sc_node_get_thread(bt->node)),
             "%s: Bad packet.  (Invalid arista 7280 field).\n", __func__);
    return;
  }
  /* Deal with rollover, if outside window or cannot compute then assume no rollover */
  uint64_t pkt_ns = ps_pkt->ps_ts_sec * SC_NS_IN_S + ps_pkt->ps_ts_nsec;
  bool is_rollover = inside_rollover_window(bt, arista_ns);
  if( is_rollover )
    fix_rollover_bug(bt, &arista_ns, &pkt_ns);

  /* All checks passed.
   * If not in rollover window update delta, update packet times and strip arista field
   */
  if( !is_rollover )
    *bt->last_good_delta_ns = pkt_ns - arista_ns;

  ps_pkt_ts_from_ns(ps_pkt, arista_ns);
  if( bt->strip_ticks )
    ps_pkt_strip_arista7280_64bit(ps_pkt);

  return;
}


static inline void process_packed_stream_packet(const struct sc_arista7280_64bit_ts* bt,
                                                struct sc_packet* pkt)
{
  /* Packets in packed stream cannot be separated but do have CLOCK_SET and
   * CLOCK_IN_SYNC flags available.
   */
  struct sc_packed_packet* ps_pkt = sc_packet_packed_first(pkt);
  struct sc_packed_packet* ps_end = sc_packet_packed_end(pkt);

  for( ; ps_pkt < ps_end; ps_pkt = sc_packed_packet_next(ps_pkt) ) {
    process_packed_stream_single_packed_packet(bt, ps_pkt);
  }
}


static void sc_arista7280_64bit_ts_pkts(struct sc_node* node,
                                  struct sc_packet_list* pl)
{
  const struct sc_arista7280_64bit_ts* bt = node->nd_private;
  struct sc_packet* pkt = pl->head;
  while( pkt ) {
    if( pkt->flags & SC_PACKED_STREAM ) {
      process_packed_stream_packet(bt, pkt);
      sc_forward2(bt->next_hop, pkt);
    }
    else {
      switch( process_single_packet(bt, pkt) ) {
        case GOOD_PACKET:
          sc_forward2(bt->next_hop, pkt);
          break;
        case NO_TIMESTAMP:
          sc_forward2(bt->next_hop_no_timestamp, pkt);
          break;
        default:
          SC_TEST(0);
      }
    }
    pkt = pkt->next;
  }
  bt->stats->last_good_delta_ns = *bt->last_good_delta_ns;
}


static void sc_arista7280_64bit_ts_end_of_stream(struct sc_node* node)
{
  const struct sc_arista7280_64bit_ts* bt = node->nd_private;
  sc_node_link_end_of_stream2(bt->next_hop);
  sc_node_link_end_of_stream2(bt->next_hop_no_timestamp);
  /* NB. Not used, but we still accept a link called 'lldp' to avoid
   * breaking any apps that expect it.
   */
  sc_node_link_end_of_stream2(bt->next_hop_lldp);
}


static int sc_arista7280_64bit_ts_prep(struct sc_node* node,
                                 const struct sc_node_link* const * links,
                                 int n_links)
{
  struct sc_arista7280_64bit_ts* bt = node->nd_private;
  bt->next_hop = sc_node_prep_get_link_or_free(node, "");
  bt->next_hop_no_timestamp =
    p_or(sc_node_prep_get_link(node, "no_timestamp"), bt->next_hop);
  bt->next_hop_lldp =
    p_or(sc_node_prep_get_link(node, "lldp"), bt->next_hop_no_timestamp);
  return sc_node_prep_check_links(node);
}


static int get_uint(uint32_t* v, struct sc_node* node, const char* k, int default_v)
{
  int temp = 0;
  if( sc_node_init_get_arg_int(&temp, node, k, default_v) < 0 || temp < 0 )
    return sc_node_set_error(node, EINVAL, "sc_arista7280_64bit_ts: ERROR: bad value for "
                             "arg '%s'; expected >= 0\n", k);
  *v = (uint32_t)temp;
  return 0;
}


static int sc_arista7280_64bit_ts_init(struct sc_node* node, const struct sc_attr* attr,
                                 const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if (nt == NULL) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_prep_fn = sc_arista7280_64bit_ts_prep;
    nt->nt_pkts_fn = sc_arista7280_64bit_ts_pkts;
    nt->nt_end_of_stream_fn = sc_arista7280_64bit_ts_end_of_stream;
  }
  sc_arista7280_64bit_ts_stats_declare(sc_thread_get_session(sc_node_get_thread(node)));
  node->nd_type = nt;

  struct sc_arista7280_64bit_ts* bt = sc_thread_calloc(sc_node_get_thread(node),
                                                 sizeof(*bt));
  bt->node = node;

  const char* switch_model;
  const char* ts_format;
  const char* filter_oui;
  uint32_t rollover_window_ms = SC_MS_IN_S;
  if( sc_node_init_get_arg_str(&switch_model, node, "switch_model", NULL)                             < 0 ||
      sc_node_init_get_arg_str(&ts_format, node, "ts_format", NULL)                                   < 0 ||
      get_bool(&bt->strip_ticks, node, "strip_ticks", true)                                           < 0 ||
      get_uint(&rollover_window_ms, node, "rollover_window_ms", SC_MS_IN_S)                           < 0 ||
      sc_node_init_get_arg_str(&filter_oui, node, "filter_oui", NULL)                                 < 0 )
    return -1;

  if( switch_model != NULL && strcmp(switch_model, "7280") )
    return sc_node_set_error(node, EINVAL, "sc_arista7280: ERROR: arg 'switch_model' bad mode %s"
                             ", should be 7280", switch_model);

  if( ts_format != NULL && strcmp(ts_format, "64bit") )
    return sc_node_set_error(node, EINVAL, "%s: ERROR: "
                             "arg 'ts_format' bad value %s,"
                             "should be 64bit", __func__, ts_format);

  bt->rollover_window_ns = rollover_window_ms * SC_NS_IN_MS;

  /* Have this as a pointer so that bt can be passed as const */
  bt->last_good_delta_ns = sc_thread_calloc(sc_node_get_thread(node),
                                            sizeof(*bt->last_good_delta_ns));
  *bt->last_good_delta_ns = INT64_MAX;

  if( filter_oui != NULL ) {
    if( parse_oui(bt->no_ts_oui, filter_oui) < 0 )
      return sc_node_set_error(node, EINVAL, "sc_arista7280: ERROR: arg "
                               "'filter_oui' badly formatted; expected "
                               "Ethernet OUI\n");
    bt->filter_oui = true;
  }
  node->nd_private = bt;

  sc_node_export_state(node, "sc_arista7280_64bit_ts_stats",
                       sizeof(struct sc_arista7280_64bit_ts_stats), &bt->stats);
  bt->stats->strip_ticks = bt->strip_ticks;
  bt->stats->rollover_window_ns = bt->rollover_window_ns;
  bt->stats->last_good_delta_ns = *bt->last_good_delta_ns;

  return 0;
}


const struct sc_node_factory sc_arista7280_64bit_ts_sc_node_factory = {
  .nf_node_api_ver = SC_API_VER,
  .nf_name = "sc_arista7280_64bit_ts",
  .nf_source_file = __FILE__,
  .nf_init_fn = sc_arista7280_64bit_ts_init,
};

/** \endcond NODOC */
