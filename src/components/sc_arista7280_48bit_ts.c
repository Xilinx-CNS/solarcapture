/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \page sc_arista7280_48bit_ts_node sc_arista_ts, switch_model=7280, ts_format=48bit
 *
 * \brief Replace SolarCapture timestamp with timestamp decoded from 48bit timestamp
 * from an Arista 7280 switch.
 *
 * \nodedetails
 * This mode is used to decode 48 bit timestamps added by Arista 7280 series switches.
 *
 * \internal
 * The 48 bit timestamp is in a shortened IEEE-1588 ToD format. The first 2 octets make a
 * 16 bit number of seconds; the following 4 octets make a 30 bit number of nanoseconds
 * with the two MSBs being zeros. It does not correspond to a real time without
 * a reference, but proper merging with host timestamp allows retrieval of the real time.
 *
 * The 48 bit timestamp field is inserted as either in ethertype layer or in source MAC
 * field.
 *
 * Note: if Arista switch and host time differ by more than 2^15 seconds (~9 hours),
 * there is no guarantee that the merged timestamp will be correct.
 * \endinternal
 *
 * \nodeargs
 * Argument            | Optional? | Default   | Type           | Description
 * ------------------- | --------- | --------- | -------------- | ----------------------------------------------------------------------------------------------------
 * filter_oui          | Yes       |           | ::SC_PARAM_STR | Assume packets with this OUI in the Ethernet source field do not have a switch timestamp.
 * strip_ticks         | Yes       | 1         | ::SC_PARAM_INT | Toggle the option for the node to strip switch timestamps. Set to 0 for off and 1 for on.
 * ts_src_mac          | Yes       | 0         | ::SC_PARAM_INT | If set then timestamp is retrieved from source mac address field instead of ethertype layer.
 * replacement_src_mac | Yes       |           | ::SC_PARAM_STR | Replace timestamp located in source mac address field by given mac address. Applicable for ts_src_mac=1 only.
 * switch_model        | Yes       |           | ::SC_PARAM_STR | Passed through from sc_arista_ts, must be either '7280' or unspecified.
 * ts_format           | Yes       |           | ::SC_PARAM_STR | Passed through from sc_arista_ts, must be either '48bit' or unspecified.
 *
 * \namedinputlinks
 * None
 *
 * \outputlinks
 * Link         | Default            | Description
 * ------------ | ------------------ | ----------------------------------------------------------------------------
 * ""           | free               | Packets with corrected timestamps
 * no_timestamp | default            | Packets with no arista 48bit timestamp
 * lldp         | no_timestamp       | Used for LLDP packets
 *
 * LLDP packets are treated specially because they are not timestamped
 * by the switch, and so it is not possible to give them timestamps
 * with the same clock as other packets.
 *
 * \nodestatscopy{sc_arista7280_48bit_ts}
 *
 * \cond NODOC
 */

#include <sc_internal.h>

#define SC_TYPE_TEMPLATE  <sc_arista7280_48bit_ts_types_tmpl.h>
#define SC_DECLARE_TYPES  sc_arista7280_48bit_ts_stats_declare
#include <solar_capture/declare_types.h>

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

#include <sc_arista7280_ts.h>

/* Bitmask to get lower 16 bits of seconds from 32 bit timestamp field */
#define ARISTA7280_48BIT_SECONDS_BITMASK 0xFFFF

struct sc_arista7280_48bit_ts {
  struct sc_node*            node;
  struct sc_arista7280_48bit_ts_stats* stats;
  const struct sc_node_link* next_hop;
  const struct sc_node_link* next_hop_no_timestamp;
  const struct sc_node_link* next_hop_lldp;

  bool ts_src_mac;
  bool replace_src_mac;
  uint8_t new_src_mac[6];
  bool strip_ticks;
  bool filter_oui;
  uint8_t no_ts_oui[3];
};


struct arista7280_48bit_ts_packed {
  uint16_t sec;
  uint32_t nsec;
} __attribute__((packed));


struct arista7280_48bit_field_packed {
  uint16_t ether_type;
  uint16_t sub_type;
  uint16_t version;
  struct arista7280_48bit_ts_packed ts;
} __attribute__((packed));

static const int
arista7280_48bit_field_size = sizeof(struct arista7280_48bit_field_packed);


static inline void pkt_strip_arista7280_48bit(struct sc_packet* pkt)
{
  memmove((uint8_t*)pkt->iov[0].iov_base + MAC_ADDRESSES_SIZE,
          (uint8_t*)pkt->iov[0].iov_base + MAC_ADDRESSES_SIZE +
              arista7280_48bit_field_size,
          pkt->iov[0].iov_len - MAC_ADDRESSES_SIZE -
              arista7280_48bit_field_size);
  pkt->iov[0].iov_len -= arista7280_48bit_field_size;
  pkt->frame_len -= arista7280_48bit_field_size;
}


static inline void
ps_pkt_strip_arista7280_48bit(struct sc_packed_packet* ps_pkt)
{
  uint8_t* original = sc_packed_packet_payload(ps_pkt);

  ps_pkt->ps_pkt_start_offset += arista7280_48bit_field_size;
  ps_pkt->ps_cap_len -= arista7280_48bit_field_size;
  ps_pkt->ps_orig_len -= arista7280_48bit_field_size;
  memmove(sc_packed_packet_payload(ps_pkt), original, MAC_ADDRESSES_SIZE);
}


static inline void
replace_src_mac(const struct sc_arista7280_48bit_ts* dt,
                struct ether_header* eth)
{
    memcpy(eth->ether_shost, dt->new_src_mac, sizeof(dt->new_src_mac));
}


static inline int
fetch_arista7280_48bit_field(const struct sc_arista7280_48bit_ts* dt,
                             uint8_t* packet_buffer,
                             struct arista7280_48bit_ts_packed **ts_field)
{
  if( !dt->ts_src_mac ) {
    struct arista7280_48bit_field_packed* packed;

    /* Arista7280 field is located just after the mac addresses */
    packed = (void*)(packet_buffer + MAC_ADDRESSES_SIZE);
    if( packed->ether_type != htons(ARISTA7280_ETHERTYPE) ||
        (packed->version != htons(ARISTA7280_PROTOCOL_VERSION_48BIT_TAI) &&
         packed->version != htons(ARISTA7280_PROTOCOL_VERSION_48BIT_UTC) &&
         packed->version != htons(ARISTA7280_PROTOCOL_VERSION_48BIT_TAI_R3) &&
         packed->version != htons(ARISTA7280_PROTOCOL_VERSION_48BIT_UTC_R3)) ||
        packed->sub_type != htons(ARISTA7280_PROTOCOL_SUBTYPE) )
      return -1;

    *ts_field = &packed->ts;
  }
  else {
    /* Arista7280 timestamp is located in source mac field */
    const struct ether_header* eth = (void *)packet_buffer;
    *ts_field = (void*)&eth->ether_shost;
  }

  if( ntohl((*ts_field)->nsec) >= SC_NS_IN_S )
    return -1;

  return 0;
}


/* Restore missing higher 16 bits of seconds using host time */
static inline void
merge_arista7280_48bit_time(const struct sc_arista7280_48bit_ts* dt,
                            const struct arista7280_48bit_ts_packed *ts,
                            uint64_t* arista_ns)
{
  struct timespec host_ts;
  uint64_t host_sec;
  uint16_t sec = ntohs(ts->sec);
  uint32_t nsec = ntohl(ts->nsec);

  sc_thread_get_time(sc_node_get_thread(dt->node), &host_ts);
  host_sec = host_ts.tv_sec;

  /* In most cases higher 16 bits of timestamps would match.
   * But there could be rollover down/up cases because of difference
   * between Arista and host time (time sync, different time protocols) and
   * the delay between timestamping. In such cases we need to add/subtract 1
   * for higher 16bits. Casting lower 16 bits of timestamps difference
   * to int16_t allows to achieve such effect.
   */
  host_sec += (int16_t)(sec - (host_sec & ARISTA7280_48BIT_SECONDS_BITMASK));

  if( (host_sec | ARISTA7280_48BIT_SECONDS_BITMASK) !=
      (host_ts.tv_sec | ARISTA7280_48BIT_SECONDS_BITMASK) )
    ++(dt->stats->n_rollover);

  *arista_ns = (SC_NS_IN_S * host_sec) + nsec;
}


static inline int
fetch_arista7280_48bit_time(const struct sc_arista7280_48bit_ts* dt,
                            uint8_t* packet_buffer, uint64_t* arista_ns)
{
  struct arista7280_48bit_ts_packed *ts_field;
  int ret = fetch_arista7280_48bit_field(dt, packet_buffer, &ts_field);
  if( ret != 0 )
    return ret;
  merge_arista7280_48bit_time(dt, ts_field, arista_ns);
  return 0;
}


static inline int
arista7280_48bit_packet_min_size(const struct sc_arista7280_48bit_ts* dt)
{
  int min_size = MAC_ADDRESSES_SIZE;
  if( !dt->ts_src_mac )
    min_size += arista7280_48bit_field_size;
  return min_size;
}


static inline ts_class
process_single_packet(const struct sc_arista7280_48bit_ts* dt,
                      struct sc_packet* pkt)
{
  /* Single packets do not have CLOCK_SET CLOCK_IN_SYNC flags available.
   * Must classify packet in return code to separate into different
   * output links.
   */
  const struct ether_header* eth = pkt->iov[0].iov_base;
  if( eth->ether_type == htobe16(ETHERTYPE_LLDP) ) {
    sc_trace(sc_thread_get_session(sc_node_get_thread(dt->node)),
             "%s: Ignoring packet.  (LLDP).\n", __func__);
    ++(dt->stats->n_filtered_other);
    return NO_TIMESTAMP;
  }

  if( dt->filter_oui && ! cmp_oui(eth->ether_shost, dt->no_ts_oui) ) {
    sc_trace(sc_thread_get_session(sc_node_get_thread(dt->node)),
             "%s: Ignoring packet.  (oui match).\n", __func__);
    ++(dt->stats->n_filtered_oui);
    return NO_TIMESTAMP;
  }

  if( pkt->flags & SC_CRC_ERROR ||
      pkt->frame_len < arista7280_48bit_packet_min_size(dt) ) {
    sc_trace(sc_thread_get_session(sc_node_get_thread(dt->node)),
             "%s: Bad packet.  (CRC error or too small packet length).\n",
             __func__);
    ++(dt->stats->n_filtered_other);
    return NO_TIMESTAMP;
  }

  /* Retrieve arista time, check for errors in ts field */
  uint64_t arista_ns;

  if( fetch_arista7280_48bit_time(dt, pkt->iov[0].iov_base,
                                  &arista_ns) != 0 ) {
    sc_trace(sc_thread_get_session(sc_node_get_thread(dt->node)),
             "%s: Bad packet.  (Invalid arista 7280 field).\n", __func__);
    ++(dt->stats->n_filtered_arista);
    return NO_TIMESTAMP;
  }

  /* All checks passed. Update packet times and strip arista field or
   * replace source mac if requested.
   */
  pkt_ts_from_ns(pkt, arista_ns);
  if( dt->strip_ticks )
    pkt_strip_arista7280_48bit(pkt);

  if( dt->replace_src_mac )
    replace_src_mac(dt, pkt->iov[0].iov_base);

  return GOOD_PACKET;
}


static inline void
process_packed_stream_single_packed_packet(
            const struct sc_arista7280_48bit_ts* dt,
            struct sc_packed_packet* ps_pkt)
{
  const struct ether_header* eth = sc_packed_packet_payload(ps_pkt);

  if( eth->ether_type == htobe16(ETHERTYPE_LLDP) ) {
    /* Ignore LLDP packets, leave NIC time but do not mark as invalid.
     */
    sc_trace(sc_thread_get_session(sc_node_get_thread(dt->node)),
             "%s: Ignoring packet.  (LLDP).\n", __func__);
    ++(dt->stats->n_filtered_other);
    return;
  }

  if( dt->filter_oui && ! cmp_oui(eth->ether_shost, dt->no_ts_oui) ) {
    /* Ignore packets matching the node's oui filter,
     * leave NIC time but do not mark as invalid.
     */
    sc_trace(sc_thread_get_session(sc_node_get_thread(dt->node)),
             "%s: Ignoring packet.  (oui match).\n", __func__);
    ++(dt->stats->n_filtered_oui);
    return;
  }

  if( ps_pkt->ps_flags & SC_PS_FLAG_BAD_FCS ||
      ps_pkt->ps_cap_len < arista7280_48bit_packet_min_size(dt) ) {
    ps_pkt->ps_flags &= ~SC_PS_FLAG_CLOCK_SET;
    ps_pkt->ps_flags &= ~SC_PS_FLAG_CLOCK_IN_SYNC;
    sc_trace(sc_thread_get_session(sc_node_get_thread(dt->node)),
             "%s: Bad packet.  (CRC error or "
             "bad packet length).\n", __func__);
    ++(dt->stats->n_filtered_other);
    return;
  }

  /* Retrieve arista time, check for errors in ts field */
  uint64_t arista_ns;

  if( fetch_arista7280_48bit_time(dt, sc_packed_packet_payload(ps_pkt),
                                  &arista_ns) != 0 ) {
    ps_pkt->ps_flags &= ~SC_PS_FLAG_CLOCK_SET;
    ps_pkt->ps_flags &= ~SC_PS_FLAG_CLOCK_IN_SYNC;
    sc_trace(sc_thread_get_session(sc_node_get_thread(dt->node)),
             "%s: Bad packet.  (Invalid arista 7280 field).\n", __func__);
    ++(dt->stats->n_filtered_arista);
    return;
  }

  /* All checks passed. Update packet times and strip arista field or
   * replace source mac if requested.
   */
  ps_pkt_ts_from_ns(ps_pkt, arista_ns);
  if( dt->strip_ticks )
    ps_pkt_strip_arista7280_48bit(ps_pkt);

  if( dt->replace_src_mac )
    replace_src_mac(dt, sc_packed_packet_payload(ps_pkt));
}


static inline void
process_packed_stream_packet(const struct sc_arista7280_48bit_ts* dt,
                             struct sc_packet* pkt)
{
  /* Packets in packed stream cannot be separated but do have CLOCK_SET and
   * CLOCK_IN_SYNC flags available.
   */
  struct sc_packed_packet* ps_pkt = sc_packet_packed_first(pkt);
  struct sc_packed_packet* ps_end = sc_packet_packed_end(pkt);

  for( ; ps_pkt < ps_end; ps_pkt = sc_packed_packet_next(ps_pkt) ) {
    process_packed_stream_single_packed_packet(dt, ps_pkt);
  }
}


static void sc_arista7280_48bit_ts_pkts(struct sc_node* node,
                                        struct sc_packet_list* pl)
{
  const struct sc_arista7280_48bit_ts* dt = node->nd_private;
  struct sc_packet* pkt = pl->head;

  while( pkt ) {
    if( pkt->flags & SC_PACKED_STREAM ) {
      process_packed_stream_packet(dt, pkt);
      sc_forward2(dt->next_hop, pkt);
    }
    else {
      switch( process_single_packet(dt, pkt) ) {
        case GOOD_PACKET:
          sc_forward2(dt->next_hop, pkt);
          break;
        case NO_TIMESTAMP:
          sc_forward2(dt->next_hop_no_timestamp, pkt);
          break;
        default:
          SC_TEST(0);
      }
    }
    pkt = pkt->next;
  }
}


static void sc_arista7280_48bit_ts_end_of_stream(struct sc_node* node)
{
  const struct sc_arista7280_48bit_ts* dt = node->nd_private;

  sc_node_link_end_of_stream2(dt->next_hop);
  sc_node_link_end_of_stream2(dt->next_hop_no_timestamp);
  /* NB. Not used, but we still accept a link called 'lldp' to avoid
   * breaking any apps that expect it.
   */
  sc_node_link_end_of_stream2(dt->next_hop_lldp);
}


static int
sc_arista7280_48bit_ts_prep(struct sc_node* node,
                            const struct sc_node_link* const * links,
                            int n_links)
{
  struct sc_arista7280_48bit_ts* dt = node->nd_private;

  dt->next_hop = sc_node_prep_get_link_or_free(node, "");
  dt->next_hop_no_timestamp =
    p_or(sc_node_prep_get_link(node, "no_timestamp"), dt->next_hop);
  dt->next_hop_lldp =
    p_or(sc_node_prep_get_link(node, "lldp"), dt->next_hop_no_timestamp);
  return sc_node_prep_check_links(node);
}


static int sc_arista7280_48bit_ts_init(struct sc_node* node,
                                       const struct sc_attr* attr,
                                       const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  struct sc_arista7280_48bit_ts* dt;
  const char* switch_model;
  const char* filter_oui;
  const char* ts_format;
  const char* new_src_mac;

  if (nt == NULL) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_prep_fn = sc_arista7280_48bit_ts_prep;
    nt->nt_pkts_fn = sc_arista7280_48bit_ts_pkts;
    nt->nt_end_of_stream_fn = sc_arista7280_48bit_ts_end_of_stream;
  }
  sc_arista7280_48bit_ts_stats_declare(
    sc_thread_get_session(sc_node_get_thread(node))
  );
  node->nd_type = nt;

  dt = sc_thread_calloc(sc_node_get_thread(node), sizeof(*dt));
  dt->node = node;

  if( sc_node_init_get_arg_str(&switch_model, node,
                               "switch_model", NULL)                  < 0 ||
      sc_node_init_get_arg_str(&ts_format, node, "ts_format", NULL)   < 0 ||
      get_bool(&dt->strip_ticks, node, "strip_ticks", true)           < 0 ||
      get_bool(&dt->ts_src_mac, node, "ts_src_mac", false)            < 0 ||
      sc_node_init_get_arg_str(&filter_oui, node, "filter_oui", NULL) < 0 ||
      sc_node_init_get_arg_str(&new_src_mac, node,
                               "replacement_src_mac", NULL) < 0 )
    return -1;

  if( switch_model != NULL && strcmp(switch_model, "7280") )
    return sc_node_set_error(node, EINVAL, "%s: ERROR: "
                             "arg 'switch_model' bad value %s,"
                             "should be 7280", __func__, switch_model);

  if( ts_format != NULL && strcmp(ts_format, "48bit") )
    return sc_node_set_error(node, EINVAL, "%s: ERROR: "
                             "arg 'ts_format' bad value %s,"
                             "should be 48bit", __func__, ts_format);

  if( dt->strip_ticks && dt->ts_src_mac )
    return sc_node_set_error(node, EINVAL, "%s: ERROR: 'strip_ticks'"
                             "is not applicable with 'ts_src_mac'", __func__);

  if( filter_oui != NULL ) {
    if( parse_oui(dt->no_ts_oui, filter_oui) < 0 )
      return sc_node_set_error(node, EINVAL, "%s: ERROR: "
                               "arg 'filter_oui' badly formatted; expected "
                               "Ethernet OUI\n", __func__);
    dt->filter_oui = true;
  }

   if( new_src_mac != NULL ) {
    if( parse_mac(dt->new_src_mac, new_src_mac) < 0 )
      return sc_node_set_error(node, EINVAL, "%s: ERROR: "
                               "arg 'replacement_src_mac' badly formatted; "
                               "expected MAC address\n", __func__);
    dt->replace_src_mac = true;
  }

  node->nd_private = dt;

  sc_node_export_state(node, "sc_arista7280_48bit_ts_stats",
                       sizeof(struct sc_arista7280_48bit_ts_stats),
                       &dt->stats);
  dt->stats->strip_ticks = dt->strip_ticks;
  dt->stats->replace_src_mac = dt->replace_src_mac;

  return 0;
}


const struct sc_node_factory sc_arista7280_48bit_ts_sc_node_factory = {
  .nf_node_api_ver = SC_API_VER,
  .nf_name = "sc_arista7280_48bit_ts",
  .nf_source_file = __FILE__,
  .nf_init_fn = sc_arista7280_48bit_ts_init,
};

/** \endcond NODOC */
