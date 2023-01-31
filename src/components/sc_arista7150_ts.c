/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \page sc_arista7150_ts_node sc_arista_ts, switch_model=7150
 *
 * \brief Replace SolarCapture timestamp with timestamp from an Arista 7150
 * switch.
 *
 * \nodedetails
 * This mode is used to decode timestamps added by Arista 7150 series switches.
 *
 * \internal
 * The timestamps provided by the switch are an integer tick that wraps
 * quite frequently.  The switch also sends 'keyframes' which tell us the
 * correspondence between ticks and UTC.
 * \endinternal
 *
 * \nodeargs
 * Argument           | Optional? | Default   | Type           | Description
 * ------------------ | --------- | --------- | -------------- | ----------------------------------------------------------------------------------------------------
 * kf_ip_proto        | Yes       | 253       | ::SC_PARAM_INT | The IP protocol used to send key frames.
 * log_level          | Yes       | "sync"    | ::SC_PARAM_STR | The logging level of the node, must be set to one of "silent", "errors", "setup", "sync" or "verbose".
 * filter_oui         | Yes       |           | ::SC_PARAM_STR | Filter out timestamps with this OUI.
 * kf_device          | Yes       |           | ::SC_PARAM_STR | Filter keyframes by device field.
 * kf_eth_dhost       | No        |           | ::SC_PARAM_STR | Destination MAC address for the keyframes.
 * kf_ip_dest         | No        |           | ::SC_PARAM_STR | Destination IP address for the keyframes.
 * tick_freq          | Yes       | 350000000 | ::SC_PARAM_INT | Expected frequency in Hz of the switch tick.
 * max_freq_error_ppm | Yes       | 20000     | ::SC_PARAM_INT | Max ppm between expected and observed frequency before entering no sync state.
 * lost_sync_ms       | Yes       | 10000     | ::SC_PARAM_INT | Time after last keyframe to enter lost sync state.
 * no_sync_ms         | Yes       | 60000     | ::SC_PARAM_INT | Time after last keyframe to enter no sync state.
 * no_sync_drop       | Yes       | 0         | ::SC_PARAM_INT | Toggle sync drop, set to 1 for on 0 for off.
 * strip_ticks        | Yes       | 1         | ::SC_PARAM_INT | Toggle the option for the node to strip switch timestamps. Set to 0 for off and 1 for on.
 * has_fcs            | Yes       | 0         | ::SC_PARAM_INT | The incoming packets have a trailing FCS, after the ticks.
 * drop_sync_on_skew  | Yes       | 0         | ::SC_PARAM_INT | If set then sync is dropped when packets are received with a bad or absent ticks field.
 * switch_model       | Yes       |           | ::SC_PARAM_STR | Passed through from sc_arista_ts, must either '7150' or unspecified.
 *
 * \namedinputlinks
 * None
 *
 * \outputlinks
 * Link         | Default            | Description
 * ------------ | ------------------ | ----------------------------------------------------------------------------
 * ""           | free               | Packets with corrected timestamps
 * lost_sync    | default            | Packets with corrected timestamps when no keyframes have been seen for a while
 * no_sync      | lost_sync or free* | Used when no recent keyframes have been seen
 * no_timestamp | no_sync            | Packets with no arista timestamp
 * keyframes    | no_sync            | Used for keyframes
 * lldp         | no_timestamp       | Used for LLDP packets
 *
 * Keyframes and LLDP packets are treated specially because they are not
 * timestamped by the switch, and so it is not possible to give them timestamps
 * with the same clock as other packets.
 *
 * (*) no_sync packets go to the same place as lost_sync packets by default.
 * If no_sync_drop=1, then they are freed by default.
 *
 * \nodestatscopy{sc_arista7150_ts}
 *
 * \cond NODOC
 */

#include <sc_internal.h>
#include <sc_internal/builtin_nodes.h>
#include <sc_internal/packed_stream.h>

#define SC_TYPE_TEMPLATE  <sc_arista7150_ts_types_tmpl.h>
#define SC_DECLARE_TYPES  sc_arista7150_ts_stats_declare
#include <solar_capture/declare_types.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <stdint.h>
#include <inttypes.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <stdarg.h>

#define NS_PER_SEC 1000000000ULL

/* Definition of the hardware tick. */
#define TICK_BYTES          4
#define TICK_MASK           0x7fffffff
#define TICK_SUB(big, sml)  (((big) - (sml)) & TICK_MASK)

#define FCS_BYTES           4

/* MAX_HOST_T_DELTA_TICKS gives the max time delta we can tolerate between
 * packet arrival and the "sync" state that we rely on to compute switch
 * time.  We can't allow the delta to be big, or the ticks will wrap.
 *
 * MAX_TICK_DELTA gives the max delta we expect to see between the packet
 * ticks and sync_ticks.  It needs to be somewhat larger than
 * MAX_HOST_T_DELTA_TICKS.
 *
 * TICK_MASK corresponds to around 6 seconds when tick_freq is 350 MHz.
 */
#define MAX_HOST_T_DELTA_TICKS   (TICK_MASK / 3u)
#define MAX_TICK_FWD_DELTA       (TICK_MASK / 2u)
#define MAX_TICK_REV_DELTA       (TICK_MASK / 4u)


#define T_FMT           "%d.%09d"
#define TF_ARG(f)       (int) floorl(f), (int) (((f) - floorl(f)) * 1e9)
#define TS_ARG(ts)      (int) (ts)->tv_sec, (int) (ts)->tv_nsec

#define TICK_ARG(t) ((unsigned) ((unsigned) (t) & TICK_MASK))

#define LOG(st, x)  ((st)->log_level >= ats_ll_##x)


#ifndef ETHERTYPE_8021Q
# define ETHERTYPE_8021Q  0x8100
#endif
#ifndef ETHERTYPE_LLDP
# define ETHERTYPE_LLDP   0x88CC
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN
# define HTONS_CONST(x)  ((uint16_t) (((x) >> 8) | ((x) << 8)))
#else
# define HTONS_CONST(x)  (x)
#endif


enum arista7150_ts_state {
  /* Not synchronised. */
  ST_NO_SYNC,
  /* Seen one recent keyframe, but don't know the tick_freq yet. */
  ST_SYNC1,
  /* Synchronised (seen >1 recent keyframe). */
  ST_SYNC2,
  /* Was synchronised, but not seen keyframes for a while. */
  ST_LOST_SYNC,
};


static const char*const arista7150_ts_state_to_str[] = {
  "no_sync",
  "sync1",
  "sync2",
  "lost_sync",
};


enum arista_ts_log_level {
  ats_ll_silent,
  ats_ll_errors,
  ats_ll_setup,
  ats_ll_sync,
  ats_ll_verbose,
  ats_num_log_levels
};


static const char*const arista_ts_ll_to_str[] = {
  "silent",
  "errors",
  "setup",
  "sync",
  "verbose",
};


struct arista7150_ts {

  /* Configuration (mostly constant). */
  struct sc_node*                node;
  struct sc_arista7150_ts_stats* stats;
  const struct sc_node_link*     next_hop;
  const struct sc_node_link*     next_hop_keyframes;
  const struct sc_node_link*     next_hop_no_timestamp;
  const struct sc_node_link*     next_hop_lldp;
  const struct sc_node_link*     next_hop_lost_sync;
  const struct sc_node_link*     next_hop_no_sync;

  int                      filter_oui;
  uint8_t                  no_ts_oui[3];
  uint8_t                  kf_eth_dhost[6];
  uint8_t                  kf_ip_proto;
  uint32_t                 kf_ip_dest;         /* network endian */
  int                      kf_device;          /* network endian */
  int                      no_sync_drop;       /* drop by default if no sync */
  int                      has_fcs;            /* is there an FCS at the end of
                                                * each incoming packet,
                                                * after the ticks? */
  int                      strip_ticks;        /* strip packet timestamps */
  uint64_t                 exp_tick_freq;      /* expected tick frequency */
  uint64_t                 lost_sync_gap;
  uint64_t                 no_sync_gap;
  uint64_t                 max_host_t_delta_ns;
  long double              max_freq_error;
  enum arista_ts_log_level log_level;
  int                      drop_sync_on_skew;

  /* State. */
  enum arista7150_ts_state state;
  uint64_t                 last_keyframe_host_ts_ns;
  uint64_t                 last_keyframe_utc_ts_ns;
  long double              last_keyframe_utc_ts;
  long double              freq_keyframe_utc_ts;
  uint64_t                 tick_freq;          /* measured tick frequency */
  double                   ns_per_tick;
  uint64_t                 sync_utc_ts_ns;
  uint64_t                 sync_host_ts_ns;
  uint64_t                 sync_ticks;
  uint64_t                 freq_keyframe_ticks;
};


/* Switch sends packet with this info periodically.  Gives info needed to
 * convert ticks to UTC.
 */
struct keyframe_v1 {
  /* 64-bit version of the counter that gets appended to packets. */
  uint64_t  asic_time;
  /* UTC time, hopefully synchronised with PTP. */
  uint64_t  utc_nanos;
  /* When did the switch last see a PTP sync? */
  uint64_t  last_sync_nanos;
  /* When did the switch emit this keyframe? */
  uint64_t  kf_timestamp_nanos;
  /* Number of drops at the interface sending to us. */
  uint64_t  drops;
  /* This value can be assigned by the switch admin. */
  uint16_t  device;
  /* Identifies the switch port the keyframe was emitted on. */
  uint16_t  interface;
  /* 0 = timestamping disabled
   * 1 = timestamp before FCS
   * 2 = timestamp replaces FCS
   */
  uint8_t   fcs_type;
  uint8_t   reserved;
};


/* As of EOS-4.13 the keyframe format changes to this: */
struct keyframe_v2 {
  uint64_t  asic_time;
  uint64_t  utc_nanos;
  uint64_t  last_sync_nanos;
  uint64_t  skew_numerator;
  uint64_t  skew_denominator;
  uint64_t  kf_timestamp_nanos;
  uint64_t  drops;
  uint16_t  device;
  uint16_t  interface;
  uint8_t   fcs_type;
  uint8_t   reserved;
};


static inline uint64_t ntohll(uint64_t v)
{
  return ntohl(v >> 32) | ((uint64_t) ntohl((uint32_t) v) << 32);
}


static inline unsigned pkt_get_ticks_raw(const struct sc_packet* pkt,
                                         int has_fcs)
{
  uint32_t ticks_field[2];
  assert(TICK_BYTES == sizeof(uint32_t));
  sc_iovec_copy_from_end(ticks_field,
                         pkt->iov,
                         pkt->iovlen,
                         sizeof(ticks_field));
  return ntohl(ticks_field[has_fcs ? 0 : 1]);
}


static inline unsigned pkt_get_ticks(const struct sc_packet* pkt, int has_fcs)
{
  unsigned ticks_field = pkt_get_ticks_raw(pkt, has_fcs);
  return ((ticks_field & 0xffffff00) >> 1u) | (ticks_field & 0x7f);
}


static inline void pkt_strip_ticks(struct sc_packet* pkt)
{
  pkt->frame_len -= TICK_BYTES;
  sc_iovec_trim_end(pkt->iov, &pkt->iovlen, TICK_BYTES);
}


static inline unsigned ps_pkt_get_ticks_raw(struct sc_packed_packet* ps_pkt,
                                            int has_fcs)
{
  uint32_t ticks_field;
  char* payload = sc_packed_packet_payload(ps_pkt);
  assert(TICK_BYTES == sizeof(uint32_t));
  assert(ps_pkt->ps_cap_len == ps_pkt->ps_orig_len);
  memcpy(&ticks_field,
         payload + ps_pkt->ps_cap_len - TICK_BYTES -
           (has_fcs ? FCS_BYTES : 0),
         TICK_BYTES);
  return ntohl(ticks_field);
}


/* Should not be called on snapped packets, which will be missing their
 * timestamp. */
static inline unsigned ps_pkt_get_ticks(struct sc_packed_packet* ps_pkt,
                                        int has_fcs)
{
  unsigned ticks_field = ps_pkt_get_ticks_raw(ps_pkt, has_fcs);
  return ((ticks_field & 0xffffff00) >> 1u) | (ticks_field & 0x7f);
}


static inline void ps_pkt_strip_ticks(struct sc_packed_packet* ps_pkt)
{
  ps_pkt->ps_cap_len -= TICK_BYTES;
  ps_pkt->ps_orig_len -= TICK_BYTES;
}


static inline long double timespec_to_f(const struct timespec* ts)
{
  return ts->tv_sec + ts->tv_nsec * 1e-9L;
}


static inline uint64_t ps_pkt_ts_to_ns(const struct sc_packed_packet* ps_pkt)
{
  return ps_pkt->ps_ts_sec * NS_PER_SEC + ps_pkt->ps_ts_nsec;
}


static inline uint64_t pkt_ts_to_ns(const struct sc_packet* pkt)
{
  return pkt->ts_sec * NS_PER_SEC + pkt->ts_nsec;
}


static inline void pkt_ts_from_ns(struct sc_packet* pkt, uint64_t ts)
{
  pkt->ts_sec = ts / NS_PER_SEC;
  pkt->ts_nsec = ts % NS_PER_SEC;
}


static inline void ps_pkt_ts_from_ns(struct sc_packed_packet* ps_pkt,
                                     uint64_t ts)
{
  ps_pkt->ps_ts_sec = ts / NS_PER_SEC;
  ps_pkt->ps_ts_nsec = ts % NS_PER_SEC;
}


static const void* p_or(const void* a, const void* b)
{
  return a ? a : b;
}


static int arista_ts_log_level_from_str(const char* ll_str,
                                            enum arista_ts_log_level* ll_out)
{
  for( *ll_out = 0; *ll_out < ats_num_log_levels; ++*ll_out )
    if( ! strcasecmp(ll_str, arista_ts_ll_to_str[*ll_out]) )
      return 1;
  return 0;
}


static void arista7150_ts_set_state(struct arista7150_ts* st, enum arista7150_ts_state s,
                                    const char* why_fmt, ...)
{
  if( st->state != s ) {
    if( LOG(st, sync) ) {
      char buf[256];
      va_list va;
      va_start(va, why_fmt);
      vsprintf(buf, why_fmt, va);
      va_end(va);
      fprintf(stderr, "arista7150_ts: %s => %s %s\n",
              arista7150_ts_state_to_str[st->state], arista7150_ts_state_to_str[s],
              buf);
    }
    st->state = s;
    switch( st->state ) {
    case ST_NO_SYNC:
      ++(st->stats->enter_no_sync);
      break;
    case ST_SYNC1:
      ++(st->stats->enter_sync1);
      break;
    case ST_SYNC2:
      ++(st->stats->enter_sync2);
      break;
    case ST_LOST_SYNC:
      ++(st->stats->enter_lost_sync);
      break;
    }
    /* idea: measure time spent in each state? */
  }
}


static int arista7150_ts_advance_sync(struct arista7150_ts* st,
                                      uint64_t pkt_host_ts_ns, uint32_t pkt_ticks)
{
  /* Long time since we've seen a keyframe.  Need to avoid wrapping the
   * packet ticks.
   */
  if( LOG(st, sync) )
    fprintf(stderr, "arista7150_ts: GAP: gap=%.3fs sync_host_ts=%"PRIu64
            " sync_utc_ts=%"PRIu64" sync_ticks=%"PRIx64" pkt_host_ts_ns=%"
            PRIu64" pkt_ticks=%x\n",
            ((double) pkt_host_ts_ns - st->sync_host_ts_ns) / NS_PER_SEC,
            st->sync_host_ts_ns, st->sync_utc_ts_ns, st->sync_ticks,
            pkt_host_ts_ns, pkt_ticks);

  if( pkt_host_ts_ns < st->sync_host_ts_ns ) {
    /* Host timestamp is earlier than sync host timestamp.  Implies
     * configuration error or someone is messing with the clock.  We don't
     * really know what is going on, so can't do better than dropping sync.
     */
    if( LOG(st, errors) )
      fprintf(stderr, "arista7150_ts: ERROR: host_ts=%"PRIu64" before "
              "sync_host_ts=%"PRIu64" (last_kf_host_ts=%"PRIu64")\n",
              pkt_host_ts_ns, st->sync_host_ts_ns,
              st->last_keyframe_host_ts_ns);
    arista7150_ts_set_state(st, ST_NO_SYNC, "(host timestamp out-of-order)");
    ++(st->stats->n_host_ts_misorder);
    return -EINVAL;
  }

  ++(st->stats->n_kf_big_gap);
  do {
    st->sync_host_ts_ns += st->max_host_t_delta_ns;
    st->sync_utc_ts_ns += st->max_host_t_delta_ns;
    st->sync_ticks += MAX_HOST_T_DELTA_TICKS;
    uint64_t kf_delta_ns = st->sync_utc_ts_ns - st->last_keyframe_utc_ts_ns;
    if( st->no_sync_gap && kf_delta_ns > st->no_sync_gap ) {
      arista7150_ts_set_state(st, ST_NO_SYNC, "(%.3fs since last keyframe)",
                              (double) kf_delta_ns / NS_PER_SEC);
      return -EINVAL;
    }
    if( st->lost_sync_gap && kf_delta_ns > st->lost_sync_gap )
      arista7150_ts_set_state(st, ST_LOST_SYNC, "(%.3fs since last keyframe)",
                              (double) kf_delta_ns / NS_PER_SEC);
  } while( pkt_host_ts_ns - st->sync_host_ts_ns >= st->max_host_t_delta_ns );
  if( LOG(st, sync) )
    fprintf(stderr, "arista7150_ts: GAP: sync_host_ts=%"PRIu64
            " sync_utc_ts=%"PRIu64" sync_ticks=%"PRIx64"\n",
            st->sync_host_ts_ns, st->sync_utc_ts_ns, st->sync_ticks);
  return 0;
}


/* Calculates adjusted timestamp from base timestamp [pkt_host_ts] and Arista
 * ticks [pkt_ticks] and stores it in [*pkt_utc_ts]. Returns zero on success,
 * -ENOENT if the ticks are unexpectedly zero and -EINVAL on other errors.
 */
static int __arista7150_ts_pkt_adjust(struct arista7150_ts* st, uint64_t pkt_host_ts_ns,
                                      uint32_t pkt_ticks, uint64_t* pkt_utc_ts_ns)
{
  /* Check if large gap since last keyframe, or if packet's host timestamp
   * is before last keyframe's host timestamp.
   */
  if( pkt_host_ts_ns - st->sync_host_ts_ns >= st->max_host_t_delta_ns ) {
    int rc = arista7150_ts_advance_sync(st, pkt_host_ts_ns, pkt_ticks);
    if( rc != 0 )
      return rc;
  }

  int ticks_delta = TICK_SUB(pkt_ticks, (uint32_t) st->sync_ticks);
  if( ticks_delta < MAX_TICK_FWD_DELTA ) {
    /* we're good */
  }
  else {
    ticks_delta = - TICK_SUB((uint32_t) st->sync_ticks, pkt_ticks);
    if( ticks_delta < -MAX_TICK_REV_DELTA )
      goto out_of_range;
  }
  int64_t ns_delta = ticks_delta * st->ns_per_tick;
  *pkt_utc_ts_ns = st->sync_utc_ts_ns + ns_delta;
  if( LOG(st, verbose) )
    fprintf(stderr, "arista7150_ts: PKT: state=%s ticks=%x sync_ticks=%"PRIx64
            " ticks_delta=%d ns_delta=%"PRId64" host_ts=%"PRIu64
            " corrected_ts=%"PRIu64"\n", arista7150_ts_state_to_str[st->state],
            pkt_ticks, st->sync_ticks, ticks_delta, ns_delta, pkt_host_ts_ns,
            *pkt_utc_ts_ns);
  return 0;

 out_of_range:
  /* pkt_ticks is not within the range we expect, which implies either
   * badness by the switch, or we've not seen keyframes for a long time and
   * started to skew, or severe reordering between timestamped frames and
   * keyframes, or we've received a frame that doesn't have a timestamp.
   *
   * Two reason packets can be without a timestamp: (a) Packet is generated
   * by the switch rather than forwarded.  In this case the timestamp is
   * zero.  (b) Packets without timestamps being multiplexed into the
   * stream we're capturing.  In this case the end of the frame or FCS is
   * being interpreted as the tick field.
   *
   * NB. We expect packets without a timestamp to be trapped by the OUI
   * check in arista7150_ts_try_special().
   *
   * Unfortunately we can't reliably distinguish between frames without
   * timestamps and frames with valid pkt_ticks=0.  Therefore if packets
   * get here without timestamps, but happen to appear to be in-range, they
   * will get bogus timestamps.
   */
  if( LOG(st, sync) )
    fprintf(stderr, "arista7150_ts: %s: state=%s ticks=%x sync_ticks=%"PRIx64
            " ticks_delta=%d sync_host_ts=%"PRIu64" sync_utc_ts=%"PRIu64
            " pkt_host_ts=%"PRIu64"\n", pkt_ticks ? "SKEW":"SKEW_ZERO",
            arista7150_ts_state_to_str[st->state], pkt_ticks, st->sync_ticks,
            ticks_delta, st->last_keyframe_host_ts_ns, st->sync_utc_ts_ns,
            pkt_host_ts_ns);
  if( pkt_ticks == 0 ) {
    /* Don't drop sync -- likely just a packet without valid ticks. */
    ++(st->stats->n_skew_zero_ticks);
    return -ENOENT;
  }
  else if( ! st->drop_sync_on_skew ) {
    ++(st->stats->n_skew);
    return -ENOENT;
  }
  else {
    arista7150_ts_set_state(st, ST_NO_SYNC, "(skew)");
    ++(st->stats->n_skew);
    return -EINVAL;
  }
}


static int arista7150_ts_pkt_adjust(struct arista7150_ts* st, uint64_t pkt_host_ts_ns,
                                    struct sc_packet* pkt)
{
  uint32_t pkt_ticks;
  uint64_t pkt_utc_ts_ns;

  pkt_ticks = pkt_get_ticks(pkt, st->has_fcs);
  if( st->strip_ticks )
    pkt_strip_ticks(pkt);

  int rc;
  rc = __arista7150_ts_pkt_adjust(st, pkt_host_ts_ns, pkt_ticks, &pkt_utc_ts_ns);
  if( rc == 0 )
    pkt_ts_from_ns(pkt, pkt_utc_ts_ns);
  else if( rc == -ENOENT ) {
    /* Missing timestamp. */
    sc_forward(st->node, st->next_hop_no_timestamp, pkt);
    return 1;
  }

  return 0;
}


static void arista7150_ts_ps_pkt_adjust(struct arista7150_ts* st,
                                        uint64_t pkt_host_ts_ns,
                                        struct sc_packed_packet* ps_pkt)
{
  uint32_t pkt_ticks;
  uint64_t pkt_utc_ts_ns;

  /* Don't attempt to read timestamp from snapped packets. */
  if( ps_pkt->ps_cap_len == ps_pkt->ps_orig_len ) {
    pkt_ticks = ps_pkt_get_ticks(ps_pkt, st->has_fcs);
    if( st->strip_ticks )
      ps_pkt_strip_ticks(ps_pkt);

    if( __arista7150_ts_pkt_adjust(st, pkt_host_ts_ns,
                                   pkt_ticks, &pkt_utc_ts_ns) == 0 )
      ps_pkt_ts_from_ns(ps_pkt, pkt_utc_ts_ns);
  }
}


static void arista7150_ts_calc_freq(struct arista7150_ts* st, uint64_t kf_ticks,
                                    long double utc_ts)
{
  /* Calculate tick frequency based on tick and UTC deltas between this
   * keyframe and an earlier one.  In order to calculate the tick_freq with
   * sufficient precision we need an interval of at least a second.  (Plus
   * a customer has reported seeing the switch generate duplicate
   * keyframes.  ie. With no delta in UTC or tick).
   */
  long double kf_delta = utc_ts - st->freq_keyframe_utc_ts;
  uint64_t tick_delta =
    (kf_ticks - st->freq_keyframe_ticks) & 0x8fffffffffffffff;
  st->tick_freq = tick_delta / kf_delta;
  st->ns_per_tick = ( kf_delta * 1000000000 ) / tick_delta;
  st->stats->tick_freq = st->tick_freq;
  if( LOG(st, sync) )
    fprintf(stderr, "arista7150_ts: KF: delta="T_FMT" tick_freq=%"PRIu64
            " ns_per_tick=%1.09f\n", TF_ARG(kf_delta), st->tick_freq,
            st->ns_per_tick);
  if( fabs((double)st->tick_freq - st->exp_tick_freq) / st->exp_tick_freq >
      st->max_freq_error ) {
    if( LOG(st, errors) ) {
      fprintf(stderr, "arista7150_ts: WARNING: tick_freq looks wrong or UTC "
              "stepped (exp=%"PRIu64" measured=%"PRIu64")\n", st->exp_tick_freq,
              st->tick_freq);
      fprintf(stderr, "arista7150_ts: WARNING: ticks=%"PRIx64",%"PRIx64
              " utc="T_FMT","T_FMT"\n", kf_ticks, st->freq_keyframe_ticks,
              TF_ARG(utc_ts), TF_ARG(st->freq_keyframe_utc_ts));
      fprintf(stderr, "arista7150_ts: WARNING: tick_delta=%"PRIx64
              " utc_delta="T_FMT"\n", tick_delta, TF_ARG(kf_delta));
    }
    arista7150_ts_set_state(st, ST_NO_SYNC, "(bad tick freq=%Lf)", st->tick_freq);
    st->tick_freq = 0.0L;
    st->stats->tick_freq = 0;
  }
  st->freq_keyframe_utc_ts = utc_ts;
  st->freq_keyframe_ticks = kf_ticks;
}


static void arista7150_ts_keyframe(struct arista7150_ts* st,
                                   uint64_t kf_host_ts_ns,
                                   const struct keyframe_v1* kf)
{
  struct timespec kf_utc_timespec;
  uint64_t utc_nanos = ntohll(kf->utc_nanos);
  st->last_keyframe_utc_ts_ns = utc_nanos;
  kf_utc_timespec.tv_sec = utc_nanos / NS_PER_SEC;
  kf_utc_timespec.tv_nsec = utc_nanos % NS_PER_SEC;
  long double kf_utc_ts = timespec_to_f(&kf_utc_timespec);
  uint64_t kf_ticks = ntohll(kf->asic_time);

  if( LOG(st, sync) )
    fprintf(stderr, "arista7150_ts: KF: state=%s kf_utc="T_FMT" host=%"PRIu64" "
            "ticks=%"PRIx64" drops=%"PRId64"\n",
            arista7150_ts_state_to_str[st->state], TF_ARG(kf_utc_ts),
            kf_host_ts_ns, kf_ticks, ntohll(kf->drops));

  st->stats->kf_switch_drops = ntohll(kf->drops);

  if( kf->fcs_type != 1 && kf->fcs_type != 2 && LOG(st, errors) ) {
    fprintf(stderr, "arista7150_ts: KF: ERROR: fcs_type=%d; expected 1 or 2\n",
            (int) kf->fcs_type);
    ++(st->stats->n_kf_bad_fcs_type);
  }

  long double kf_delta = kf_utc_ts - st->last_keyframe_utc_ts;
  if( st->no_sync_gap && kf_delta * NS_PER_SEC > st->no_sync_gap )
    arista7150_ts_set_state(st, ST_NO_SYNC, "(keyframe interval > no_sync_ms)");
  st->last_keyframe_utc_ts = kf_utc_ts;

  if( st->state != ST_NO_SYNC ) {
    if( kf_utc_ts - st->freq_keyframe_utc_ts >= 0.99L )
      arista7150_ts_calc_freq(st, kf_ticks, kf_utc_ts);
  }
  else {
    st->freq_keyframe_utc_ts = kf_utc_ts;
    st->freq_keyframe_ticks = kf_ticks;
  }

  st->sync_utc_ts_ns = utc_nanos;
  st->sync_ticks = kf_ticks;
  st->last_keyframe_host_ts_ns = kf_host_ts_ns;
  st->sync_host_ts_ns = kf_host_ts_ns;
  if( st->state == ST_NO_SYNC )
    arista7150_ts_set_state(st, ST_SYNC1, "");
  else if( st->tick_freq != 0 )
    arista7150_ts_set_state(st, ST_SYNC2, "");

  ++(st->stats->n_keyframes);
}


static int arista7150_ts_try_keyframe_v1(struct arista7150_ts* st,
                                         uint64_t kf_host_ts,
                                         const struct keyframe_v1* kf)
{
  if( st->kf_device >= 0 && kf->device != st->kf_device ) {
    if( LOG(st, verbose) )
      fprintf(stderr, "arista7150_ts: KF: device=%d != %d\n",
              (int) ntohs(kf->device), (int) ntohs(st->kf_device));
    ++(st->stats->n_kf_dev_mismatch);
    return 0;
  }
  arista7150_ts_keyframe(st, kf_host_ts, kf);
  return 1;
}


static int arista7150_ts_try_keyframe_v2(struct arista7150_ts* st,
                                         uint64_t kf_host_ts,
                                         const struct keyframe_v2* kf)
{
  if( st->kf_device >= 0 && kf->device != st->kf_device ) {
    if( LOG(st, verbose) )
      fprintf(stderr, "arista7150_ts: KF: device=%d != %d\n",
              (int) ntohs(kf->device), (int) ntohs(st->kf_device));
    ++(st->stats->n_kf_dev_mismatch);
    return 0;
  }
  struct keyframe_v1 kf1;
  kf1.asic_time = kf->asic_time;
  kf1.utc_nanos = kf->utc_nanos;
  kf1.last_sync_nanos = kf->last_sync_nanos;
  kf1.kf_timestamp_nanos = kf->kf_timestamp_nanos;
  kf1.drops = kf->drops;
  kf1.device = kf->device;
  kf1.interface = kf->interface;
  kf1.fcs_type = kf->fcs_type;
  kf1.reserved = kf->reserved;
  arista7150_ts_keyframe(st, kf_host_ts, &kf1);
  return 1;
}


/* Compares first 3 bytes pointed to by args.  Returns 0 if they're the
 * same else non-zero.
 */
static inline int cmp_oui(const void* oui_a, const void* oui_b)
{
  const uint8_t* a = oui_a;
  const uint8_t* b = oui_b;
  return (a[0] - b[0]) | (a[1] - b[1]) | (a[2] - b[2]);
}


/* Common logic for identifying and processing frames with timestamping control
 * significance. If the frame is handled here, its ticks are stripped if
 * necessary and the next hop is returned; otherwise, the frame is not modified
 * and NULL is returned.
 */
static const struct sc_node_link*
__arista7150_ts_try_special(struct arista7150_ts* st, uint64_t pkt_host_ts_ns,
                            const struct ether_header* eth)
{
  const uint16_t* p_ether_type = &eth->ether_type;
  if( *p_ether_type == htons(ETHERTYPE_8021Q) )
    p_ether_type += 2;
  switch( *p_ether_type ) {
  case HTONS_CONST(ETHERTYPE_IP):
    break;
  case HTONS_CONST(ETHERTYPE_LLDP):
    ++(st->stats->n_filtered_other);
    goto no_timestamp;
  default:
    goto check_oui;
  }

  if( memcmp(eth->ether_dhost, st->kf_eth_dhost, 6) != 0 )
    goto check_oui;

  const struct iphdr* ip = (void*) (p_ether_type + 1);
  if( ip->protocol != st->kf_ip_proto || ip->daddr != st->kf_ip_dest )
    goto check_oui;

  int ip_paylen = ntohs(ip->tot_len) - (ip->ihl << 2);
  void* ip_payload = (uint32_t*) ip + ip->ihl;

  switch( ip_paylen ) {
  case 46:
    return arista7150_ts_try_keyframe_v1(st, pkt_host_ts_ns, ip_payload) ?
           st->next_hop_keyframes : NULL;
  case 62:
    return arista7150_ts_try_keyframe_v2(st, pkt_host_ts_ns, ip_payload) ?
           st->next_hop_keyframes : NULL;
  default:
    ++(st->stats->n_kf_len_mismatch);
    goto check_oui;
  }
  /* unreachable */

 check_oui:
  if( st->filter_oui && cmp_oui(eth->ether_shost, st->no_ts_oui) == 0 ) {
    ++(st->stats->n_filtered_oui);
    goto no_timestamp;
  }
  return NULL;

 no_timestamp:
  if( LOG(st, verbose) )
    fprintf(stderr, "arista7150_ts: NO TIMESTAMP type=%04x OUI=%02x:%02x:%02x\n",
            ntohs(*p_ether_type), (unsigned) eth->ether_shost[0],
            (unsigned) eth->ether_shost[1], (unsigned) eth->ether_shost[2]);
  return st->next_hop_no_timestamp;
}


static inline int
arista7150_ts_try_special(struct arista7150_ts* st, uint64_t pkt_host_ts_ns,
                          struct sc_packet* pkt)
{
  const struct sc_node_link* next_hop;
  next_hop = __arista7150_ts_try_special(st, pkt_host_ts_ns, pkt->iov[0].iov_base);
  if( next_hop != NULL ) {
    if( st->strip_ticks )
      pkt_strip_ticks(pkt);
    sc_forward(st->node, next_hop, pkt);
    return 1;
  }

  return 0;
}


static inline int
arista7150_ts_ps_try_special(struct arista7150_ts* st, uint64_t pkt_host_ts_ns,
                             struct sc_packed_packet* ps_pkt)
{
  if( __arista7150_ts_try_special(st, pkt_host_ts_ns,
                              sc_packed_packet_payload(ps_pkt)) != NULL ) {
    if( st->strip_ticks )
      ps_pkt_strip_ticks(ps_pkt);
    return 1;
  }

  return 0;
}


/* Returns non-zero if and only if processing is complete for the packet. */
static inline int arista7150_ts_pkt(struct arista7150_ts* st, uint64_t pkt_host_ts_ns,
                                    struct sc_packet* pkt)
{
  if( arista7150_ts_try_special(st, pkt_host_ts_ns, pkt) )
    /* Packet already forwarded. */
    return 1;

  if( st->state >= ST_SYNC2 ) {  /* sync2 or lost_sync */
    if( arista7150_ts_pkt_adjust(st, pkt_host_ts_ns, pkt) )
      /* Packet already forwarded. */
      return 1;
  }

  const struct sc_node_link* next_hop;
  next_hop = st->state == ST_SYNC2     ? st->next_hop           :
             st->state == ST_LOST_SYNC ? st->next_hop_lost_sync :
             /* ST_SYNC1, ST_NO_SYNC */  st->next_hop_no_sync;
  sc_forward(st->node, next_hop, pkt);
  return 0;
}


static inline void arista7150_ts_record_pkt(struct arista7150_ts* st)
{
  switch( st->state ) {
  case ST_SYNC2:
    break;
  case ST_LOST_SYNC:
    ++(st->stats->n_lost_sync);
    break;
  case ST_SYNC1:
  case ST_NO_SYNC:
    ++(st->stats->n_no_sync);
    if( LOG(st, verbose) )
      fprintf(stderr, "arista7150_ts: PKT: state=%s\n",
              arista7150_ts_state_to_str[st->state]);
    break;
  }
}


/* Iterates over the packets in a packed-stream buffer and adjusts their
 * timestamps.
 */
static void arista7150_ts_ps_buf(struct arista7150_ts* st, struct sc_packet* pkt)
{
  SC_TEST(pkt->flags & SC_PACKED_STREAM);
  SC_TEST(pkt->iovlen == 1);

  struct sc_packed_packet* ps_pkt = sc_packet_packed_first(pkt);
  struct sc_packed_packet* ps_end = sc_packet_packed_end(pkt);

  for( ; ps_pkt < ps_end; ps_pkt = sc_packed_packet_next(ps_pkt) ) {
    uint64_t pkt_host_ts_ns = ps_pkt_ts_to_ns(ps_pkt);
    if( arista7150_ts_ps_try_special(st, pkt_host_ts_ns, ps_pkt) )
      continue;
    if( st->state >= ST_SYNC2 )
      arista7150_ts_ps_pkt_adjust(st, pkt_host_ts_ns, ps_pkt);
    arista7150_ts_record_pkt(st);
  }

  /* Packed-stream buffers are all forwarded to the same link. */
  sc_forward(st->node, st->next_hop, pkt);
}


static void arista7150_ts_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct arista7150_ts* st = node->nd_private;
  struct sc_packet* next;
  struct sc_packet* pkt;

  for( next = pl->head; (pkt = next) && ((next = next->next) || 1); )
    if( pkt->flags & SC_PACKED_STREAM )
      arista7150_ts_ps_buf(st, pkt);
    else if( ! arista7150_ts_pkt(st, pkt_ts_to_ns(pkt), pkt) )
      arista7150_ts_record_pkt(st);
}


static void arista7150_ts_end_of_stream(struct sc_node* node)
{
  struct arista7150_ts* st = node->nd_private;
  sc_node_link_end_of_stream(node, st->next_hop);
  sc_node_link_end_of_stream(node, st->next_hop_keyframes);
  sc_node_link_end_of_stream(node, st->next_hop_no_timestamp);
  sc_node_link_end_of_stream(node, st->next_hop_lldp);
  sc_node_link_end_of_stream(node, st->next_hop_lost_sync);
  sc_node_link_end_of_stream(node, st->next_hop_no_sync);
}


static int ip4_is_broadcast(unsigned ip4_ne)
{
  return ip4_ne == 0xffffffff;
}


static int ip4_is_multicast(unsigned ip4_ne)
{
  return (ip4_ne & htonl(0xf0000000)) == htonl(0xe0000000);
}


static int ip4_to_mac(uint8_t* mac, unsigned ip4_ne)
{
  if( ip4_is_broadcast(ip4_ne) ) {
    memset(mac, 0xff, 6);
    return 0;
  }
  else if( ip4_is_multicast(ip4_ne) ) {
    unsigned ip4 = ntohl(ip4_ne);
    mac[0] = 1;
    mac[1] = 0;
    mac[2] = 0x5e;
    mac[3] = (ip4 >> 16) & 0x7f;
    mac[4] = (ip4 >>  8) & 0xff;
    mac[5] =  ip4        & 0xff;
    return 0;
  }
  else {
    return -1;
  }
}


static int parse_mac(uint8_t* mac, const char* s)
{
  unsigned u[6];
  int i;
  char c;
  if( sscanf(s, "%x:%x:%x:%x:%x:%x%c",
             &u[0], &u[1], &u[2], &u[3], &u[4], &u[5], &c) != 6 )
    return -1;
  for( i = 0; i < 6; ++i ) {
    if( u[i] > 255 )
      return -1;
    mac[i] = u[i];
    }
  return 0;
}


static int parse_oui(uint8_t* oui, const char* s)
{
  unsigned u[3];
  char c;
  int i;
  if( sscanf(s, "%x:%x:%x%c", &u[0], &u[1], &u[2], &c) != 3 )
    return -1;
  for( i = 0; i < 3; ++i ) {
    if( u[i] > 255 )
      return -1;
    oui[i] = u[i];
  }
  return 0;
}


static int parse_ip(uint32_t* pip, const char* s)
{
  struct addrinfo hints, *ai;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  int rc = getaddrinfo(s, NULL, &hints, &ai);
  if( rc != 0 )
    return rc;
  const struct sockaddr_in* sin = (void*) ai->ai_addr;
  *pip = sin->sin_addr.s_addr;
  freeaddrinfo(ai);
  return 0;
}


static int get_str(const char** s, struct sc_node* node, const char* name,
                   int required)
{
  if( sc_node_init_get_arg_str(s, node, name, NULL) < 0 )
    return -1;
  if( required && *s == NULL )
    return sc_node_set_error(node, EINVAL, "sc_arista7150: ERROR: required "
                             "arg '%s' not provided\n", name);
  return (*s == NULL) ? 1 : 0;
}


static int get_mac(uint8_t* mac, struct sc_node* node, const char* name,
                   int required)
{
  const char* s;
  if( get_str(&s, node, name, required) < 0 )
    return -1;
  if( s != NULL && parse_mac(mac, s) < 0 )
    return sc_node_set_error(node, EINVAL, "sc_arista7150: ERROR: arg '%s' badly "
                             "formatted; expected mac address\n", name);
  return (s == NULL) ? 1 : 0;
}


static int get_ip(uint32_t* pip, struct sc_node* node, const char* name,
                  int required)
{
  const char* s;
  int rc;
  if( get_str(&s, node, name, required) < 0 )
    return -1;
  if( s != NULL && (rc = parse_ip(pip, s)) < 0 )
    return sc_node_set_error(node, EINVAL, "sc_arista7150: ERROR: could not "
                             "resolve '%s' to an IP address for arg %s (%s)\n",
                             s, name, gai_strerror(rc));
  return (s == NULL) ? 1 : 0;
}


static int get_uint(int* v, struct sc_node* node, const char* k, int default_v)
{
  if( sc_node_init_get_arg_int(v, node, k, default_v) < 0 || *v < 0 )
    return sc_node_set_error(node, EINVAL, "sc_arista7150: ERROR: bad value for "
                             "arg '%s'; expected >= 0\n", k);
  return 0;
}


static int get_bool(int* v, struct sc_node* node, const char* k, int default_v)
{
  if( sc_node_init_get_arg_int(v, node, k, default_v) < 0 ||
      *v < 0 || *v > 1 )
    return sc_node_set_error(node, EINVAL, "sc_arista7150: ERROR: bad value for "
                             "arg '%s'; expected 0 or 1\n", k);
  return 0;
}


static void dump_options(struct arista7150_ts* st)
{
  fprintf(stderr, "arista7150_ts: kf_eth_dhost=%02x:%02x:%02x:%02x:%02x:%02x\n",
          (unsigned) st->kf_eth_dhost[0], (unsigned) st->kf_eth_dhost[1],
          (unsigned) st->kf_eth_dhost[2], (unsigned) st->kf_eth_dhost[3],
          (unsigned) st->kf_eth_dhost[4], (unsigned) st->kf_eth_dhost[5]);
  fprintf(stderr, "arista7150_ts: kf_ip_proto=%d\n", (int) st->kf_ip_proto);
  struct in_addr ip = { st->kf_ip_dest };
  fprintf(stderr, "arista7150_ts: kf_ip_dest=%s\n", inet_ntoa(ip));
  fprintf(stderr, "arista7150_ts: strip_ticks=%d\n", st->strip_ticks);
  fprintf(stderr, "arista7150_ts: tick_freq=%"PRIu64"\n", st->tick_freq);
  fprintf(stderr, "arista7150_ts: lost_sync_ms=%d\n",
          (int) (st->lost_sync_gap / 1000000));
  fprintf(stderr, "arista7150_ts: no_sync_ms=%d\n",
          (int) (st->no_sync_gap / 1000000));
  fprintf(stderr, "arista7150_ts: max_freq_error=%d\n",
          (int) (st->max_freq_error * 1e6));
  fprintf(stderr, "arista7150_ts: filter_oui=%d oui=%02x:%02x:%02x\n",
          st->filter_oui, (unsigned) st->no_ts_oui[0],
          (unsigned) st->no_ts_oui[1], (unsigned) st->no_ts_oui[2]);
  fprintf(stderr, "arista7150_ts: has_fcs=%d\n", st->has_fcs);
  fprintf(stderr, "arista7150_ts: drop_sync_on_skew=%d\n", st->drop_sync_on_skew);
}


static int arista7150_ts_prep(struct sc_node* node,
                              const struct sc_node_link*const* links, int n_links)
{
  struct arista7150_ts* st = node->nd_private;

  st->next_hop = sc_node_prep_get_link_or_free(node, "");
  st->next_hop_lost_sync =
    p_or(sc_node_prep_get_link(node, "lost_sync"), st->next_hop);

  /* Where to send packets when the timestamps are not accurate. */
  st->next_hop_no_sync = sc_node_prep_get_link(node, "no_sync");
  if( st->next_hop_no_sync == NULL ) {
    if( st->no_sync_drop )
      st->next_hop_no_sync = sc_node_prep_get_link_or_free(node, NULL);
    else
      st->next_hop_no_sync = st->next_hop_lost_sync;
  }

  /* Keyframes and other packets with zero-ticks don't get corrected
   * timestamps, so send them the same way as no_sync by default.
   */
  st->next_hop_keyframes =
    p_or(sc_node_prep_get_link(node, "keyframes"), st->next_hop_no_sync);
  st->next_hop_no_timestamp =
    p_or(sc_node_prep_get_link(node, "no_timestamp"), st->next_hop_no_sync);
  /* NB. Not used, but we still accept a link called 'lldp' to avoid
   * breaking any apps that expect it.
   */
  st->next_hop_lldp =
    p_or(sc_node_prep_get_link(node, "lldp"), st->next_hop_no_timestamp);

  return sc_node_prep_check_links(node);
}


static int arista7150_ts_init(struct sc_node* node, const struct sc_attr* attr,
                              const struct sc_node_factory* factory)
{
  struct arista7150_ts* st;
  const char* s;
  int tick_freq, mfe, rc;

  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_pkts_fn = arista7150_ts_pkts;
    nt->nt_prep_fn = arista7150_ts_prep;
    nt->nt_end_of_stream_fn = arista7150_ts_end_of_stream;
  }
  sc_arista7150_ts_stats_declare(sc_thread_get_session(sc_node_get_thread(node)));
  node->nd_type = nt;

  st = sc_thread_calloc(sc_node_get_thread(node), sizeof(*st));
  st->node = node;

  int ip_proto;
  if( sc_node_init_get_arg_int(&ip_proto, node, "kf_ip_proto", 253) < 0 ||
      (unsigned) ip_proto > 255 ) {
    sc_node_set_error(node, EINVAL, "%s: ERROR: bad kf_ip_proto; "
                      "expected 0-255\n", __func__);
    goto error;
  }
  st->kf_ip_proto = ip_proto;

  if( sc_node_init_get_arg_str(&s, node, "log_level", "sync") < 0 )
    goto error;
  if( ! arista_ts_log_level_from_str(s, &st->log_level) ) {
    sc_node_set_error(node, EINVAL, "%s: ERROR: bad log_level '%s'; expected "
                      "one of: silent, errors, setup, sync or verbose\n",
                      __func__, s);
    goto error;
  }

  /* st->filter_oui = 0; */
  if( sc_node_init_get_arg_str(&s, node, "filter_oui", NULL) < 0 )
    goto error;
  if( s != NULL ) {
    if( parse_oui(st->no_ts_oui, s) < 0 ) {
      sc_node_set_error(node, EINVAL, "sc_arista7150: ERROR: arg 'filter_oui' "
                        "badly formatted; expected Ethernet OUI\n");
      goto error;
    }
    st->filter_oui = 1;
  }

  if( sc_node_init_get_arg_str(&s, node, "switch_model", NULL) < 0 )
    goto error;
  if( s != NULL && strcmp(s, "7150") )
    return sc_node_set_error(node, EINVAL, "sc_arista7150: ERROR: arg 'switch_model' bad mode %s"
                             ", should be 7150", s);

  if( get_ip(&st->kf_ip_dest, node, "kf_ip_dest", 1)                  < 0 ||
      get_bool(&st->no_sync_drop, node, "no_sync_drop", 0)            < 0 ||
      sc_node_init_get_arg_int(&st->kf_device, node, "kf_device", -1) < 0 ||
      get_bool(&st->strip_ticks, node, "strip_ticks", 1)              < 0 ||
      get_bool(&st->has_fcs, node, "has_fcs", 0)                      < 0 ||
      get_bool(&st->drop_sync_on_skew, node, "drop_sync_on_skew", 0)  < 0 ||
      get_uint(&tick_freq, node, "tick_freq", 350000000)              < 0 ||
      get_uint(&mfe, node, "max_freq_error_ppm", 20000)               < 0  )
    goto error;

  if( st->strip_ticks && st->has_fcs ) {
    sc_node_set_error(node, EINVAL, "sc_arista7150: ERROR: bad param combination:"
                      " strip_ticks AND has_fcs");
    goto error;
  }

  int gap_ms;
  if( sc_node_init_get_arg_int(&gap_ms, node, "lost_sync_ms", 10000) < 0 ||
      gap_ms < 0 )
    return sc_node_set_error(node, EINVAL, "sc_arista7150: ERROR: bad value for "
                             "arg lost_sync_ms; expected >= 0\n");
  st->lost_sync_gap = gap_ms * 1000000ULL;
  if( sc_node_init_get_arg_int(&gap_ms, node, "no_sync_ms", 60000) < 0 ||
      gap_ms < 0 )
    return sc_node_set_error(node, EINVAL, "sc_arista7150: ERROR: bad value for "
                             "no_sync_ms; expected >= 0\n");
  st->no_sync_gap = gap_ms * 1000000ULL;
  st->exp_tick_freq = tick_freq;
  st->max_freq_error = mfe / 1e6;
  if( st->kf_device >= 0 )
    st->kf_device = htons(st->kf_device);

  /* If possible, calculate mac from IP (if mac not given). */
  if( (rc = get_mac(st->kf_eth_dhost, node, "kf_eth_dhost", 0)) > 0 ) {
    if( ip4_to_mac(st->kf_eth_dhost, st->kf_ip_dest) < 0 ) {
      sc_node_set_error(node, EINVAL, "sc_arista7150: ERROR: arg 'kf_eth_dhost' "
                        "is required because kf_ip_dest is not multicast\n");
      goto error;
    }
  }
  else if( rc < 0 ) {
    goto error;
  }

  /* Max delta (in nanoseconds) we can safely compute a tick-delta over.  If we
   * go much larger than this we'll overflow the 31-bit tick.
   */
  st->max_host_t_delta_ns =
    (double)MAX_HOST_T_DELTA_TICKS * NS_PER_SEC / st->exp_tick_freq;
  st->state = ST_NO_SYNC;
  st->tick_freq = 0;
  node->nd_private = st;

  sc_node_export_state(node, "sc_arista7150_ts_stats",
                       sizeof(struct sc_arista7150_ts_stats), &st->stats);
  st->stats->max_host_t_delta = st->max_host_t_delta_ns;
  st->stats->max_freq_error = st->max_freq_error;
  st->stats->lost_sync_ms = st->lost_sync_gap / 1000000ULL;
  st->stats->no_sync_ms = st->no_sync_gap / 1000000ULL;
  st->stats->exp_tick_freq = st->exp_tick_freq;
  st->stats->strip_ticks = st->strip_ticks;
  st->stats->log_level = st->log_level;
  st->stats->has_fcs = st->has_fcs;

  if( st->log_level >= ats_ll_setup )
    dump_options(st);

  return 0;

 error:
  sc_thread_mfree(sc_node_get_thread(node), st);
  return -1;
}


const struct sc_node_factory sc_arista7150_ts_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_arista7150_ts",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = arista7150_ts_init,
};

/** \endcond NODOC */
