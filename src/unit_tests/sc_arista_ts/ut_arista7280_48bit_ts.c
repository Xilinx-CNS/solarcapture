/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/*
 * ut_arista7280_48bit_ts.c
 *
 *  Created on: 03 Apr 2019
 *      Author: marsik
 */

#include "solar_capture/ext_packet.h"

#include <sys/uio.h>
#include <check.h>
#include <check_helpers.h>
#include <ut_helpers.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Include C directly so that we can test static functions */
#include "../../components/sc_arista7280_48bit_ts.c"

/* Add macros for the test name to avoid long unreadable lines in the code */
#define TEST_FETCH_ARISTA_TS(_ret, _ts_type) \
  TEST_that_fetch_arista7280_48bit_time_returns_\
    ##_ret##_packet_##_ts_type##_timestamp

#define TEST_FETCH_ARISTA_TS_PACKED(_ret, _ts_type) \
  TEST_that_fetch_arista7280_48bit_time_returns_\
    ##_ret##_packed_packet_##_ts_type##_timestamp

#define TEST_STRIP_TICKS(_pkt_type) \
  TEST_strip_timestamp_removes_field_from_##_pkt_type##_packet

#define TEST_PROCESS_IGNORE(_pkt_type) \
  TEST_that_process_packet_ignores_##_pkt_type##_packets

#define TEST_PROCESS_PACKED_IGNORE(_pkt_type) \
  TEST_that_process_packed_packet_ignores_##_pkt_type##_packets

#define TEST_PROCESS_PACKED_FLAG(_pkt_type) \
  TEST_that_process_packed_packet_flags_##_pkt_type##_packets

#define TEST_PROCESS_DECODE(_pkt_type) \
  TEST_that_process_packet_decodes_##_pkt_type##_packets

#define TEST_PROCESS_PACKED_DECODE(_pkt_type) \
  TEST_that_process_packed_packet_decodes_##_pkt_type##_packets

#define TEST_PROCESS_STRIP_TICKS \
  TEST_that_process_packet_strip_ticks_flag_works

#define TEST_PROCESS_PACKED_STRIP_TICKS \
  TEST_that_process_packed_packet_strip_ticks_flag_works

#define TEST_PROCESS_REPLACE(_field_type) \
  TEST_that_process_packet_replace_##_field_type##_works

#define TEST_PROCESS_PACKED_REPLACE(_field_type) \
  TEST_that_process_packed_packet_replace_##_field_type##_works


/* test data -------------------------------------------------------------- */
static const size_t def_payload_len = 64;
static const uint32_t def_time_s = 1500000000;
static const uint32_t def_time_ns = 999900000;
static const int16_t def_shift_s = 0;
static const bool def_ts_src_mac = false;
static const bool def_invalid = false;
static const int64_t capture_delay_ns = 1000023456;
static const size_t MAX_IOV_LEN = 1920; /* Arbitrary plausible size */
static const size_t MAX_PACKED_SIZE = 64*1024;
static const uint16_t good_ps_ts_flags = SC_PS_FLAG_CLOCK_SET |
                                         SC_PS_FLAG_CLOCK_IN_SYNC;
static struct sc_arista7280_48bit_ts_stats def_stats;
static const struct sc_arista7280_48bit_ts def_dt = {
  .stats = &def_stats,
  .ts_src_mac = false,
  .strip_ticks = false,
  .filter_oui = false
};

#define __TEST_MAX_IOVS 20
struct packet_counts_in_iovs {
  unsigned number_of_iovs;
  uint packet_counts[__TEST_MAX_IOVS];
};

static const struct packet_counts_in_iovs def_pkt_counts = {
    .number_of_iovs = 1,
    .packet_counts = {1}
};


static inline void
populate_arista_ts(struct arista7280_48bit_ts_packed* ts,
                   uint32_t time_s, uint32_t time_ns) {
  ts->sec = htons(time_s & ARISTA7280_48BIT_SECONDS_BITMASK);
  ts->nsec = htonl(time_ns);
}


static inline void
populate_arista_field(uint8_t* buf, uint32_t time_s, uint32_t time_ns,
                      bool ts_src_mac) {
  struct arista7280_48bit_ts_packed* ts;

  if( !ts_src_mac ) {
    struct arista7280_48bit_field_packed* arista;

    arista = (void*)(buf + MAC_ADDRESSES_SIZE);
    arista->ether_type = htons(ARISTA7280_ETHERTYPE);
    arista->sub_type = htons(ARISTA7280_PROTOCOL_SUBTYPE);
    arista->version = htons(ARISTA7280_PROTOCOL_VERSION_48BIT_TAI);
    ts = &arista->ts;
  }
  else {
    struct ether_header* eth = (void *)buf;
    ts = (void *)&eth->ether_shost;
  }

  populate_arista_ts(ts, time_s, time_ns);
}


/* Generate a dummy packet with Arista7280 field.
 * Only fill the fields required for the test.
 */
static struct sc_packet* generate_packet(size_t total_length) {
  struct sc_packet* packet = malloc(sizeof(*packet));
  memset(packet, 0, sizeof(*packet));
  packet->frame_len = total_length;
  size_t iovec_count = total_length/MAX_IOV_LEN;
  if(total_length % MAX_IOV_LEN)
    ++iovec_count;
  packet->iovlen = iovec_count;
  packet->iov = malloc(sizeof(struct iovec)*iovec_count);
  size_t bytes_remaining = total_length;
  int i;
  for( i = 0; i < iovec_count; ++i ) {
    size_t iov_len = bytes_remaining > MAX_IOV_LEN ?
                     MAX_IOV_LEN : bytes_remaining;
    bytes_remaining -= iov_len;
    packet->iov[i].iov_len = iov_len;
    packet->iov[i].iov_base = malloc(iov_len);
  }
  return packet;
}


static struct sc_packet*
generate_arista7280_48bit(size_t payload_length,  uint32_t time_s,
                          uint32_t time_ns, bool ts_src_mac) {
  size_t total_length = payload_length;
  struct sc_packet* packet;

  if( !ts_src_mac )
    total_length += arista7280_48bit_field_size;

  packet = generate_packet(total_length);
  packet->ts_sec = time_s;
  packet->ts_nsec = time_ns;
  populate_arista_field(packet->iov[0].iov_base, time_s, time_ns, ts_src_mac);
  return packet;
}


static void free_packet(struct sc_packet* done) {
  int i;
  for( i = 0; i < done->iovlen; ++i ) {
    free(done->iov[i].iov_base);
  }
  free(done->iov);
  free(done);
}


static struct sc_packet*
generate_packed_stream_arista7280_48bit(
                                size_t payload_len,
                                struct packet_counts_in_iovs pkt_counts,
                                uint32_t time_s, uint32_t time_ns,
                                bool ts_src_mac, uint8_t flags) {
  static const size_t PRE_PAD_SIZE = 19; /* Arbitrary plausible size */
  static const size_t POST_PAD_SIZE = 96; /* Arbitrary plausible size */
  uint64_t capture_ts_ns = (time_s * SC_NS_IN_S) + time_ns + capture_delay_ns;

  struct sc_packet* result = malloc(sizeof(struct sc_packet));
  struct sc_packed_packet* pph;
  memset(result, 0, sizeof(*result));
  result->flags = SC_PACKED_STREAM;
  result->iovlen = pkt_counts.number_of_iovs;
  result->iov = malloc(sizeof(struct iovec) * pkt_counts.number_of_iovs);
  const size_t packet_requirement = sizeof(*pph) + PRE_PAD_SIZE +
                                    payload_len + POST_PAD_SIZE;
  /* In packed stream mode, this field has no sensible meaning. */
  result->frame_len = 0;
  unsigned iovi;
  for( iovi = 0; iovi < pkt_counts.number_of_iovs; ++iovi ) {
    size_t iov_len = packet_requirement * pkt_counts.packet_counts[iovi];
    ck_assert_int_le(iov_len, MAX_PACKED_SIZE);
    result->iov[iovi].iov_len = iov_len;
    result->iov[iovi].iov_base = malloc(iov_len);
    memset(result->iov[iovi].iov_base, 0xde, iov_len);

    int i;
    size_t pph_offset = 0;
    size_t len = payload_len;

    if( !ts_src_mac )
      len += arista7280_48bit_field_size;

    for( i = 0; i < pkt_counts.packet_counts[iovi]; ++i ) {
      pph = result->iov[iovi].iov_base + pph_offset;
      memset(pph, 0, sizeof(*pph));
      pph->ps_next_offset = packet_requirement;
      pph->ps_pkt_start_offset = sizeof(*pph) + PRE_PAD_SIZE;
      pph->ps_orig_len = len;
      pph->ps_cap_len = len;
      pph->ps_ts_sec = capture_ts_ns / SC_NS_IN_S;
      pph->ps_ts_nsec = capture_ts_ns % SC_NS_IN_S;
      pph->ps_flags = flags;
      populate_arista_field(sc_packed_packet_payload(pph),
                            time_s, time_ns, ts_src_mac);
     }
    /* There is no next, as indicated by the fact that
     * the next offset points outside the iovec */
  }
  return result;
}


static struct sc_packet*
generate_packed_stream_arista7280_48bit_def(void) {
  return generate_packed_stream_arista7280_48bit(
                                        def_payload_len, def_pkt_counts,
                                        def_time_s, def_time_ns,
                                        def_ts_src_mac, good_ps_ts_flags);
}

static void
fetch_time_and_check(uint8_t* packet_buffer, uint32_t time_s, uint32_t time_ns,
                     int16_t shift_s, bool ts_src_mac, bool invalid)
{
  uint64_t arista_ns;
  struct sc_arista7280_48bit_ts dt = {
    .stats = &def_stats,
    .ts_src_mac = ts_src_mac,
  };

  ZERO_STRUCT(def_stats);
  node_stub_sc_thread_set_time(time_s + shift_s, time_ns);

  int rc = fetch_arista7280_48bit_time(&dt, packet_buffer, &arista_ns);
  if( invalid ) {
    ck_assert_int_eq(rc, -1);
  }
  else {
    ck_assert_int_eq(rc, 0);
    ck_assert_int_eq(time_s, arista_ns / SC_NS_IN_S);
    ck_assert_int_eq(time_ns, arista_ns % SC_NS_IN_S);
  }
}


static void
generate_fetch_time_and_check(size_t packet_len, uint32_t time_s,
                              uint32_t time_ns, int16_t shift_s,
                              bool ts_src_mac, bool invalid)
{
  struct sc_packet* packet;

  packet = generate_arista7280_48bit(packet_len, time_s, time_ns, ts_src_mac);
  fetch_time_and_check(packet->iov[0].iov_base, time_s, time_ns, shift_s,
                       ts_src_mac, invalid);
  free_packet(packet);
}


static void
generate_packed_fetch_time_and_check(size_t packet_len, uint32_t time_s,
                                     uint32_t time_ns, int16_t shift_s,
                                     bool ts_src_mac, bool invalid)
{
  struct sc_packet* packet;
  struct sc_packed_packet* ps_pkt;
  size_t len = packet_len;

  if( !ts_src_mac )
    len += arista7280_48bit_field_size;

  packet = generate_packed_stream_arista7280_48bit(packet_len, def_pkt_counts,
                                                   time_s, time_ns,
                                                   ts_src_mac,
                                                   good_ps_ts_flags);
  ps_pkt = sc_packet_packed_first(packet);
  ck_assert_int_eq(ps_pkt->ps_orig_len, len);
  ck_assert_int_eq(ps_pkt->ps_cap_len, len);
  fetch_time_and_check(sc_packed_packet_payload(ps_pkt), time_s, time_ns,
                       shift_s, ts_src_mac, invalid);
  free_packet(packet);
}


static void
process_packet_check_ignored(const struct sc_arista7280_48bit_ts* dt,
                             struct sc_packet* packet)
{
  uint32_t time_s = packet->ts_sec;
  uint32_t time_ns = packet->ts_nsec;
  uint16_t flags = packet->flags;
  uint32_t frame_len = packet->frame_len;
  ts_class result = process_single_packet(dt, packet);
  ck_assert_int_eq((int)result, (int)NO_TIMESTAMP);
  ck_assert_int_eq(time_s, packet->ts_sec);
  ck_assert_int_eq(time_ns, packet->ts_nsec);
  ck_assert_int_eq(flags, packet->flags);
  ck_assert_int_eq(frame_len, packet->frame_len);
}


static void
process_packed_packet_check_ignored(const struct sc_arista7280_48bit_ts* dt,
                                    struct sc_packet* packet)
{
  struct sc_packed_packet* ps_pkt = sc_packet_packed_first(packet);
  /* This test only checks the first ps_pkt so require that it be
   * the only ps_pkt.
   */
  struct sc_packed_packet* ps_end = sc_packet_packed_end(packet);
  ck_assert(sc_packed_packet_next(ps_pkt) >= ps_end);
  uint32_t time_s = ps_pkt->ps_ts_sec;
  uint32_t time_ns = ps_pkt->ps_ts_nsec;
  uint16_t flags = ps_pkt->ps_flags;
  uint32_t cap_len = ps_pkt->ps_cap_len;
  uint32_t orig_len = ps_pkt->ps_orig_len;
  process_packed_stream_packet(dt, packet);
  ck_assert_int_eq(time_s, ps_pkt->ps_ts_sec);
  ck_assert_int_eq(time_ns, ps_pkt->ps_ts_nsec);
  ck_assert_int_eq(flags, ps_pkt->ps_flags);
  ck_assert_int_eq(cap_len, ps_pkt->ps_cap_len);
  ck_assert_int_eq(orig_len, ps_pkt->ps_orig_len);
}


static void process_packed_packet_check_flagged_bad(
    const struct sc_arista7280_48bit_ts* dt, struct sc_packet* packet)
{
  struct sc_packed_packet* ps_pkt = sc_packet_packed_first(packet);
  /* This test only checks the first ps_pkt so require that it be
   * the only ps_pkt.
   */
  struct sc_packed_packet* ps_end = sc_packet_packed_end(packet);
  ck_assert(sc_packed_packet_next(ps_pkt) >= ps_end);
  uint32_t time_s = ps_pkt->ps_ts_sec;
  uint32_t time_ns = ps_pkt->ps_ts_nsec;
  uint16_t flags = ps_pkt->ps_flags & ~good_ps_ts_flags;
  uint32_t cap_len = ps_pkt->ps_cap_len;
  uint32_t orig_len = ps_pkt->ps_orig_len;
  process_packed_stream_packet(dt, packet);
  ck_assert_int_eq(time_s, ps_pkt->ps_ts_sec);
  ck_assert_int_eq(time_ns, ps_pkt->ps_ts_nsec);
  ck_assert_int_eq(flags, ps_pkt->ps_flags);
  ck_assert_int_eq(cap_len, ps_pkt->ps_cap_len);
  ck_assert_int_eq(orig_len, ps_pkt->ps_orig_len);
}


/* tests ------------------------------------------------------------------ */

/* fetch_arista7280_48bit_time() tests for packed and non-packed packets ---*/

#define CTS_TEST TEST_FETCH_ARISTA_TS(correct_time, synced)
START_TEST(CTS_TEST) {
  generate_fetch_time_and_check(def_payload_len, def_time_s, def_time_ns,
                                def_shift_s, def_ts_src_mac, def_invalid);
}
END_TEST

#define CTM_TEST TEST_FETCH_ARISTA_TS(correct_time, max_behind)
START_TEST(CTM_TEST) {
  static const int16_t shift_s = -(ARISTA7280_48BIT_SECONDS_BITMASK >> 1);

  generate_fetch_time_and_check(def_payload_len, def_time_s, def_time_ns,
                                shift_s, def_ts_src_mac, def_invalid);
}
END_TEST

#define CTMA_TEST TEST_FETCH_ARISTA_TS(correct_time, max_ahead)
START_TEST(CTMA_TEST) {
  static const int16_t shift_s = ARISTA7280_48BIT_SECONDS_BITMASK >> 1;

  generate_fetch_time_and_check(def_payload_len, def_time_s, def_time_ns,
                                shift_s, def_ts_src_mac, def_invalid);
}
END_TEST

#define CTRD_TEST TEST_FETCH_ARISTA_TS(correct_time, rollover_down)
START_TEST(CTRD_TEST) {
  static const int16_t shift_s = -1;
  static const uint32_t time_s = 0x12340000;

  generate_fetch_time_and_check(def_payload_len, time_s, def_time_ns,
                                shift_s, def_ts_src_mac, def_invalid);
  ck_assert_int_eq(def_stats.n_rollover, 1);
}
END_TEST

#define CTRU_TEST TEST_FETCH_ARISTA_TS(correct_time, rollover_up)
START_TEST(CTRU_TEST) {
  static const int16_t shift_s = 1;
  static const uint32_t time_s = 0x1234FFFF;

  generate_fetch_time_and_check(def_payload_len, time_s, def_time_ns,
                                shift_s, def_ts_src_mac, def_invalid);
  ck_assert_int_eq(def_stats.n_rollover, 1);
}
END_TEST


#define CTSM_TEST TEST_FETCH_ARISTA_TS(correct_time, src_mac)
START_TEST(CTSM_TEST) {
  static const bool ts_src_mac = true;

  generate_fetch_time_and_check(def_payload_len, def_time_s, def_time_ns,
                                def_shift_s, ts_src_mac, def_invalid);
}
END_TEST

#define EI_TEST TEST_FETCH_ARISTA_TS(error, invalid)
START_TEST(EI_TEST) {
  static const uint32_t time_ns = 3287091583;
  static const bool invalid = true;

  generate_fetch_time_and_check(def_payload_len, def_time_s, time_ns,
                                def_shift_s, def_ts_src_mac, invalid);
}
END_TEST

#define CTST_TEST TEST_FETCH_ARISTA_TS_PACKED(correct_time, synced)
START_TEST(CTST_TEST) {
  generate_packed_fetch_time_and_check(def_payload_len, def_time_s,
                                       def_time_ns, def_shift_s,
                                       def_ts_src_mac, def_invalid);
}
END_TEST

#define CTMB_TEST TEST_FETCH_ARISTA_TS_PACKED(correct_time, max_behind)
START_TEST(CTMB_TEST) {
  static const int16_t shift_s = -(ARISTA7280_48BIT_SECONDS_BITMASK >> 1);

  generate_packed_fetch_time_and_check(def_payload_len, def_time_s,
                                       def_time_ns, shift_s,
                                       def_ts_src_mac, def_invalid);
}
END_TEST

#define CTME_TEST TEST_FETCH_ARISTA_TS_PACKED(correct_time, max_ahead)
START_TEST(CTME_TEST) {
  static const int16_t shift_s = ARISTA7280_48BIT_SECONDS_BITMASK >> 1;

  generate_packed_fetch_time_and_check(def_payload_len, def_time_s,
                                       def_time_ns, shift_s,
                                       def_ts_src_mac, def_invalid);
}
END_TEST

#define CPRD_TEST TEST_FETCH_ARISTA_TS_PACKED(correct_time, rollover_down)
START_TEST(CPRD_TEST) {
  static const int16_t shift_s = -1;
  static const uint32_t time_s = 0x12340000;

  generate_packed_fetch_time_and_check(def_payload_len, time_s,
                                       def_time_ns, shift_s,
                                       def_ts_src_mac, def_invalid);
  ck_assert_int_eq(def_stats.n_rollover, 1);
}
END_TEST

#define CPRU_TEST TEST_FETCH_ARISTA_TS_PACKED(correct_time, rollover_up)
START_TEST(CPRU_TEST) {
  static const int16_t shift_s = 1;
  static const uint32_t time_s = 0x1234FFFF;

  generate_packed_fetch_time_and_check(def_payload_len, time_s,
                                       def_time_ns, shift_s,
                                       def_ts_src_mac, def_invalid);
  ck_assert_int_eq(def_stats.n_rollover, 1);
}
END_TEST

#define CPSM_TEST TEST_FETCH_ARISTA_TS_PACKED(correct_time, src_mac)
START_TEST(CPSM_TEST) {
  static const bool ts_src_mac = true;

  generate_packed_fetch_time_and_check(def_payload_len, def_time_s,
                                       def_time_ns, def_shift_s,
                                       ts_src_mac, def_invalid);
}
END_TEST

#define CPI_TEST TEST_FETCH_ARISTA_TS_PACKED(error, invalid)
START_TEST(CPI_TEST) {
  static const uint32_t time_ns = 3287091583;
  static const bool invalid = true;

  generate_packed_fetch_time_and_check(def_payload_len, def_time_s,
                                       time_ns, def_shift_s,
                                       def_ts_src_mac, invalid);
}
END_TEST


/* strip_arista7280 function tests for packed and non-packed packets --------*/
#define TS_TEST TEST_STRIP_TICKS(single)
START_TEST(TS_TEST) {
  struct sc_packet* packet;

  packet = generate_arista7280_48bit(def_payload_len, def_time_s, def_time_ns,
                                     def_ts_src_mac);
  /* Check arista field is there before removal */
  ck_assert_int_eq(def_payload_len + arista7280_48bit_field_size,
                   packet->frame_len);
  ck_assert_int_eq(def_payload_len + arista7280_48bit_field_size,
                   packet->iov[0].iov_len);

  /* Get expected packet after strip */
  uint8_t *expected = malloc(def_payload_len);
  memcpy(expected, packet->iov[0].iov_base, MAC_ADDRESSES_SIZE);
  memcpy(expected + MAC_ADDRESSES_SIZE,
         packet->iov[0].iov_base + MAC_ADDRESSES_SIZE +
            arista7280_48bit_field_size,
         def_payload_len - MAC_ADDRESSES_SIZE);
  pkt_strip_arista7280_48bit(packet);

  /* Check that packet now matches expectation */
  ck_assert_int_eq(def_payload_len, packet->frame_len);
  ck_assert_int_eq(def_payload_len, packet->iov[0].iov_len);
  int i;
  for( i = 0; i < def_payload_len; ++i ) {
    ck_assert_int_eq(((uint8_t*)packet->iov[0].iov_base)[i], expected[i]);
  }
  free(expected);
  free_packet(packet);
}
END_TEST

#define TP_TEST TEST_STRIP_TICKS(packed)
START_TEST(TP_TEST) {
  struct sc_packet* packet;
  struct sc_packed_packet* ps_pkt;

  packet = generate_packed_stream_arista7280_48bit_def();
  ps_pkt = sc_packet_packed_first(packet);
  /* Check arista field is there before removal */
  ck_assert_int_eq(def_payload_len + arista7280_48bit_field_size,
                   ps_pkt->ps_orig_len);
  ck_assert_int_eq(def_payload_len + arista7280_48bit_field_size,
                   ps_pkt->ps_cap_len);

  /* Get expected packet after strip */
  uint8_t *expected = malloc(def_payload_len);
  uint8_t* ps_pkt_start = sc_packed_packet_payload(ps_pkt);
  memcpy(expected, ps_pkt_start, MAC_ADDRESSES_SIZE);
  memcpy(expected + MAC_ADDRESSES_SIZE,
         ps_pkt_start + MAC_ADDRESSES_SIZE +
            arista7280_48bit_field_size,
         def_payload_len - MAC_ADDRESSES_SIZE);
  ps_pkt_strip_arista7280_48bit(ps_pkt);

  /* Check that packet now matches expectation */
  ck_assert_int_eq(def_payload_len, ps_pkt->ps_orig_len);
  ck_assert_int_eq(def_payload_len, ps_pkt->ps_cap_len);
  ps_pkt_start = sc_packed_packet_payload(ps_pkt);
  int i;
  for( i = 0; i < def_payload_len; ++i ) {
    ck_assert_int_eq(ps_pkt_start[i], expected[i]);
  }
  free(expected);
  free_packet(packet);
}
END_TEST


/* process_single_packet tests for non-packed packets -------------*/

START_TEST(TEST_PROCESS_STRIP_TICKS) {
  struct sc_packet* packet;
  struct sc_arista7280_48bit_ts dt = def_dt;

  packet = generate_arista7280_48bit(def_payload_len, def_time_s, def_time_ns,
                                     def_ts_src_mac);
  process_single_packet(&dt, packet);
  ck_assert_int_eq(packet->frame_len,
                   def_payload_len + arista7280_48bit_field_size);
  ck_assert_int_eq(packet->iov[0].iov_len,
                   def_payload_len + arista7280_48bit_field_size);
  dt.strip_ticks = true;
  process_single_packet(&dt, packet);
  ck_assert_int_eq(packet->frame_len, def_payload_len);
  ck_assert_int_eq(packet->iov[0].iov_len, def_payload_len);
  free_packet(packet);
}
END_TEST

#define IL_TEST TEST_PROCESS_IGNORE(lldp)
START_TEST(IL_TEST) {
  struct sc_packet* packet = generate_packet(def_payload_len);
  struct ether_header* eth = packet->iov[0].iov_base;

  ZERO_STRUCT(def_stats);
  packet->ts_sec = def_time_s;
  packet->ts_nsec = def_time_ns;
  eth->ether_type = htons(ETHERTYPE_LLDP);
  process_packet_check_ignored(&def_dt, packet);
  free_packet(packet);
  ck_assert_int_eq(def_dt.stats->n_filtered_other, 1);
}
END_TEST

#define IO_TEST TEST_PROCESS_IGNORE(oui)
START_TEST(IO_TEST) {
  struct sc_packet* packet = generate_packet(def_payload_len);
  struct ether_header* eth = packet->iov[0].iov_base;
  struct sc_arista7280_48bit_ts dt = def_dt;

  ZERO_STRUCT(def_stats);
  dt.filter_oui = true;
  dt.no_ts_oui[0] = 0x10;
  dt.no_ts_oui[1] = 0x11;
  dt.no_ts_oui[2] = 0x12;
  packet->ts_sec = def_time_s;
  packet->ts_nsec = def_time_ns;
  eth->ether_type = htons(SC_ETHERTYPE_8021Q);
  eth->ether_shost[0] = dt.no_ts_oui[0];
  eth->ether_shost[1] = dt.no_ts_oui[1];
  eth->ether_shost[2] = dt.no_ts_oui[2];
  process_packet_check_ignored(&dt, packet);
  free_packet(packet);
  ck_assert_int_eq(dt.stats->n_filtered_oui, 1);
}
END_TEST

#define IB_TEST TEST_PROCESS_IGNORE(bad_crc)
START_TEST(IB_TEST) {
  struct sc_packet* packet = generate_packet(def_payload_len);
  struct ether_header* eth = packet->iov[0].iov_base;

  ZERO_STRUCT(def_stats);
  packet->ts_sec = def_time_s;
  packet->ts_nsec = def_time_ns;
  packet->flags = SC_CRC_ERROR;
  eth->ether_type = htons(ARISTA7280_ETHERTYPE);
  process_packet_check_ignored(&def_dt, packet);
  free_packet(packet);
  ck_assert_int_eq(def_dt.stats->n_filtered_other, 1);
}
END_TEST

#define IN_TEST TEST_PROCESS_IGNORE(non_arista7280)
START_TEST(IN_TEST) {
  struct sc_packet* packet = generate_packet(def_payload_len);
  struct ether_header* eth = packet->iov[0].iov_base;

  ZERO_STRUCT(def_stats);
  packet->ts_sec = def_time_s;
  packet->ts_nsec = def_time_ns;
  eth->ether_type = htons(SC_ETHERTYPE_8021Q);
  process_packet_check_ignored(&def_dt, packet);
  free_packet(packet);
  ck_assert_int_eq(def_dt.stats->n_filtered_arista, 1);
}
END_TEST

#define IA_TEST TEST_PROCESS_IGNORE(arista7280_64bit)
START_TEST(IA_TEST) {
  struct sc_packet* packet = generate_packet(def_payload_len);
  struct ether_header* eth = packet->iov[0].iov_base;
  struct arista7280_48bit_field_packed* arista;
  uint8_t *buf = packet->iov[0].iov_base;

  ZERO_STRUCT(def_stats);
  populate_arista_field(buf, 0, 0, def_dt.ts_src_mac);
  arista = (void*)(buf + MAC_ADDRESSES_SIZE);
  arista->version = htons(ARISTA7280_PROTOCOL_VERSION_64BIT_TAI);
  packet->ts_sec = def_time_s;
  packet->ts_nsec = def_time_ns;
  process_packet_check_ignored(&def_dt, packet);
  free_packet(packet);
  ck_assert_int_eq(def_dt.stats->n_filtered_arista, 1);
}
END_TEST

#define DA_TEST TEST_PROCESS_DECODE(arista7280_48bit)
START_TEST(DA_TEST) {
  struct sc_packet* packet;

  node_stub_sc_thread_set_time(def_time_s, def_time_ns);
  packet = generate_arista7280_48bit(def_payload_len, def_time_s, def_time_ns,
                                     def_ts_src_mac);
  ts_class result = process_single_packet(&def_dt, packet);
  ck_assert_int_eq((int)result, (int)GOOD_PACKET);
  ck_assert_int_eq(packet->ts_sec, def_time_s);
  ck_assert_int_eq(packet->ts_nsec, def_time_ns);
  free_packet(packet);
}
END_TEST

#define DT_TEST TEST_PROCESS_DECODE(ts_src_mac)
START_TEST(DT_TEST) {
  struct sc_packet* packet;
  struct sc_arista7280_48bit_ts dt = def_dt;

  dt.ts_src_mac = true,
  node_stub_sc_thread_set_time(def_time_s, def_time_ns);
  packet = generate_arista7280_48bit(def_payload_len, def_time_s, def_time_ns,
                                     dt.ts_src_mac);
  ts_class result = process_single_packet(&dt, packet);
  ck_assert_int_eq((int)result, (int)GOOD_PACKET);
  ck_assert_int_eq(packet->ts_sec, def_time_s);
  ck_assert_int_eq(packet->ts_nsec, def_time_ns);
  free_packet(packet);
}
END_TEST

#define RSM_TEST TEST_PROCESS_REPLACE(src_mac)
START_TEST(RSM_TEST) {
  static const size_t payload_len = 64;
  static const uint32_t time_s = 0x12345678;
  static const uint32_t time_ns = 0x12345678;
  struct sc_packet* packet;
  struct ether_header* eth;
  struct sc_arista7280_48bit_ts dt = {
    .stats = &def_stats,
    .ts_src_mac = true,
    .strip_ticks = false,
    .filter_oui = false,
    .replace_src_mac = true,
    .new_src_mac = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
  };

  packet = generate_arista7280_48bit(payload_len, time_s, time_ns, true);
  process_single_packet(&dt, packet);
  eth = packet->iov[0].iov_base;

  int i;
  for( i = 0; i < 6; ++i ) {
    ck_assert_uint_eq(eth->ether_shost[i], dt.new_src_mac[i]);
  }
  ck_assert_int_eq(packet->frame_len, payload_len);
  ck_assert_int_eq(packet->iov[0].iov_len, payload_len);
  free_packet(packet);
}
END_TEST


/* process_packed_stream_packet tests for packed packets -------------*/

START_TEST(TEST_PROCESS_PACKED_STRIP_TICKS) {
  struct sc_packet* packet;
  struct sc_packed_packet* ps_pkt;
  struct sc_arista7280_48bit_ts dt = def_dt;

  dt.strip_ticks = true;
  node_stub_sc_thread_set_time(def_time_s, def_time_ns);
  packet = generate_packed_stream_arista7280_48bit_def();
  ps_pkt = sc_packet_packed_first(packet);
  process_packed_stream_packet(&dt, packet);
  ck_assert_int_eq(def_payload_len, ps_pkt->ps_orig_len);
  ck_assert_int_eq(def_payload_len, ps_pkt->ps_cap_len);
  free_packet(packet);
}
END_TEST

#define PILL_TEST TEST_PROCESS_PACKED_IGNORE(lldp)
START_TEST(PILL_TEST) {
  struct sc_packet* packet;
  struct sc_packed_packet* ps_pkt;
  struct ether_header* eth;

  ZERO_STRUCT(def_stats);
  packet = generate_packed_stream_arista7280_48bit_def();
  ps_pkt = sc_packet_packed_first(packet);
  eth = sc_packed_packet_payload(ps_pkt);

  /* This will leave a mess after the ethertype but
   * the process function shouldn't care.
   */
  eth->ether_type = htons(ETHERTYPE_LLDP);
  process_packed_packet_check_ignored(&def_dt, packet);
  free_packet(packet);
  ck_assert_int_eq(def_dt.stats->n_filtered_other, 1);
}
END_TEST

#define PIOU_TEST TEST_PROCESS_PACKED_IGNORE(oui)
START_TEST(PIOU_TEST) {
  struct sc_packet* packet;
  struct sc_packed_packet* ps_pkt;
  struct ether_header* eth;
  struct sc_arista7280_48bit_ts dt = def_dt;

  ZERO_STRUCT(def_stats);
  dt.filter_oui = true;
  dt.no_ts_oui[0] = 0x10;
  dt.no_ts_oui[1] = 0x11;
  dt.no_ts_oui[2] = 0x12;
  packet = generate_packed_stream_arista7280_48bit_def();
  ps_pkt = sc_packet_packed_first(packet);
  eth = sc_packed_packet_payload(ps_pkt);

  /* This will leave a mess after the ethertype but
   * the process function shouldn't care.
   */
  eth->ether_type = htons(SC_ETHERTYPE_8021Q);
  eth->ether_shost[0] = dt.no_ts_oui[0];
  eth->ether_shost[1] = dt.no_ts_oui[1];
  eth->ether_shost[2] = dt.no_ts_oui[2];
  process_packed_packet_check_ignored(&dt, packet);
  free_packet(packet);
  ck_assert_int_eq(dt.stats->n_filtered_oui, 1);
}
END_TEST

#define PFBC_TEST TEST_PROCESS_PACKED_FLAG(bad_crc)
START_TEST(PFBC_TEST) {
  struct sc_packet* packet;
  struct sc_packed_packet* ps_pkt;

  ZERO_STRUCT(def_stats);
  packet = generate_packed_stream_arista7280_48bit_def();
  ps_pkt = sc_packet_packed_first(packet);
  ps_pkt->ps_flags |= SC_PS_FLAG_BAD_FCS;
  process_packed_packet_check_flagged_bad(&def_dt, packet);
  free_packet(packet);
  ck_assert_int_eq(def_dt.stats->n_filtered_other, 1);
}
END_TEST

#define PFNA_TEST TEST_PROCESS_PACKED_FLAG(non_arista7280)
START_TEST(PFNA_TEST) {
  struct sc_packet* packet;
  struct sc_packed_packet* ps_pkt;
  struct ether_header* eth;

  ZERO_STRUCT(def_stats);
  packet = generate_packed_stream_arista7280_48bit_def();
  ps_pkt = sc_packet_packed_first(packet);
  eth = sc_packed_packet_payload(ps_pkt);

  /* This will leave a mess after the ethertype but
   * the process function shouldn't care.
   */
  eth->ether_type = htons(SC_ETHERTYPE_8021Q);
  process_packed_packet_check_flagged_bad(&def_dt, packet);
  free_packet(packet);
  ck_assert_int_eq(def_dt.stats->n_filtered_arista, 1);
}
END_TEST

#define PFAS_TEST TEST_PROCESS_PACKED_FLAG(arista7280_64bit)
START_TEST(PFAS_TEST) {
  struct sc_packet* packet;
  struct sc_packed_packet* ps_pkt;
  struct arista7280_48bit_field_packed* arista;
  uint8_t *buf;

  ZERO_STRUCT(def_stats);
  packet = generate_packed_stream_arista7280_48bit_def();
  ps_pkt = sc_packet_packed_first(packet);
  buf = sc_packed_packet_payload(ps_pkt);
  populate_arista_field(buf, 0, 0, def_dt.ts_src_mac);
  arista = (void*)(buf + MAC_ADDRESSES_SIZE);
  arista->version = htons(ARISTA7280_PROTOCOL_VERSION_64BIT_TAI);
  process_packed_packet_check_flagged_bad(&def_dt, packet);
  free_packet(packet);
  ck_assert_int_eq(def_dt.stats->n_filtered_arista, 1);
}
END_TEST

#define PDAF_TEST TEST_PROCESS_PACKED_DECODE(arista7280_48bit)
START_TEST(PDAF_TEST) {
  struct sc_packet* packet;
  struct sc_packed_packet* ps_pkt;

  node_stub_sc_thread_set_time(def_time_s, def_time_ns);
  packet = generate_packed_stream_arista7280_48bit_def();
  ps_pkt = sc_packet_packed_first(packet);
  process_packed_stream_packet(&def_dt, packet);
  ck_assert_int_eq(ps_pkt->ps_ts_sec, def_time_s);
  ck_assert_int_eq(ps_pkt->ps_ts_nsec, def_time_ns);
  ck_assert_int_eq(ps_pkt->ps_flags, good_ps_ts_flags);
  free_packet(packet);
}
END_TEST

#define PDTS_TEST TEST_PROCESS_PACKED_DECODE(ts_src_mac)
START_TEST(PDTS_TEST) {
  struct sc_packet* packet;
  struct sc_packed_packet* ps_pkt;
  struct sc_arista7280_48bit_ts dt = def_dt;

  dt.ts_src_mac = true;
  node_stub_sc_thread_set_time(def_time_s, def_time_ns);
  packet = generate_packed_stream_arista7280_48bit(
                                        def_payload_len, def_pkt_counts,
                                        def_time_s, def_time_ns,
                                        dt.ts_src_mac, good_ps_ts_flags);
  ps_pkt = sc_packet_packed_first(packet);
  process_packed_stream_packet(&dt, packet);
  ck_assert_int_eq(ps_pkt->ps_ts_sec, def_time_s);
  ck_assert_int_eq(ps_pkt->ps_ts_nsec, def_time_ns);
  ck_assert_int_eq(ps_pkt->ps_flags, good_ps_ts_flags);
  free_packet(packet);
}
END_TEST

#define PRSM_TEST TEST_PROCESS_PACKED_REPLACE(src_mac)
START_TEST(PRSM_TEST) {
  static const size_t payload_len = 64;
  static const uint32_t time_s = 0x12345678;
  static const uint32_t time_ns = 0x12345678;
  struct sc_packet* packet;
  struct sc_packed_packet* ps_pkt;
  struct ether_header* eth;
  struct sc_arista7280_48bit_ts dt = {
    .stats = &def_stats,
    .ts_src_mac = true,
    .strip_ticks = false,
    .filter_oui = false,
    .replace_src_mac = true,
    .new_src_mac = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
  };
  struct packet_counts_in_iovs pkt_counts = {
    .number_of_iovs = 1,
    .packet_counts = {1}
  };

  packet = generate_packed_stream_arista7280_48bit(payload_len, pkt_counts,
                                                   time_s, time_ns, true,
                                                   good_ps_ts_flags);
  ps_pkt = sc_packet_packed_first(packet);
  process_packed_stream_packet(&dt, packet);
  eth = sc_packed_packet_payload(ps_pkt);

  int i;
  for( i = 0; i < 6; ++i ) {
    ck_assert_uint_eq(eth->ether_shost[i], dt.new_src_mac[i]);
  }
  ck_assert_int_eq(payload_len, ps_pkt->ps_orig_len);
  ck_assert_int_eq(payload_len, ps_pkt->ps_cap_len);
  ck_assert_int_eq(ps_pkt->ps_flags, good_ps_ts_flags);
  free_packet(packet);
}
END_TEST

/* set up and run --------------------------------------------------------- */

int main(int argc, const char *argv[]) {
  int number_failed;
  Suite *s = suite_create("sc_arista7280_48bit_ts");

  TCase *tc_field = tcase_create("Arista7280 48bit Timestamp Field Functions");
  tcase_add_test(tc_field, TEST_FETCH_ARISTA_TS(correct_time, synced));
  tcase_add_test(tc_field, TEST_FETCH_ARISTA_TS(correct_time, max_behind));
  tcase_add_test(tc_field, TEST_FETCH_ARISTA_TS(correct_time, max_ahead));
  tcase_add_test(tc_field, TEST_FETCH_ARISTA_TS(correct_time, rollover_down));
  tcase_add_test(tc_field, TEST_FETCH_ARISTA_TS(correct_time, rollover_up));
  tcase_add_test(tc_field, TEST_FETCH_ARISTA_TS(correct_time, src_mac));
  tcase_add_test(tc_field, TEST_FETCH_ARISTA_TS(error, invalid));

  tcase_add_test(tc_field, TEST_FETCH_ARISTA_TS_PACKED(correct_time, synced));
  tcase_add_test(tc_field, TEST_FETCH_ARISTA_TS_PACKED(correct_time,
                                                       max_behind));
  tcase_add_test(tc_field, TEST_FETCH_ARISTA_TS_PACKED(correct_time,
                                                       max_ahead));
  tcase_add_test(tc_field, TEST_FETCH_ARISTA_TS_PACKED(correct_time,
                                                       rollover_down));
  tcase_add_test(tc_field, TEST_FETCH_ARISTA_TS_PACKED(correct_time,
                                                       rollover_up));
  tcase_add_test(tc_field, TEST_FETCH_ARISTA_TS_PACKED(correct_time,
                                                       src_mac));
  tcase_add_test(tc_field, TEST_FETCH_ARISTA_TS_PACKED(error, invalid));

  tcase_add_test(tc_field, TEST_STRIP_TICKS(single));
  tcase_add_test(tc_field, TEST_STRIP_TICKS(packed));
  suite_add_tcase(s, tc_field);

  TCase *tc_packet = tcase_create("Arista7280 48bit Timestamp sc_packet");
  tcase_add_test(tc_packet, TEST_PROCESS_STRIP_TICKS);
  tcase_add_test(tc_packet, TEST_PROCESS_IGNORE(lldp));
  tcase_add_test(tc_packet, TEST_PROCESS_IGNORE(oui));
  tcase_add_test(tc_packet, TEST_PROCESS_IGNORE(bad_crc));
  tcase_add_test(tc_packet, TEST_PROCESS_IGNORE(non_arista7280));
  tcase_add_test(tc_packet, TEST_PROCESS_IGNORE(arista7280_64bit));
  tcase_add_test(tc_packet, TEST_PROCESS_DECODE(arista7280_48bit));
  tcase_add_test(tc_packet, TEST_PROCESS_DECODE(ts_src_mac));
  tcase_add_test(tc_packet, TEST_PROCESS_REPLACE(src_mac));
  suite_add_tcase(s, tc_packet);

  TCase *tc_packed_packet =
    tcase_create("Arista7280 48bit Timestamp sc_packed_packet");
  tcase_add_test(tc_packed_packet, TEST_PROCESS_PACKED_STRIP_TICKS);
  tcase_add_test(tc_packed_packet, TEST_PROCESS_PACKED_IGNORE(lldp));
  tcase_add_test(tc_packed_packet, TEST_PROCESS_PACKED_IGNORE(oui));
  tcase_add_test(tc_packed_packet, TEST_PROCESS_PACKED_FLAG(bad_crc));
  tcase_add_test(tc_packed_packet, TEST_PROCESS_PACKED_FLAG(non_arista7280));
  tcase_add_test(tc_packed_packet, TEST_PROCESS_PACKED_FLAG(arista7280_64bit));
  tcase_add_test(tc_packed_packet,
                 TEST_PROCESS_PACKED_DECODE(arista7280_48bit));
  tcase_add_test(tc_packed_packet, TEST_PROCESS_PACKED_DECODE(ts_src_mac));
  tcase_add_test(tc_packed_packet, TEST_PROCESS_PACKED_REPLACE(src_mac));
  suite_add_tcase(s, tc_packed_packet);

  SRunner *sr = srunner_create(s);
  const char *progname;
  char logfile[512];

  progname = strrchr(argv[0], '/');
  if (progname) {
    progname++;
  } else {
    progname = argv[0];
  }
  snprintf(logfile, sizeof(logfile), "%s.out", progname);

  srunner_set_log(sr, logfile);
  srunner_run_all(sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);

  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}


