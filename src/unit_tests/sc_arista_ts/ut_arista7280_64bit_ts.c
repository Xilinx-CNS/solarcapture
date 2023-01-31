/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/*
 * ut_arista7280_64bit_ts.c
 *
 *  Created on: 22 May 2015
 *      Author: ld
 */

#include "solar_capture/ext_packet.h"

#include <bits/uio.h>
#include <check.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Include C directly so that we can test static functions */
#include "../../components/sc_arista7280_64bit_ts.c"

#define ETHERTYPE_VLAN 0x8100

/* test data -------------------------------------------------------------- */

static const int64_t capture_delay_ns = 1000023456;
static const uint32_t switch_latency_ns = 100000;
static const size_t MAX_IOV_LEN = 1920; /* Arbitrary plausible size */
static const size_t MAX_PACKED_SIZE = 64*1024;
static const uint16_t good_ps_ts_flags = SC_PS_FLAG_CLOCK_SET | SC_PS_FLAG_CLOCK_IN_SYNC;

static inline void populate_arista(struct arista7280_64bit_field_packed* arista,
                                   uint32_t time_s,
                                   uint32_t time_ns) {
  arista->ether_type = htons(ARISTA7280_ETHERTYPE);
  arista->sub_type = htons(ARISTA7280_PROTOCOL_SUBTYPE);
  arista->version = htons(ARISTA7280_PROTOCOL_VERSION_64BIT_TAI);
  uint32_t ingress_mask = ARISTA7280_64BIT_INGRESS_ROLLOVER - 1;
  uint32_t ingress_sec = ingress_mask & time_s;
  uint32_t egress_sec = ~ingress_mask & (time_s + ((time_ns + switch_latency_ns) / SC_NS_IN_S));
  arista->sec = htonl(ingress_sec + egress_sec);
  arista->nsec = htonl(time_ns);
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
  for(i = 0; i < iovec_count; ++i) {
    size_t iov_len = (bytes_remaining > MAX_IOV_LEN) ? MAX_IOV_LEN : bytes_remaining;
    bytes_remaining -= iov_len;
    packet->iov[i].iov_len = iov_len;
    packet->iov[i].iov_base = malloc(iov_len);
  }
  return packet;
}

static struct sc_packet* generate_arista7280_64bit(size_t payload_length,
                                             uint32_t time_s,
                                             uint32_t time_ns) {
  size_t total_length = payload_length + arista7280_64bit_field_size;
  struct sc_packet* packet = generate_packet(total_length);

  /* set the per packet fields */
  uint64_t capture_ts_ns = (time_s * SC_NS_IN_S) + time_ns + capture_delay_ns;
  packet->ts_sec = capture_ts_ns / SC_NS_IN_S;
  packet->ts_nsec = capture_ts_ns % SC_NS_IN_S;
  /* fill in the arista7280 field */
  struct arista7280_64bit_field_packed* arista = (void*)((uint8_t*)packet->iov[0].iov_base + MAC_ADDRESSES_SIZE);
  populate_arista(arista, time_s, time_ns);

  return packet;
}

static void free_packet(struct sc_packet* done) {
  int i;
  for(i = 0; i < done->iovlen; ++i) {
    free(done->iov[i].iov_base);
  }
  free(done->iov);
  free(done);
}


#define __TEST_MAX_IOVS 20
struct packet_counts_in_iovs {
  unsigned number_of_iovs;
  uint packet_counts[__TEST_MAX_IOVS];
};

/* payload_len includes arista field */
static struct sc_packet* generate_packed_stream_arista7280_64bit(size_t payload_len,
                                                           const struct packet_counts_in_iovs pkt_counts,
                                                           uint32_t time_s,
                                                           uint32_t time_ns,
                                                           uint8_t flags) {
  static const size_t PRE_PAD_SIZE = 19; /* Arbitrary plausible size */
  static const size_t POST_PAD_SIZE = 96; /* Arbitrary plausible size, must be >= arista7280_64bit_field_size */
  uint64_t capture_ts_ns = (time_s * SC_NS_IN_S) + time_ns + capture_delay_ns;

  struct sc_packet* result = malloc(sizeof(struct sc_packet));
  struct sc_packed_packet* pph;
  memset(result, 0, sizeof(*result));
  result->flags = SC_PACKED_STREAM;
  result->iovlen = pkt_counts.number_of_iovs;
  result->iov = malloc(sizeof(struct iovec) * pkt_counts.number_of_iovs);
  const size_t packet_requirement = sizeof(*pph) + PRE_PAD_SIZE + payload_len
      + POST_PAD_SIZE;
  /* In packed stream mode, this field has no sensible meaning. */
  result->frame_len = 0;
  unsigned iovi;
  for(iovi = 0; iovi < pkt_counts.number_of_iovs; ++iovi) {
    size_t iov_len = packet_requirement * pkt_counts.packet_counts[iovi];
    ck_assert_int_le(iov_len, MAX_PACKED_SIZE);
    result->iov[iovi].iov_len = iov_len;
    result->iov[iovi].iov_base = malloc(iov_len);
    memset(result->iov[iovi].iov_base, 0xde, iov_len);

    int i;
    size_t pph_offset = 0;
    for(i = 0; i < pkt_counts.packet_counts[iovi]; ++i) {
      pph = result->iov[iovi].iov_base + pph_offset;
      memset(pph, 0, sizeof(*pph));
      pph->ps_next_offset = packet_requirement;
      pph->ps_pkt_start_offset = sizeof(*pph) + PRE_PAD_SIZE;
      pph->ps_orig_len = payload_len + arista7280_64bit_field_size;
      pph->ps_cap_len = payload_len + arista7280_64bit_field_size;
      pph->ps_ts_sec = capture_ts_ns / SC_NS_IN_S;
      pph->ps_ts_nsec = capture_ts_ns % SC_NS_IN_S;
      pph->ps_flags = flags;

      struct arista7280_64bit_field_packed* arista = (void*)((uint8_t*)sc_packed_packet_payload(pph) + MAC_ADDRESSES_SIZE);
      populate_arista(arista, time_s, time_ns);
    }
    /* There is no next, as indicated by the fact that
     * the next offset points outside the iovec */
  }
  return result;
}

static void fetch_time_and_check(uint8_t* packet_buffer,
                                 const uint32_t time_s,
                                 const uint32_t time_ns,
                                 const bool rollover,
                                 const bool invalid)
{
  uint64_t arista_ns;
  int rc = fetch_arista7280_64bit_time(packet_buffer, &arista_ns);
  if( invalid ) {
    ck_assert_int_eq(rc, -1);
  }
  else {
    ck_assert_int_eq(rc, 0);
    if ( rollover ) {
      ck_assert_int_eq(time_s + ARISTA7280_64BIT_INGRESS_ROLLOVER, arista_ns / SC_NS_IN_S);
    }
    else {
      ck_assert_int_eq(time_s, arista_ns / SC_NS_IN_S);
    }
    ck_assert_int_eq(time_ns, arista_ns % SC_NS_IN_S);
  }
}

static void generate_fetch_time_and_check(const size_t packet_len,
                                          const uint32_t time_s,
                                          const uint32_t time_ns,
                                          const bool rollover,
                                          const bool invalid)
{
  struct sc_packet* packet = generate_arista7280_64bit(packet_len, time_s, time_ns);
  fetch_time_and_check(packet->iov[0].iov_base, time_s, time_ns, rollover, invalid);
  free_packet(packet);
}

static void generate_packed_fetch_time_and_check(const size_t packet_len,
                                                 const uint32_t time_s,
                                                 const uint32_t time_ns,
                                                 const bool rollover,
                                                 const bool invalid)
{
  struct packet_counts_in_iovs pkt_counts = {.number_of_iovs = 1, .packet_counts = {1}};
  struct sc_packet* packet = generate_packed_stream_arista7280_64bit(packet_len, pkt_counts, time_s, time_ns, good_ps_ts_flags);
  struct sc_packed_packet* ps_pkt = sc_packet_packed_first(packet);
  ck_assert_int_eq(ps_pkt->ps_orig_len, packet_len + arista7280_64bit_field_size);
  ck_assert_int_eq(ps_pkt->ps_cap_len, packet_len + arista7280_64bit_field_size);
  fetch_time_and_check(sc_packed_packet_payload(ps_pkt), time_s, time_ns, rollover, invalid);
  free_packet(packet);
}

static void process_packet_check_ignored(const struct sc_arista7280_64bit_ts* bt, struct sc_packet* packet)
{
  uint32_t time_s = packet->ts_sec;
  uint32_t time_ns = packet->ts_nsec;
  uint16_t flags = packet->flags;
  uint32_t frame_len = packet->frame_len;
  ts_class result = process_single_packet(bt, packet);
  ck_assert_int_eq((int)result, (int)NO_TIMESTAMP);
  ck_assert_int_eq(time_s, packet->ts_sec);
  ck_assert_int_eq(time_ns, packet->ts_nsec);
  ck_assert_int_eq(flags, packet->flags);
  ck_assert_int_eq(frame_len, packet->frame_len);
}

static void process_packed_packet_check_ignored(const struct sc_arista7280_64bit_ts* bt, struct sc_packet* packet)
{
  struct sc_packed_packet* ps_pkt = sc_packet_packed_first(packet);
  /* This test only checks the first ps_pkt so require that it be the only ps_pkt */
  struct sc_packed_packet* ps_end = sc_packet_packed_end(packet);
  ck_assert(sc_packed_packet_next(ps_pkt) >= ps_end);
  uint32_t time_s = ps_pkt->ps_ts_sec;
  uint32_t time_ns = ps_pkt->ps_ts_nsec;
  uint16_t flags = ps_pkt->ps_flags;
  uint32_t cap_len = ps_pkt->ps_cap_len;
  uint32_t orig_len = ps_pkt->ps_orig_len;
  process_packed_stream_packet(bt, packet);
  ck_assert_int_eq(time_s, ps_pkt->ps_ts_sec);
  ck_assert_int_eq(time_ns, ps_pkt->ps_ts_nsec);
  ck_assert_int_eq(flags, ps_pkt->ps_flags);
  ck_assert_int_eq(cap_len, ps_pkt->ps_cap_len);
  ck_assert_int_eq(orig_len, ps_pkt->ps_orig_len);
}

static void process_packed_packet_check_flagged_bad(const struct sc_arista7280_64bit_ts* bt, struct sc_packet* packet)
{
  struct sc_packed_packet* ps_pkt = sc_packet_packed_first(packet);
  /* This test only checks the first ps_pkt so require that it be the only ps_pkt */
  struct sc_packed_packet* ps_end = sc_packet_packed_end(packet);
  ck_assert(sc_packed_packet_next(ps_pkt) >= ps_end);
  uint32_t time_s = ps_pkt->ps_ts_sec;
  uint32_t time_ns = ps_pkt->ps_ts_nsec;
  uint16_t flags = ps_pkt->ps_flags & ~good_ps_ts_flags;
  uint32_t cap_len = ps_pkt->ps_cap_len;
  uint32_t orig_len = ps_pkt->ps_orig_len;
  process_packed_stream_packet(bt, packet);
  ck_assert_int_eq(time_s, ps_pkt->ps_ts_sec);
  ck_assert_int_eq(time_ns, ps_pkt->ps_ts_nsec);
  ck_assert_int_eq(flags, ps_pkt->ps_flags);
  ck_assert_int_eq(cap_len, ps_pkt->ps_cap_len);
  ck_assert_int_eq(orig_len, ps_pkt->ps_orig_len);
}

/* tests ------------------------------------------------------------------ */

/* fetch_arista7280_64bit_time() tests for packed and non-packed packets -------------*/

START_TEST(TEST_that_given_a_non_rollover_packet_with_arista7280_64bit_timestamp_fetch_arista7280_64bit_time_returns_correct_time) {
  static const size_t payload_len = 64;
  static const uint32_t time_s = 1500000000;
  static const uint32_t time_ns = 999900000;
  generate_fetch_time_and_check(payload_len, time_s, time_ns, false, false);
}
END_TEST

START_TEST(TEST_that_given_a_rollover_packet_with_arista7280_64bit_timestamp_fetch_arista7280_64bit_time_returns_correct_time) {
  static const size_t payload_len = 64;
  static const uint32_t time_s = 1499999999;
  static const uint32_t time_ns = 999900000;
  generate_fetch_time_and_check(payload_len, time_s, time_ns, true, false);
}
END_TEST

START_TEST(TEST_that_given_a_packet_with_invalid_arista7280_64bit_timestamp_fetch_arista7280_64bit_time_returns_error) {
  static const size_t payload_len = 64;
  static const uint32_t time_s = 1499999999;
  static const uint32_t time_ns = 3287091583;
  generate_fetch_time_and_check(payload_len, time_s, time_ns, false, true);
}
END_TEST

START_TEST(TEST_that_given_a_non_rollover_packed_packet_with_arista7280_64bit_timestamp_fetch_arista7280_64bit_time_returns_correct_time) {
  static const size_t payload_len = 64;
  static const uint32_t time_s = 1500000000;
  static const uint32_t time_ns = 999900000;
  generate_packed_fetch_time_and_check(payload_len, time_s, time_ns, false, false);
}
END_TEST

START_TEST(TEST_that_given_a_rollover_packed_packet_with_arista7280_64bit_timestamp_fetch_arista7280_64bit_time_returns_correct_time) {
  static const size_t payload_len = 64;
  static const uint32_t time_s = 1499999999;
  static const uint32_t time_ns = 999900000;
  generate_packed_fetch_time_and_check(payload_len, time_s, time_ns, true, false);
}
END_TEST

START_TEST(TEST_that_given_a_packed_packet_with_invalid_arista7280_64bit_timestamp_fetch_arista7280_64bit_time_returns_error) {
  static const size_t payload_len = 64;
  static const uint32_t time_s = 1499999999;
  static const uint32_t time_ns = 3287091583;
  generate_packed_fetch_time_and_check(payload_len, time_s, time_ns, false, true);
}
END_TEST

/* strip_arista7280 function tests for packed and non-packed packets ----------*/

START_TEST(TEST_strip_timestamp_removes_field_from_single_packet) {
  static const size_t payload_len = 64;
  static const uint32_t time_s = 1499999999;
  static const uint32_t time_ns = 999900000;
  struct sc_packet* packet = generate_arista7280_64bit(payload_len, time_s, time_ns);
  /* Check arista field is there before removal */
  ck_assert_int_eq(payload_len + arista7280_64bit_field_size, packet->frame_len);
  ck_assert_int_eq(payload_len + arista7280_64bit_field_size, packet->iov[0].iov_len);
  /* Get expected packet after strip */
  uint8_t *expected = malloc(payload_len);
  memcpy(expected, packet->iov[0].iov_base, MAC_ADDRESSES_SIZE);
  memcpy(expected + MAC_ADDRESSES_SIZE, packet->iov[0].iov_base + MAC_ADDRESSES_SIZE + arista7280_64bit_field_size,
         payload_len - MAC_ADDRESSES_SIZE);
  pkt_strip_arista7280_64bit(packet);
  /* Check that packet now matches expectation */
  ck_assert_int_eq(payload_len, packet->frame_len);
  ck_assert_int_eq(payload_len, packet->iov[0].iov_len);
  int i;
  for( i = 0; i < payload_len; ++i ) {
    ck_assert_int_eq(((uint8_t*)packet->iov[0].iov_base)[i], expected[i]);
  }
  free(expected);
  free_packet(packet);
}
END_TEST

START_TEST(TEST_strip_timestamp_removes_field_from_packed_packet) {
  static const size_t payload_len = 64;
  static const uint32_t time_s = 1499999999;
  static const uint32_t time_ns = 999900000;
  struct packet_counts_in_iovs pkt_counts = {.number_of_iovs = 1, .packet_counts = {1}};
  struct sc_packet* packet = generate_packed_stream_arista7280_64bit(payload_len, pkt_counts, time_s, time_ns, good_ps_ts_flags);
  struct sc_packed_packet* ps_pkt = sc_packet_packed_first(packet);
  /* Check arista field is there before removal */
  ck_assert_int_eq(payload_len + arista7280_64bit_field_size, ps_pkt->ps_orig_len);
  ck_assert_int_eq(payload_len + arista7280_64bit_field_size, ps_pkt->ps_cap_len);
  /* Get expected packet after strip */
  uint8_t *expected = malloc(payload_len);
  uint8_t* ps_pkt_start = sc_packed_packet_payload(ps_pkt);
  memcpy(expected, ps_pkt_start, MAC_ADDRESSES_SIZE);
  memcpy(expected + MAC_ADDRESSES_SIZE, ps_pkt_start + MAC_ADDRESSES_SIZE + arista7280_64bit_field_size,
         payload_len - MAC_ADDRESSES_SIZE);
  ps_pkt_strip_arista7280_64bit(ps_pkt);
  /* Check that packet now matches expectation */
  ck_assert_int_eq(payload_len, ps_pkt->ps_orig_len);
  ck_assert_int_eq(payload_len, ps_pkt->ps_cap_len);
  ps_pkt_start = sc_packed_packet_payload(ps_pkt);
  int i;
  for( i = 0; i < payload_len; ++i ) {
    ck_assert_int_eq(ps_pkt_start[i], expected[i]);
  }
  free(expected);
  free_packet(packet);
}
END_TEST

/* process_single_packet tests for non-packed packets -------------*/

START_TEST(TEST_that_process_packet_strip_ticks_flag_works) {
  static const size_t payload_len = 64;
  static const uint32_t time_s = 1500000000;
  static const uint32_t time_ns = 999900000;
  int64_t last_good_delta_ns = INT64_MAX;
  struct sc_arista7280_64bit_ts bt = {.strip_ticks=false,
                                .rollover_window_ns=SC_NS_IN_S,
                                .filter_oui=false,
                                .last_good_delta_ns=&last_good_delta_ns};
  struct sc_packet* packet = generate_arista7280_64bit(payload_len, time_s, time_ns);
  process_single_packet(&bt, packet);
  ck_assert_int_eq(packet->frame_len, payload_len + arista7280_64bit_field_size);
  ck_assert_int_eq(packet->iov[0].iov_len, payload_len + arista7280_64bit_field_size);
  bt.strip_ticks = true;
  process_single_packet(&bt, packet);
  ck_assert_int_eq(packet->frame_len, payload_len);
  ck_assert_int_eq(packet->iov[0].iov_len, payload_len);
  free_packet(packet);
}
END_TEST

START_TEST(TEST_that_process_packet_ignores_lldp_packets) {
  static const size_t payload_len = 64;
  int64_t last_good_delta_ns = INT64_MAX;
  struct sc_arista7280_64bit_ts bt = {.strip_ticks=false,
                            .rollover_window_ns=SC_NS_IN_S,
                            .filter_oui=false,
                            .last_good_delta_ns=&last_good_delta_ns};
  struct sc_packet* packet = generate_packet(payload_len);
  struct ether_header* eth = packet->iov[0].iov_base;
  packet->ts_sec = 1500000000;
  packet->ts_nsec = 999900000;
  eth->ether_type = htons(ETHERTYPE_LLDP);
  process_packet_check_ignored(&bt, packet);
  free_packet(packet);
}
END_TEST

START_TEST(TEST_that_process_packet_ignores_oui_packets) {
  static const size_t payload_len = 64;
  int64_t last_good_delta_ns = INT64_MAX;
  struct sc_arista7280_64bit_ts bt = {.strip_ticks=false,
                            .rollover_window_ns=SC_NS_IN_S,
                            .filter_oui=true,
                            .no_ts_oui={0x10, 0x11, 0x12},
                            .last_good_delta_ns=&last_good_delta_ns};
  struct sc_packet* packet = generate_packet(payload_len);
  struct ether_header* eth = packet->iov[0].iov_base;
  packet->ts_sec = 1500000000;
  packet->ts_nsec = 999900000;
  eth->ether_type = htons(ETHERTYPE_VLAN);
  eth->ether_shost[0] = bt.no_ts_oui[0];
  eth->ether_shost[1] = bt.no_ts_oui[1];
  eth->ether_shost[2] = bt.no_ts_oui[2];
  process_packet_check_ignored(&bt, packet);
  free_packet(packet);
}
END_TEST

START_TEST(TEST_that_process_packet_ignores_bad_crc_packets) {
  static const size_t payload_len = 64;
  int64_t last_good_delta_ns = INT64_MAX;
  struct sc_arista7280_64bit_ts bt = {.strip_ticks=false,
                            .rollover_window_ns=SC_NS_IN_S,
                            .filter_oui=false,
                            .last_good_delta_ns=&last_good_delta_ns};
  struct sc_packet* packet = generate_packet(payload_len);
  struct ether_header* eth = packet->iov[0].iov_base;
  packet->ts_sec = 1500000000;
  packet->ts_nsec = 999900000;
  packet->flags = SC_CRC_ERROR;
  eth->ether_type = htons(ARISTA7280_ETHERTYPE);
  process_packet_check_ignored(&bt, packet);
  free_packet(packet);
}
END_TEST

START_TEST(TEST_that_process_packet_ignores_non_arista7280_packets) {
  static const size_t payload_len = 64;
  int64_t last_good_delta_ns = INT64_MAX;
  struct sc_arista7280_64bit_ts bt = {.strip_ticks=false,
                            .rollover_window_ns=SC_NS_IN_S,
                            .filter_oui=false,
                            .last_good_delta_ns=&last_good_delta_ns};
  struct sc_packet* packet = generate_packet(payload_len);
  struct ether_header* eth = packet->iov[0].iov_base;
  packet->ts_sec = 1500000000;
  packet->ts_nsec = 999900000;
  eth->ether_type = htons(ETHERTYPE_VLAN);
  process_packet_check_ignored(&bt, packet);
  free_packet(packet);
}
END_TEST

START_TEST(TEST_that_process_packet_decodes_non_rollover_packets) {
  static const size_t payload_len = 64;
  static const uint32_t time_s = 1500000000;
  static const uint32_t time_ns = 999900000;
  int64_t last_good_delta_ns = INT64_MAX;
  struct sc_arista7280_64bit_ts bt = {.strip_ticks=false,
                            .rollover_window_ns=SC_NS_IN_S,
                            .filter_oui=false,
                            .last_good_delta_ns=&last_good_delta_ns};
  struct sc_packet* packet = generate_arista7280_64bit(payload_len, time_s, time_ns);
  ts_class result = process_single_packet(&bt, packet);
  ck_assert_int_eq((int)result, (int)GOOD_PACKET);
  ck_assert_int_eq(packet->ts_sec, time_s);
  ck_assert_int_eq(packet->ts_nsec, time_ns);
  ck_assert_int_eq(last_good_delta_ns, capture_delay_ns);
  free_packet(packet);
}
END_TEST

START_TEST(TEST_that_process_packet_decodes_rollover_packets_with_last_delta) {
  static const size_t payload_len = 64;
  static const uint32_t time_s = 1499999999;
  static const uint32_t time_ns = 999900000;
  int64_t last_good_delta_ns = capture_delay_ns;
  struct sc_arista7280_64bit_ts bt = {.strip_ticks=false,
                            .rollover_window_ns=SC_NS_IN_S,
                            .filter_oui=false,
                            .last_good_delta_ns=&last_good_delta_ns};
  struct sc_packet* packet = generate_arista7280_64bit(payload_len, time_s, time_ns);
  ts_class result = process_single_packet(&bt, packet);
  ck_assert_int_eq((int)result, (int)GOOD_PACKET);
  ck_assert_int_eq(packet->ts_sec, time_s);
  ck_assert_int_eq(packet->ts_nsec, time_ns);
  free_packet(packet);
}
END_TEST

START_TEST(TEST_that_process_packet_decodes_rollover_packets_with_no_last_delta) {
  static const size_t payload_len = 64;
  static const uint32_t time_s = 1499999999;
  static const uint32_t time_ns = 999900000;
  int64_t last_good_delta_ns = INT64_MAX;
  struct sc_arista7280_64bit_ts bt = {.strip_ticks=false,
                            .rollover_window_ns=SC_NS_IN_S,
                            .filter_oui=false,
                            .last_good_delta_ns=&last_good_delta_ns};
  struct sc_packet* packet = generate_arista7280_64bit(payload_len, time_s, time_ns);
  ts_class result = process_single_packet(&bt, packet);
  ck_assert_int_eq((int)result, (int)GOOD_PACKET);
  ck_assert_int_eq(packet->ts_sec, time_s + ARISTA7280_64BIT_INGRESS_ROLLOVER);
  ck_assert_int_eq(packet->ts_nsec, time_ns);
  free_packet(packet);
}
END_TEST


/* process_packed_stream_packet tests for packed packets -------------*/

START_TEST(TEST_that_process_packed_packet_ignores_lldp_packets) {
  static const size_t payload_len = 64;
  static const uint32_t time_s = 1499999999;
  static const uint32_t time_ns = 999900000;
  int64_t last_good_delta_ns = INT64_MAX;
  struct sc_arista7280_64bit_ts bt = {.strip_ticks=false,
                            .rollover_window_ns=SC_NS_IN_S,
                            .filter_oui=false,
                            .last_good_delta_ns=&last_good_delta_ns};
  struct packet_counts_in_iovs pkt_counts = {.number_of_iovs = 1, .packet_counts = {1}};
  struct sc_packet* packet = generate_packed_stream_arista7280_64bit(payload_len, pkt_counts, time_s, time_ns, good_ps_ts_flags);
  struct sc_packed_packet* ps_pkt = sc_packet_packed_first(packet);
  struct ether_header* eth = sc_packed_packet_payload(ps_pkt);
  eth->ether_type = htobe16(ETHERTYPE_LLDP);  /* This will leave a mess after the ethertype but the process function shouldn't care */
  process_packed_packet_check_ignored(&bt, packet);
  free_packet(packet);
}
END_TEST

START_TEST(TEST_that_process_packed_packet_ignores_oui_packets) {
  static const size_t payload_len = 64;
  static const uint32_t time_s = 1499999999;
  static const uint32_t time_ns = 999900000;
  int64_t last_good_delta_ns = INT64_MAX;
  struct sc_arista7280_64bit_ts bt = {.strip_ticks=false,
                            .rollover_window_ns=SC_NS_IN_S,
                            .filter_oui=true,
                            .no_ts_oui={0x10, 0x11, 0x12},
                            .last_good_delta_ns=&last_good_delta_ns};
  struct packet_counts_in_iovs pkt_counts = {.number_of_iovs = 1, .packet_counts = {1}};
  struct sc_packet* packet = generate_packed_stream_arista7280_64bit(payload_len, pkt_counts, time_s, time_ns, good_ps_ts_flags);
  struct sc_packed_packet* ps_pkt = sc_packet_packed_first(packet);
  struct ether_header* eth = sc_packed_packet_payload(ps_pkt);
  eth->ether_type = htons(ETHERTYPE_VLAN);  /* This will leave a mess after the ethertype but the process function shouldn't care */
  eth->ether_shost[0] = bt.no_ts_oui[0];
  eth->ether_shost[1] = bt.no_ts_oui[1];
  eth->ether_shost[2] = bt.no_ts_oui[2];
  process_packed_packet_check_ignored(&bt, packet);
  free_packet(packet);
}
END_TEST

START_TEST(TEST_that_process_packed_packet_flags_bad_crc_packets) {
  static const size_t payload_len = 64;
  static const uint32_t time_s = 1499999999;
  static const uint32_t time_ns = 999900000;
  int64_t last_good_delta_ns = INT64_MAX;
  struct sc_arista7280_64bit_ts bt = {.strip_ticks=false,
                            .rollover_window_ns=SC_NS_IN_S,
                            .filter_oui=false,
                            .last_good_delta_ns=&last_good_delta_ns};
  struct packet_counts_in_iovs pkt_counts = {.number_of_iovs = 1, .packet_counts = {1}};
  struct sc_packet* packet = generate_packed_stream_arista7280_64bit(payload_len, pkt_counts, time_s, time_ns, good_ps_ts_flags);
  struct sc_packed_packet* ps_pkt = sc_packet_packed_first(packet);
  ps_pkt->ps_flags |= SC_PS_FLAG_BAD_FCS;
  process_packed_packet_check_flagged_bad(&bt, packet);
  free_packet(packet);
}
END_TEST

START_TEST(TEST_that_process_packed_packet_flags_non_arista7280_packets) {
  static const size_t payload_len = 64;
  static const uint32_t time_s = 1499999999;
  static const uint32_t time_ns = 999900000;
  int64_t last_good_delta_ns = INT64_MAX;
  struct sc_arista7280_64bit_ts bt = {.strip_ticks=false,
                            .rollover_window_ns=SC_NS_IN_S,
                            .filter_oui=false,
                            .last_good_delta_ns=&last_good_delta_ns};
  struct packet_counts_in_iovs pkt_counts = {.number_of_iovs = 1, .packet_counts = {1}};
  struct sc_packet* packet = generate_packed_stream_arista7280_64bit(payload_len, pkt_counts, time_s, time_ns, good_ps_ts_flags);
  struct sc_packed_packet* ps_pkt = sc_packet_packed_first(packet);
  struct ether_header* eth = sc_packed_packet_payload(ps_pkt);
  eth->ether_type = htobe16(ETHERTYPE_VLAN);  /* This will leave a mess after the ethertype but the process function shouldn't care */
  process_packed_packet_check_flagged_bad(&bt, packet);
  free_packet(packet);
}
END_TEST

START_TEST(TEST_that_process_packed_packet_decodes_non_rollover_packets) {
  static const size_t payload_len = 64;
  static const uint32_t time_s = 1500000000;
  static const uint32_t time_ns = 999900000;
  int64_t last_good_delta_ns = INT64_MAX;
  struct sc_arista7280_64bit_ts bt = {.strip_ticks=false,
                            .rollover_window_ns=SC_NS_IN_S,
                            .filter_oui=false,
                            .last_good_delta_ns=&last_good_delta_ns};
  struct packet_counts_in_iovs pkt_counts = {.number_of_iovs = 1, .packet_counts = {1}};
  struct sc_packet* packet = generate_packed_stream_arista7280_64bit(payload_len, pkt_counts, time_s, time_ns, good_ps_ts_flags);
  struct sc_packed_packet* ps_pkt = sc_packet_packed_first(packet);
  process_packed_stream_packet(&bt, packet);
  ck_assert_int_eq(ps_pkt->ps_ts_sec, time_s);
  ck_assert_int_eq(ps_pkt->ps_ts_nsec, time_ns);
  ck_assert_int_eq(ps_pkt->ps_flags, good_ps_ts_flags);
  ck_assert_int_eq(last_good_delta_ns, capture_delay_ns);
  free_packet(packet);
}
END_TEST

START_TEST(TEST_that_process_packed_packet_decodes_rollover_packets_with_last_delta) {
  static const size_t payload_len = 64;
  static const uint32_t time_s = 1499999999;
  static const uint32_t time_ns = 999900000;
  int64_t last_good_delta_ns = capture_delay_ns;
  struct sc_arista7280_64bit_ts bt = {.strip_ticks=false,
                            .rollover_window_ns=SC_NS_IN_S,
                            .filter_oui=false,
                            .last_good_delta_ns=&last_good_delta_ns};
  struct packet_counts_in_iovs pkt_counts = {.number_of_iovs = 1, .packet_counts = {1}};
  struct sc_packet* packet = generate_packed_stream_arista7280_64bit(payload_len, pkt_counts, time_s, time_ns, good_ps_ts_flags);
  struct sc_packed_packet* ps_pkt = sc_packet_packed_first(packet);
  process_packed_stream_packet(&bt, packet);
  ck_assert_int_eq(ps_pkt->ps_ts_sec, time_s);
  ck_assert_int_eq(ps_pkt->ps_ts_nsec, time_ns);
  ck_assert_int_eq(ps_pkt->ps_flags, good_ps_ts_flags);
  free_packet(packet);
}
END_TEST

START_TEST(TEST_that_process_packed_packet_decodes_rollover_packets_with_no_last_delta) {
  static const size_t payload_len = 64;
  static const uint32_t time_s = 1499999999;
  static const uint32_t time_ns = 999900000;
  int64_t last_good_delta_ns = INT64_MAX;
  struct sc_arista7280_64bit_ts bt = {.strip_ticks=false,
                            .rollover_window_ns=SC_NS_IN_S,
                            .filter_oui=false,
                            .last_good_delta_ns=&last_good_delta_ns};
  struct packet_counts_in_iovs pkt_counts = {.number_of_iovs = 1, .packet_counts = {1}};
  struct sc_packet* packet = generate_packed_stream_arista7280_64bit(payload_len, pkt_counts, time_s, time_ns, good_ps_ts_flags);
  struct sc_packed_packet* ps_pkt = sc_packet_packed_first(packet);
  process_packed_stream_packet(&bt, packet);
  ck_assert_int_eq(ps_pkt->ps_ts_sec, time_s + ARISTA7280_64BIT_INGRESS_ROLLOVER);
  ck_assert_int_eq(ps_pkt->ps_ts_nsec, time_ns);
  ck_assert_int_eq(ps_pkt->ps_flags, good_ps_ts_flags);
  free_packet(packet);
}
END_TEST

/* template - less typing
START_TEST(TEST_that_) {

}
END_TEST

*/

/* set up and run --------------------------------------------------------- */

int main(int argc, const char *argv[]) {
  int number_failed;
  Suite *s = suite_create("sc_arista7280_64bit_ts");
  TCase *tc_field = tcase_create("Arista7280 64bit Timestamp Field Functions");
  tcase_add_test(tc_field,
                 TEST_that_given_a_non_rollover_packet_with_arista7280_64bit_timestamp_fetch_arista7280_64bit_time_returns_correct_time);
  tcase_add_test(tc_field,
                 TEST_that_given_a_rollover_packet_with_arista7280_64bit_timestamp_fetch_arista7280_64bit_time_returns_correct_time);
  tcase_add_test(tc_field,
                 TEST_that_given_a_packet_with_invalid_arista7280_64bit_timestamp_fetch_arista7280_64bit_time_returns_error);
  tcase_add_test(tc_field,
                 TEST_that_given_a_non_rollover_packed_packet_with_arista7280_64bit_timestamp_fetch_arista7280_64bit_time_returns_correct_time);
  tcase_add_test(tc_field,
                 TEST_that_given_a_rollover_packed_packet_with_arista7280_64bit_timestamp_fetch_arista7280_64bit_time_returns_correct_time);
  tcase_add_test(tc_field,
                 TEST_that_given_a_packed_packet_with_invalid_arista7280_64bit_timestamp_fetch_arista7280_64bit_time_returns_error);
  tcase_add_test(tc_field,
                 TEST_strip_timestamp_removes_field_from_single_packet);
  tcase_add_test(tc_field,
                 TEST_strip_timestamp_removes_field_from_packed_packet);
  suite_add_tcase(s, tc_field);

  TCase *tc_packet = tcase_create("Arista7280 64bit sc_packet");
  tcase_add_test(tc_packet,
                 TEST_that_process_packet_ignores_lldp_packets);
  tcase_add_test(tc_packet,
                 TEST_that_process_packet_ignores_oui_packets);
  tcase_add_test(tc_packet,
                 TEST_that_process_packet_ignores_bad_crc_packets);
  tcase_add_test(tc_packet,
                 TEST_that_process_packet_ignores_non_arista7280_packets);
  tcase_add_test(tc_packet,
                 TEST_that_process_packet_decodes_non_rollover_packets);
  tcase_add_test(tc_packet,
                 TEST_that_process_packet_decodes_rollover_packets_with_last_delta);
  tcase_add_test(tc_packet,
                 TEST_that_process_packet_decodes_rollover_packets_with_no_last_delta);
  suite_add_tcase(s, tc_packet);


  TCase *tc_packed_packet = tcase_create("Arista7280 64bit sc_packed_packet");
  tcase_add_test(tc_packed_packet,
                 TEST_that_process_packed_packet_ignores_lldp_packets);
  tcase_add_test(tc_packed_packet,
                 TEST_that_process_packed_packet_ignores_oui_packets);
  tcase_add_test(tc_packed_packet,
                 TEST_that_process_packed_packet_flags_bad_crc_packets);
  tcase_add_test(tc_packed_packet,
                 TEST_that_process_packed_packet_flags_non_arista7280_packets);
  tcase_add_test(tc_packed_packet,
                 TEST_that_process_packed_packet_decodes_non_rollover_packets);
  tcase_add_test(tc_packed_packet,
                 TEST_that_process_packed_packet_decodes_rollover_packets_with_last_delta);
  tcase_add_test(tc_packed_packet,
                 TEST_that_process_packed_packet_decodes_rollover_packets_with_no_last_delta);
  suite_add_tcase(s, tc_packed_packet);

  /* template - less typing
  tcase_add_test(tc_node,
                 );
  */

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
