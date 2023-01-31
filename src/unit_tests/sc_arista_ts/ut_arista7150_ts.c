/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/*
 * ut_sc_arista7150_ts.c
 *
 *  Created on: 2016-03-09
 *      Author: ld
 */

#include <check.h>

/* Include C directly so that we can test static functions */
#include "../../components/sc_arista7150_ts.c"

/* test data -------------------------------------------------------------- */

static const double default_ns_per_tick = 10.0;

/* test helpers ----------------------------------------------------------- */

static struct arista7150_ts* generate_struct_arista7150_ts() {
  struct arista7150_ts* st = malloc(sizeof(*st));
  memset(st, 0, sizeof(*st));

  st->kf_ip_proto = 253;
  arista_ts_log_level_from_str("verbose", &st->log_level);
  st->filter_oui = 0;
  st->kf_ip_dest = 1;
  st->no_sync_drop = 0;
  st->kf_device = -1;
  st->strip_ticks = 1;
  st->has_fcs = 0;
  st->lost_sync_gap = 10000 * 1000000ULL;
  st->no_sync_gap = 60000 * 1000000ULL;
  st->exp_tick_freq = 350000000;
  st->max_freq_error = 20000 / 1e6;
  st->max_host_t_delta_ns =
    (double)MAX_HOST_T_DELTA_TICKS * NS_PER_SEC / st->exp_tick_freq;
  st->state = ST_NO_SYNC;
  st->tick_freq = 100000ULL;
  st->ns_per_tick = default_ns_per_tick;
  st->stats = malloc(sizeof(*st->stats));
  st->stats->max_host_t_delta = st->max_host_t_delta_ns;
  st->stats->max_freq_error = st->max_freq_error;
  st->stats->lost_sync_ms = st->lost_sync_gap / 1000000ULL;
  st->stats->no_sync_ms = st->no_sync_gap / 1000000ULL;
  st->stats->exp_tick_freq = st->exp_tick_freq;
  st->stats->strip_ticks = st->strip_ticks;
  st->stats->log_level = st->log_level;

  return st;
}

static void free_struct_arista7150_ts(struct arista7150_ts* st) {
  free(st->stats);
  free(st);
}

static const uint32_t capture_delay_s = 1;
static const uint32_t capture_delay_ns = 23456;
static const size_t MAX_IOV_LEN = 1920; /* Arbitrary plausible size */
static const size_t MAX_PACKED_SIZE = 64*1024;

/* Generate a dummy packet with arista ticks.
 * Only fill the fields required for the test.
 */
static struct sc_packet* generate_arista_packet(size_t payload_length,
                             uint32_t time_s,
                             uint32_t time_ns,
                             int has_fcs) {
  struct sc_packet* result = malloc(sizeof(struct sc_packet));
  memset(result, 0, sizeof(*result));
  /* set the per packet fields */
  result->ts_sec = time_s + capture_delay_s;
  result->ts_nsec = time_ns + capture_delay_ns;
  if(result->ts_nsec > 1000000000) {
    result->ts_nsec -= 1000000000;
    result->ts_sec++;
  }
  size_t footer_length = (TICK_BYTES + has_fcs ? FCS_BYTES : 0);
  size_t total_length = payload_length + footer_length;
  result->frame_len = total_length;
  /* init the iovecs */
  size_t iovec_count = total_length/MAX_IOV_LEN;
  if(total_length % MAX_IOV_LEN)
    ++iovec_count;
  result->iovlen = iovec_count;
  result->iov = malloc(sizeof(struct iovec)*iovec_count);
  size_t bytes_remaining = total_length;
  int i;
  for(i = 0; i < iovec_count; ++i) {
    size_t iov_len = (bytes_remaining > MAX_IOV_LEN) ? MAX_IOV_LEN : bytes_remaining;
    bytes_remaining -= iov_len;
    result->iov[i].iov_len = iov_len;
    result->iov[i].iov_base = malloc(iov_len);
  }
  size_t last_len = result->iov[result->iovlen - 1].iov_len;
  void* last_base = result->iov[result->iovlen - 1].iov_base;
  *((uint32_t*) (last_base + last_len - (TICK_BYTES + has_fcs ? FCS_BYTES : 0))) = (uint32_t)
      time_ns / (int) default_ns_per_tick;
  return result;
}

static void free_packet(struct sc_packet* done) {
  int i;
  for(i = 0; i < done->iovlen; ++i) {
    free(done->iov[i].iov_base);
  }
  free(done->iov);
  free(done);
}

static const uint32_t TIME_PER_PACKET = 1983; /* Arbitrary plausible inter-packet time. */

/* payload_len includes CPacket footer */
static struct sc_packet* generate_packed_stream_arista_packets(size_t payload_len,
                                                        const uint number_of_packets,
                                                        uint32_t time_s,
                                                        uint32_t time_ns,
                                                        int has_fcs) {
  static const size_t PRE_PAD_SIZE = 19; /* Arbitrary plausible size */
  static const size_t POST_PAD_SIZE = 96; /* Arbitrary plausible size */
  struct sc_packet* result = malloc(sizeof(struct sc_packet));
  struct sc_packed_packet* pph;
  memset(result, 0, sizeof(*result));
  result->flags = SC_PACKED_STREAM;
  result->iovlen = 1;
  result->iov = malloc(sizeof(struct iovec));
  const size_t packet_requirement = sizeof(*pph) + PRE_PAD_SIZE + payload_len
      + POST_PAD_SIZE;
  size_t iov_len = packet_requirement * number_of_packets;
  result->frame_len = iov_len;
  ck_assert_int_le(iov_len, MAX_PACKED_SIZE);
  result->iov[0].iov_len = iov_len;
  result->iov[0].iov_base = malloc(iov_len);
  memset(result->iov[0].iov_base, 0xde, iov_len);

  int i;
  size_t pph_offset = 0;
  for(i = 0; i < number_of_packets; ++i) {
    pph = result->iov[0].iov_base + pph_offset;
    memset(pph, 0, sizeof(*pph));
    pph->ps_next_offset = packet_requirement;
    pph->ps_pkt_start_offset = sizeof(*pph) + PRE_PAD_SIZE;
    pph->ps_orig_len = payload_len;
    pph->ps_cap_len = payload_len;

    uint32_t* ticks = sc_packed_packet_payload(pph)
        + pph->ps_cap_len
        - (TICK_BYTES + has_fcs ? FCS_BYTES : 0);
    *ticks = time_ns / default_ns_per_tick + i * TIME_PER_PACKET;

    pph_offset += packet_requirement;
  }
  /* There is no next, as indicated by the fact that
   * the next offset points outside the iovec */
  return result;
}


/* tests ------------------------------------------------------------------ */

/* Test that timestamp is read correctly and packet is stripped appropriately
 * Test that keyframes are not altered (especially, ticks aren't stripped).
 * with:
 *  packed stream | has_fcs | strip_ticks
 *  --------------+---------+------------
 *        N       |    N    |     N
 *        N       |    Y    |     N
 *        N       |    N    |     Y
 *        Y       |    N    |     N
 *        Y       |    Y    |     N
 *        Y       |    N    |     Y
 *        X       |    Y    |     Y error
 *
 *  Packed Stream TS parsing handled by arista7150_ts_pkt().
 *  (unpacked) Packet TS parsing handled by arista7150_ts_ps_buf().
 *  keep_fcs and strip_ticks are options stored in the struct arista7150_ts.
 */

START_TEST(TEST_that_given_has_fcs_false_and_strip_ticks_false_arista7150_ts_pkt_adjust_only_reads_time) {
  size_t payload_len = 247;
  uint32_t time_s = 0;
  uint32_t time_ns = 34567;
  int has_fcs = 0;
  /* init arista7150_ts */
  struct arista7150_ts *st = generate_struct_arista7150_ts();
  uint32_t ticks = time_ns / st->ns_per_tick;
  /* create packet */
  struct sc_packet *p1 = generate_arista_packet(
      payload_len,
      time_s,
      time_ns,
      has_fcs
  );
  ck_assert_int_eq(time_s + capture_delay_s, p1->ts_sec);
  ck_assert_int_eq(time_ns + capture_delay_ns, p1->ts_nsec);
  /* dup packet */
  struct sc_packet *golden = generate_arista_packet(
      payload_len,
      time_s,
      time_ns,
      has_fcs
  );
  /* call function */
  arista7150_ts_pkt_adjust(st, /* pkt_host_ts_ns*/ 0, p1);
  /* assert packet time updated correctly */
  ck_assert_int_eq(time_s, p1->ts_sec);
  ck_assert_int_eq(time_ns, p1->ts_nsec);
  /* assert packet copy still same as original */
  ck_assert_int_eq(golden->iov[0].iov_len, p1->iov[0].iov_len);
  ck_assert_int_eq(
      0,
      memcmp(
          golden->iov[0].iov_base,
          p1->iov[0].iov_base,
          p1->iov[0].iov_len));
  free_packet(golden);
  free_packet(p1);
  free_struct_arista7150_ts(st);
}
END_TEST


/* set up and run --------------------------------------------------------- */

int main(int argc, const char *argv[]) {
  int number_failed;
  Suite *s = suite_create("sc_arista7150_ts");
  TCase *tc_node = tcase_create("Arista Time Stamp Node Functions");
/*
  tcase_add_test(tc_node,
                 TEST_that_given_has_fcs_false_and_strip_ticks_false_arista7150_ts_pkt_adjust_only_reads_time);
*/
  /* template - less typing
  tcase_add_test(tc_node,
                 );
  */
  suite_add_tcase(s, tc_node);
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
