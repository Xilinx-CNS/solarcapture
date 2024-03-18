/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/*
 * ut_sc_cpacket_ts_node.c
 *
 *  Created on: 22 May 2015
 *      Author: ld
 */

#include "cpacket_offsets.h"
#include "solar_capture/ext_packet.h"

#include <sys/uio.h>
#include <check.h>
#include <check_helpers.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Include C directly so that we can test static functions */
#include "../../components/sc_cpacket_ts.c"

#define GOOD_PS_TS_FLAGS SC_PS_FLAG_CLOCK_SET | SC_PS_FLAG_CLOCK_IN_SYNC

/* test data -------------------------------------------------------------- */

static const uint32_t capture_delay_s = 1;
static const uint32_t capture_delay_ns = 23456;
static const size_t MAX_IOV_LEN = 1920; /* Arbitrary plausible size */
static const size_t CPACKET_TIMESTAMP_S_OFFSET = 4;
static const size_t MAX_PACKED_SIZE = 64*1024;


#define __TEST_MAX_TLV_WORDS 10
struct tlv_spec {
  uint8_t flags;
  int len;
  int number;
  /* Words are counted from the end, i.e. reverse order is used */
  uint32_t word[__TEST_MAX_TLV_WORDS];
};

#define TLV_WORD_24BIT_DATA 0x12345600
#define TLV_WORD_32BIT_DATA 0x12345678

/* 1 extension, consisting of a single header word */
static const struct tlv_spec tlv_single_ext_single_word = {
  .flags = METAMAKO_FLAG_TLV_PRESENT | METAMAKO_FLAG_FCS_VALID,
  .len = 4,
  .number = 1,
  .word = {TLV_WORD_24BIT_DATA | METAMAKO_FINAL}
};

/* 1 extension, consisting of a header word preceded by 3 payload words */
static const struct tlv_spec tlv_single_ext_multi_word = {
  .flags = METAMAKO_FLAG_TLV_PRESENT | METAMAKO_FLAG_FCS_VALID,
  .len = 16,
  .number = 4,
  .word = {TLV_WORD_24BIT_DATA | (3 << METAMAKO_LEN_SHIFT) | METAMAKO_FINAL,
           TLV_WORD_32BIT_DATA, TLV_WORD_32BIT_DATA, TLV_WORD_32BIT_DATA}
};

/* 2 extensions, each consisting of a single header word */
static const struct tlv_spec tlv_multi_ext_single_word = {
  .flags = METAMAKO_FLAG_TLV_PRESENT | METAMAKO_FLAG_FCS_VALID,
  .len = 8,
  .number = 2,
  .word = {TLV_WORD_24BIT_DATA, TLV_WORD_24BIT_DATA | METAMAKO_FINAL}
};

/* Invalid TLV:
 * 1 extension, consisting of a single header word,
 * but TLV present flag is not set
 */
static const struct tlv_spec tlv_ext_not_present = {
  .flags = METAMAKO_FLAG_FCS_VALID,
  .len = 4,
  .number = 1,
  .word = {TLV_WORD_24BIT_DATA | METAMAKO_FINAL}
};

/* Invalid TLV:
 * 1 extension, consisting of a single header word,
 * but TLV final flag is not set
 */
static const struct tlv_spec tlv_ext_no_final = {
  .flags =  METAMAKO_FLAG_TLV_PRESENT | METAMAKO_FLAG_FCS_VALID,
  .len = 4,
  .number = 1,
  .word = {TLV_WORD_24BIT_DATA}
};

/* 1 extension, consisting of a single header word,
 * original FCS valid flag is not set
 */
static const struct tlv_spec tlv_ext_no_valid_fcs = {
  .flags =  METAMAKO_FLAG_TLV_PRESENT,
  .len = 4,
  .number = 1,
  .word = {TLV_WORD_24BIT_DATA | METAMAKO_FINAL}
};

/* 1 extension, consisting of a header word in secondary format,
 * preceded by 6 payload words
 *
 * Note: in secondary format the header word doesn't contain payload data,
 * so first payload word is mandatory and could be treated as second word of
 * the header. Length field in the header contains number of additional
 * payload words (not including mandatory first payload word).
 */
static const struct tlv_spec tlv_secondary_ext = {
  .flags = METAMAKO_FLAG_TLV_PRESENT | METAMAKO_FLAG_FCS_VALID,
  .len = 28,
  .number = 7,
  .word = {(5 << METAMAKO_LEN_SHIFT) | METAMAKO_FINAL |
           METAMAKO_TAG_SECONDARY,
           TLV_WORD_32BIT_DATA, TLV_WORD_32BIT_DATA, TLV_WORD_32BIT_DATA,
           TLV_WORD_32BIT_DATA, TLV_WORD_32BIT_DATA, TLV_WORD_32BIT_DATA}
};


#define TEST_SINGLE_TLV_EXT_LEN(_tlv, _word, _fcs) \
  TEST_that_single_tlv_ext_len_returns_correct_length_for_\
    ##_tlv##_##_word##_##_fcs##_packet


#define TEST_SINGLE_TLV_EXT_LEN_ZERO(_type) \
  TEST_that_single_tlv_ext_len_returns_zero_length_for_##_type##_packet


#define TEST_SINGLE_PROCESS_TLV(_action, _type) \
  TEST_that_process_single_packet_##_action##_tlv_packet_##_type


#define TEST_PACKED_PROCESS_TLV(_action, _type) \
  TEST_that_process_packed_stream_##_action##_tlv_packet_##_type


/* Generate a dummy packet with CPacket footer.
 * Only fill the fields required for the test.
 */
static struct sc_packet* generate_cpacket(size_t payload_length,
                             uint32_t time_s,
                             uint32_t time_ns,
                             bool has_fcs,
                             const struct tlv_spec* tlv) {
  struct sc_packet* result = malloc(sizeof(struct sc_packet));
  memset(result, 0, sizeof(*result));
  /* set the per packet fields */
  result->ts_sec = time_s + capture_delay_s;
  result->ts_nsec = time_ns + capture_delay_ns;
  if(result->ts_nsec > SC_NS_IN_S) {
    result->ts_sec += result->ts_nsec / SC_NS_IN_S;
    result->ts_nsec = result->ts_nsec % SC_NS_IN_S;
  }
  size_t footer_length = cpacket_footer_length(has_fcs);
  size_t total_length = payload_length + footer_length;
  if ( tlv != NULL )
    total_length += tlv->len;
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
    result->iov[i].iov_base = calloc(1, iov_len);
  }
  /* fill in cpacket data */
  struct cpacket_data data;
  memset(&data, 0, sizeof(data));
  data.time.s = htonl(time_s);
  data.time.ns = htonl(time_ns);
  int offset = has_fcs ? sizeof(fcs_t) : 0;

  if( tlv != NULL )
    data.version = tlv->flags;

  sc_iovec_copy_to_end_offset(result->iov, &data, result->iovlen,
                              sizeof(data), offset);

  /* fill TLV data */
  if( tlv != NULL ) {
    offset += sizeof(data);
    for( i = 0; i < tlv->number; i++) {
      uint32_t word = htonl(tlv->word[i]);
      sc_iovec_copy_to_end_offset(result->iov, &word, result->iovlen,
                                  sizeof(word), offset);
      offset += sizeof(word);
    }
  }
  return result;
}

static void free_cpacket(struct sc_packet* done) {
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

/* payload_len includes CPacket footer (in Metamako case with TLVs) */
static struct sc_packet* generate_packed_stream_cpackets(size_t payload_len,
                                                        const struct packet_counts_in_iovs pkt_counts,
                                                        uint32_t time_s,
                                                        uint32_t time_ns,
                                                        bool has_fcs,
                                                        uint8_t flags,
                                                        const struct tlv_spec* tlv) {
  static const size_t PRE_PAD_SIZE = 19; /* Arbitrary plausible size */
  static const size_t POST_PAD_SIZE = 96; /* Arbitrary plausible size */
  struct sc_packet* result = malloc(sizeof(struct sc_packet));
  struct sc_packed_packet* pph;

  assert(tlv == NULL || tlv->len + cpacket_footer_length(has_fcs) <= payload_len);
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
      pph->ps_orig_len = payload_len;
      pph->ps_cap_len = payload_len;
      pph->ps_ts_nsec = 0;
      pph->ps_ts_sec = 0;
      pph->ps_flags = flags;

      struct cpacket_footer_with_fcs* footer = sc_packed_packet_payload(pph)
          + pph->ps_cap_len
          - cpacket_footer_length(has_fcs);
      footer->data.time.s = htonl(time_s);
      footer->data.time.ns = htonl(time_ns);

      /* fill TLV data */
      if( tlv != NULL ) {
        char *endptr = (char *) footer;
        footer->data.version = tlv->flags;
        for( i = 0; i < tlv->number; i++) {
          uint32_t word = htonl(tlv->word[i]);
          memcpy(endptr, &word, sizeof(word));
          endptr -= sizeof(word);
        }
      }

      pph_offset += packet_requirement;
    }
    /* There is no next, as indicated by the fact that
     * the next offset points outside the iovec */
  }
  return result;
}

static void generate_fetch_time_and_check(const size_t packet_len,
                                          const uint32_t time_s,
                                          const uint32_t time_ns,
                                          const bool has_fcs,
                                          const struct tlv_spec* tlv) {
  struct sc_packet* packet = generate_cpacket(packet_len, time_s, time_ns,
      has_fcs, tlv);
  struct cpacket_data buffer;
  fetch_cpacket_data(&buffer, packet, has_fcs);
  struct cpacket_time* footer_time = &buffer.time;
  ck_assert_int_eq(time_s, ntohl(footer_time->s));
  ck_assert_int_eq(time_ns, ntohl(footer_time->ns));
  free_cpacket(packet);
}

/* tests ------------------------------------------------------------------ */

/* fetch_footer() tests for non-packed packets -------------------------------
 * Note that there are probably more of these than there need to be.
 * They were put in when the code was more complex in order to get coverage.
 * If you refactor and need to change these tests then you may wish to remove
 * some of them. */

/* get time from a word aligned cpacket footer,
 * which resides fully in first iovec */
START_TEST(TEST_that_given_a_packet_with_aligned_footer_fetch_footer_returns_a_pointer_to_the_footer) {
  static const size_t short_and_aligned = 64;
  static const uint32_t time_s = 34567;
  static const uint32_t time_ns = 45678;
  static const bool has_fcs = true;
  generate_fetch_time_and_check(short_and_aligned, time_s, time_ns, has_fcs,
                                NULL);
}
END_TEST

/* get time from a word aligned cpacket footer,
 * which resides fully in first iovec */
START_TEST(TEST_that_given_a_packet_with_aligned_footer_with_no_fcs_fetch_footer_returns_a_pointer_to_the_footer) {
  static const size_t other_short_and_aligned = 120;
  static const uint32_t time_s = 23456;
  static const uint32_t time_ns = 34567;
  static const bool has_fcs = false;
  generate_fetch_time_and_check(other_short_and_aligned, time_s, time_ns,
                                has_fcs, NULL);
}
END_TEST

/* get time from an non word aligned cpacket footer,
 * which resides fully in first iovec */
START_TEST(TEST_that_given_a_packet_with_nonaligned_footer_fetch_footer_returns_a_pointer_to_the_footer) {
  static const uint32_t time_s = 23456;
  static const uint32_t time_ns = 34567;
  static const bool has_fcs = true;
  static const size_t not_the_size_of_a_whole_number_of_uint32_t = 191;
  generate_fetch_time_and_check(not_the_size_of_a_whole_number_of_uint32_t,
                                time_s, time_ns, has_fcs, NULL);
}
END_TEST

/* get time from an non word aligned cpacket footer,
 * which resides fully in first iovec */
START_TEST(TEST_that_given_a_packet_with_nonaligned_footer_with_no_fcs_fetch_footer_returns_a_pointer_to_the_footer) {
  static const uint32_t time_s = 12345;
  static const uint32_t time_ns = 23456;
  static const bool has_fcs = false;
  static const size_t not_the_size_of_a_whole_number_of_uint32_t = 193;
  generate_fetch_time_and_check(not_the_size_of_a_whole_number_of_uint32_t,
                                time_s, time_ns, has_fcs, NULL);
}
END_TEST

/* get time from cpacket footer that straddles first iovec boundary
 * (sc_packet.iovlen >= 2)
 * This one aligned (though it shouldn't make any difference). */
START_TEST(TEST_that_given_a_two_iovec_packet_with_split_footer_fetch_footer_a_pointer_to_the_footer) {
  static const uint32_t time_s = 45678;
  static const uint32_t time_ns = 91234;
  static const bool has_fcs = true;
  const size_t just_long_enough_that_the_times_straddle_the_iovec_boundary =
      MAX_IOV_LEN + cpacket_footer_length(has_fcs)
      - CPACKET_TIMESTAMP_S_OFFSET + sizeof(uint32_t);
  generate_fetch_time_and_check(
      just_long_enough_that_the_times_straddle_the_iovec_boundary,
      time_s, time_ns, has_fcs, NULL);
}
END_TEST

/* This one not aligned (mix it up to improve coverage, even though it shouldn't
 * make any difference).
 */
START_TEST(TEST_that_given_a_three_iovec_packet_with_split_footer_fetch_footer_a_pointer_to_the_footer) {
  static const uint32_t time_s = 45678;
  static const uint32_t time_ns = 91234;
  static const bool has_fcs = true;
  const size_t just_long_enough_that_the_times_straddle_the_iovec_boundary =
      MAX_IOV_LEN * 2 + cpacket_footer_length(has_fcs) - CPACKET_TIMESTAMP_S_OFFSET + 1;
  generate_fetch_time_and_check(
      just_long_enough_that_the_times_straddle_the_iovec_boundary,
      time_s, time_ns, has_fcs, NULL);
}
END_TEST

/* This one not aligned (mix it up to improve coverage, even though it shouldn't
 * make any difference).
 */
START_TEST(TEST_that_given_a_three_iovec_packet_with_split_footer_and_no_fcs_fetch_footer_a_pointer_to_the_footer) {
  static const uint32_t time_s = 45678;
  static const uint32_t time_ns = 91234;
  static const bool has_fcs = false;
  const size_t just_long_enough_that_the_times_straddle_the_iovec_boundary =
      MAX_IOV_LEN * 2 + cpacket_footer_length(has_fcs) - CPACKET_TIMESTAMP_S_OFFSET + 1;
  generate_fetch_time_and_check(
      just_long_enough_that_the_times_straddle_the_iovec_boundary,
      time_s, time_ns, has_fcs, NULL);
}
END_TEST

/* This one not aligned (mix it up to improve coverage, even though it shouldn't
 * make any difference).
 */
START_TEST(TEST_that_given_a_three_iovec_packet_with_the_footer_in_the_penultimate_iovec_and_no_fcs_fetch_footer_returns_a_pointer_to_the_footer) {
  static const uint32_t time_s = 45678;
  static const uint32_t time_ns = 91234;
  static const bool has_fcs = false;
  const size_t long_enough_that_the_times_are_in_the_penultimate_iovec =
      MAX_IOV_LEN * 2 + 1;
  generate_fetch_time_and_check(
      long_enough_that_the_times_are_in_the_penultimate_iovec,
      time_s, time_ns, has_fcs, NULL);
}
END_TEST

/* update_time() tests ---------------------------------------------------- */

/* update time in packet metadata */
START_TEST(TEST_that_update_time_updates_the_sc_packet_time_fields) {
  static const uint32_t time_s = 56789;
  static const uint32_t time_ns = 12345;
  static const size_t shortish = 93;
  static const bool has_fcs = false;
  struct cpacket_time time;
  time.s = htonl(time_s);
  time.ns = htonl(time_ns);
  struct sc_packet *packet = generate_cpacket(
        shortish,
        time_s,
        time_ns,
        has_fcs,
        NULL);
  update_time(packet, &time);
  ck_assert_int_eq(time_s, packet->ts_sec);
  ck_assert_int_eq(time_ns, packet->ts_nsec);
  free_cpacket(packet);
}
END_TEST

/* remove_footer() tests ---------------------------------------------------- */

/* update length to trim off cpacket footer
 * use solar_capture/iovec.h:sc_iovec_trim_end() */
START_TEST(TEST_that_give_a_single_iovec_packet_with_fcs_remove_footer_removes_exactly_the_cpacket_footer) {
  static const uint32_t time_s = 67891;
  static const uint32_t time_ns = 23456;
  static const size_t shortish = 98;
  static const bool has_fcs = true;
  struct sc_packet *packet = generate_cpacket(
        shortish,
        time_s,
        time_ns,
        has_fcs,
        NULL);
  ck_assert_int_eq(shortish + cpacket_footer_length(has_fcs), packet->frame_len);
  ck_assert_int_eq(shortish + cpacket_footer_length(has_fcs), packet->iov[0].iov_len);
  ck_assert_int_eq(1, packet->iovlen);
  remove_footer(packet, sizeof(struct cpacket_footer));
  ck_assert_int_eq(shortish + sizeof(uint32_t), packet->frame_len);
  ck_assert_int_eq(shortish + sizeof(uint32_t), packet->iov[0].iov_len);
  ck_assert_int_eq(1, packet->iovlen);
  free_cpacket(packet);
}
END_TEST

START_TEST(TEST_that_give_a_single_iovec_packet_without_fcs_remove_footer_removes_exactly_the_cpacket_footer) {
  static const uint32_t time_s = 78912;
  static const uint32_t time_ns = 34567;
  static const size_t shortish = 98;
  static const bool has_fcs = false;
  struct sc_packet *packet = generate_cpacket(
        shortish,
        time_s,
        time_ns,
        has_fcs,
        NULL);
  ck_assert_int_eq(shortish + cpacket_footer_length(has_fcs), packet->frame_len);
  ck_assert_int_eq(shortish + cpacket_footer_length(has_fcs), packet->iov[0].iov_len);
  ck_assert_int_eq(1, packet->iovlen);
  remove_footer(packet, sizeof(struct cpacket_footer));
  ck_assert_int_eq(shortish, packet->frame_len);
  ck_assert_int_eq(shortish, packet->iov[0].iov_len);
  ck_assert_int_eq(1, packet->iovlen);
  free_cpacket(packet);
}
END_TEST

/* process_packet() tests ------------------------------------------------- */

START_TEST(TEST_that_process_packet_returns_false_when_there_is_no_next_single_packet) {
  static const size_t short_and_aligned = 64;
  static const uint32_t time_s = 34567;
  static const uint32_t time_ns = 45678;
  struct sc_cpacket_ts state = {.has_fcs=true,
                                .check_nic_time=false,
                                .keep_cpacket_footer=false,
                                .bytes_to_remove_from_footer=sizeof(struct cpacket_footer),
                                .is_metamako=false};
  struct sc_packet* packet = generate_cpacket(short_and_aligned, time_s,
                                              time_ns, state.has_fcs, NULL);
  ck_assert(!process_packet(packet, &state));
  free_cpacket(packet);
}
END_TEST

START_TEST(TEST_that_process_packet_returns_true_when_there_is_a_next_single_packet) {
  static const size_t short_and_aligned = 64;
  static const uint32_t time_s = 34567;
  static const uint32_t time_ns = 45678;
  static const bool has_fcs = true;
  struct sc_packet* packet0 = generate_cpacket(short_and_aligned, time_s,
                                               time_ns, has_fcs, NULL);
  struct sc_packet* packet1 = generate_cpacket(short_and_aligned, time_s,
                                               time_ns, has_fcs, NULL);
  struct sc_cpacket_ts state = {.has_fcs=true,
                                .check_nic_time=false,
                                .keep_cpacket_footer=false,
                                .bytes_to_remove_from_footer=sizeof(struct cpacket_footer),
                                .is_metamako=false};
  packet0->next = packet1;
  ck_assert((intptr_t) process_packet(packet0, &state));
  free_cpacket(packet0);
  free_cpacket(packet1);
}
END_TEST

START_TEST(TEST_that_process_packet_returns_false_when_there_is_no_next_stream_packet) {
  static const size_t short_and_aligned = 64;
  static const uint32_t time_s = 1;
  static const uint32_t time_ns = 2;
  static const uint num_iovs_limit = 2;
  struct sc_cpacket_ts state = {.has_fcs=true,
                                .check_nic_time=false,
                                .keep_cpacket_footer=false,
                                .bytes_to_remove_from_footer=sizeof(struct cpacket_footer),
                                .is_metamako=false};
  struct packet_counts_in_iovs pkt_counts = {.packet_counts = {1, 1}};
  uint num_iovs;
  for (num_iovs = 1; num_iovs < num_iovs_limit; ++num_iovs) {
    pkt_counts.number_of_iovs = num_iovs;
    struct sc_packet* packet = generate_packed_stream_cpackets(
                                    short_and_aligned, pkt_counts,
                                    time_s, time_ns, true,
                                    GOOD_PS_TS_FLAGS, NULL);
    ck_assert(!process_packet(packet, &state));
    free_cpacket(packet);
  }
}
END_TEST

START_TEST(TEST_that_process_packet_returns_true_when_there_is_a_next_stream_packet) {
  static const size_t short_and_aligned = 64;
  static const uint32_t time_s = 1;
  static const uint32_t time_ns = 2;
  static const uint num_iovs_limit = 2;
  struct sc_cpacket_ts state = {.has_fcs=true,
                                .check_nic_time=false,
                                .keep_cpacket_footer=false,
                                .bytes_to_remove_from_footer=sizeof(struct cpacket_footer),
                                .is_metamako=false};
  struct packet_counts_in_iovs pkt_counts = {.packet_counts = {1, 1}};
  uint num_iovs;
  for (num_iovs = 1; num_iovs <= num_iovs_limit; ++num_iovs) {
    pkt_counts.number_of_iovs = num_iovs;
    struct sc_packet* packet0 = generate_packed_stream_cpackets(
                                    short_and_aligned, pkt_counts,
                                    time_s, time_ns, state.has_fcs,
                                    GOOD_PS_TS_FLAGS, NULL);
    struct sc_packet* packet1 = generate_packed_stream_cpackets(
                                    short_and_aligned, pkt_counts,
                                    time_s, time_ns, state.has_fcs,
                                    GOOD_PS_TS_FLAGS, NULL);
    packet0->next = packet1;
    ck_assert((intptr_t) process_packet(packet0, &state));
    free_cpacket(packet0);
    free_cpacket(packet1);
  }
}
END_TEST

/* process_stream() tests ------------------------------------------------- */

START_TEST(TEST_that_given_a_packed_stream_containing_a_single_packet_process_stream_leaves_the_sc_packet_unchanged) {
  static const size_t payload_len = 962;
  static const uint32_t time_s = 1;
  static const uint32_t time_ns = 2;
  static const uint num_iovs_limit = 2;
  static const bool has_fcs = false;
  struct packet_counts_in_iovs pkt_counts = {.packet_counts = {1, 1}};
  uint num_iovs;
  for (num_iovs = 1; num_iovs <= num_iovs_limit; ++num_iovs) {
    pkt_counts.number_of_iovs = num_iovs;
    struct sc_packet* stream = generate_packed_stream_cpackets(
                                    payload_len, pkt_counts,
                                    time_s, time_ns, has_fcs,
                                    GOOD_PS_TS_FLAGS, NULL);
    struct sc_packet original;
    struct sc_cpacket_ts state = {.has_fcs=true,
                                  .check_nic_time=false,
                                  .keep_cpacket_footer=false,
                                  .bytes_to_remove_from_footer=sizeof(struct cpacket_footer),
                                  .is_metamako=false};
    memcpy(&original, stream, sizeof(original));
    process_packed_stream_packet(stream, &state);
    ck_assert(!memcmp(&original, stream, sizeof(original)));
    free_cpacket(stream);
  }
}
END_TEST

START_TEST(TEST_that_given_a_packed_stream_containing_a_single_packet_process_stream_shortens_the_contained_packet) {
  static const size_t payload_len = 351;
  static const uint32_t time_s = 1;
  static const uint32_t time_ns = 2;
  static const uint num_iovs_limit = 2;
  struct sc_cpacket_ts state = {.has_fcs=true,
                                .keep_cpacket_footer=false,
                                .bytes_to_remove_from_footer=sizeof(struct cpacket_footer),
                                .is_metamako=false};
  struct packet_counts_in_iovs pkt_counts = {.packet_counts = {1, 1}};
  uint num_iovs;
  for( num_iovs = 1; num_iovs <= num_iovs_limit; ++num_iovs ) {
    pkt_counts.number_of_iovs = num_iovs;
    struct sc_packet* stream = generate_packed_stream_cpackets(
                                    payload_len, pkt_counts,
                                    time_s, time_ns, state.has_fcs,
                                    GOOD_PS_TS_FLAGS, NULL);
    process_packed_stream_packet(stream, &state);
    unsigned iovi;
    for( iovi = 0; iovi < num_iovs; ++iovi ) {
      struct sc_packed_packet* pph = stream->iov[iovi].iov_base;
      ck_assert_int_eq(pph->ps_cap_len, payload_len - sizeof(struct cpacket_footer));
    }
    free_cpacket(stream);
  }
}
END_TEST

START_TEST(TEST_that_given_a_packed_stream_containing_a_single_packet_process_stream_does_not_shortens_the_contained_packet_for_keep_footer_mode) {
  static const size_t payload_len = 351;
  static const uint32_t time_s = 1;
  static const uint32_t time_ns = 2;
  static const uint num_iovs_limit = 2;
  struct sc_cpacket_ts state = {.has_fcs=true,
                                .check_nic_time=false,
                                .keep_cpacket_footer=true,
                                .bytes_to_remove_from_footer=0,
                                .is_metamako=false};
  struct packet_counts_in_iovs pkt_counts = {.packet_counts = {1, 1}};
  uint num_iovs;
  for( num_iovs = 1; num_iovs <= num_iovs_limit; ++num_iovs ) {
    pkt_counts.number_of_iovs = num_iovs;
    struct sc_packet* stream = generate_packed_stream_cpackets(
                                    payload_len, pkt_counts,
                                    time_s, time_ns, state.has_fcs,
                                    GOOD_PS_TS_FLAGS, NULL);
    process_packed_stream_packet(stream, &state);
    unsigned iovi;
    for( iovi = 0; iovi < num_iovs; ++iovi ) {
      struct sc_packed_packet* pph = stream->iov[iovi].iov_base;
      ck_assert_int_eq(pph->ps_cap_len, payload_len);
    }
    free_cpacket(stream);
  }
}
END_TEST

START_TEST(TEST_that_given_a_packed_stream_containing_a_single_packet_process_stream_updates_the_time_in_the_contained_packet) {
  static const size_t payload_len = 2053;
  static const uint32_t time_s = 34567;
  static const uint32_t time_ns = 45678;
  static const uint num_iovs_limit = 2;
  struct sc_cpacket_ts state = {.has_fcs=false,
                                .check_nic_time=false,
                                .keep_cpacket_footer=false,
                                .bytes_to_remove_from_footer=sizeof(struct cpacket_footer),
                                .is_metamako=false};
  struct packet_counts_in_iovs pkt_counts = {.packet_counts = {1, 1}};
  uint num_iovs;
  for( num_iovs = 1; num_iovs <= num_iovs_limit; ++num_iovs ) {
    pkt_counts.number_of_iovs = num_iovs;
    struct sc_packet* stream = generate_packed_stream_cpackets(
                                    payload_len, pkt_counts,
                                    time_s, time_ns, state.has_fcs,
                                    GOOD_PS_TS_FLAGS, NULL);
    process_packed_stream_packet(stream, &state);
    unsigned iovi;
    for( iovi = 0; iovi < num_iovs; ++iovi ) {
      struct sc_packed_packet* pph = stream->iov[iovi].iov_base;
      ck_assert_int_eq(pph->ps_ts_sec, time_s);
      ck_assert_int_eq(pph->ps_ts_nsec, time_ns);
      ck_assert(pph->ps_flags & SC_PS_FLAG_CLOCK_SET);
      ck_assert(pph->ps_flags & SC_PS_FLAG_CLOCK_IN_SYNC);
    }
    free_cpacket(stream);
  }
}
END_TEST

START_TEST(TEST_that_given_a_packed_stream_containing_three_packets_process_stream_updates_the_times_and_removes_the_footers_for_all_the_contained_packets) {
  static const size_t payload_len = 980;
  static const uint32_t time_s = 4567;
  static const uint32_t time_ns = 5678;
  static const uint num_iovs_limit = 2;
  struct sc_cpacket_ts state = {.has_fcs=true,
                                .check_nic_time=false,
                                .keep_cpacket_footer=false,
                                .bytes_to_remove_from_footer=sizeof(struct cpacket_footer),
                                .is_metamako=false};
  struct packet_counts_in_iovs pkt_counts = {.packet_counts = {3, 3}};
  uint num_iovs;
  for( num_iovs = 1; num_iovs <= num_iovs_limit; ++num_iovs ) {
    pkt_counts.number_of_iovs = num_iovs;
    struct sc_packet* pack = generate_packed_stream_cpackets(
                                    payload_len, pkt_counts,
                                    time_s, time_ns, state.has_fcs,
                                    GOOD_PS_TS_FLAGS, NULL);
    process_packed_stream_packet(pack, &state);
    unsigned iovi;
    for( iovi = 0; iovi < num_iovs; ++iovi ) {
      struct sc_packed_packet* pph = sc_packet_iov_packed_first(pack, iovi);
      struct sc_packed_packet* end_of_pack = sc_packet_iov_packed_end(pack, iovi);
      int packet_count = 0;
      while( pph < end_of_pack ) {
        ck_assert_int_eq(pph->ps_cap_len, payload_len - sizeof(struct cpacket_footer));
        ck_assert_int_eq(pph->ps_ts_sec, time_s);
        ck_assert_int_eq(pph->ps_ts_nsec, time_ns);
        ck_assert(pph->ps_flags & SC_PS_FLAG_CLOCK_SET);
        ck_assert(pph->ps_flags & SC_PS_FLAG_CLOCK_IN_SYNC);
        pph = sc_packed_packet_next(pph);
        ++packet_count;
      }
      ck_assert_int_eq(pkt_counts.packet_counts[iovi], packet_count);
    }
    free_cpacket(pack);
  }
}
END_TEST


START_TEST(TEST_that_a_packed_stream_buffer_with_single_runt_packet_has_correct_flags_set_without_fcs)
{
  static const size_t payload_len = sizeof(struct cpacket_footer) - 1;
  static const uint32_t time_s = 34567;
  static const uint32_t time_ns = 45678;
  static const uint num_iovs_limit = 1;
  struct sc_cpacket_ts state = {.has_fcs=false,
                                .check_nic_time=false,
                                .keep_cpacket_footer=false,
                                .bytes_to_remove_from_footer=sizeof(struct cpacket_footer),
                                .is_metamako=false};
  struct packet_counts_in_iovs pkt_counts = {.packet_counts = {1}};
  uint num_iovs;
  for( num_iovs = 1; num_iovs <= num_iovs_limit; ++num_iovs ) {
    pkt_counts.number_of_iovs = num_iovs;
    struct sc_packet* stream = generate_packed_stream_cpackets(
                                    payload_len, pkt_counts,
                                    time_s, time_ns, state.has_fcs,
                                    GOOD_PS_TS_FLAGS, NULL);
    process_packed_stream_packet(stream, &state);
    unsigned iovi;
    for( iovi = 0; iovi < num_iovs; ++iovi ) {
      struct sc_packed_packet* pph = stream->iov[iovi].iov_base;
      ck_assert_int_eq(pph->ps_ts_sec, 0);
      ck_assert_int_eq(pph->ps_ts_nsec, 0);
      ck_assert(!(pph->ps_flags & SC_PS_FLAG_CLOCK_SET));
      ck_assert(!(pph->ps_flags & SC_PS_FLAG_CLOCK_IN_SYNC));
      ck_assert_uint_eq(pph->ps_cap_len, payload_len);
      ck_assert_uint_eq(pph->ps_orig_len, payload_len);
    }
    free_cpacket(stream);
  }
}
END_TEST


START_TEST(TEST_that_a_packed_stream_buffer_with_single_runt_packet_has_correct_flags_set_with_fcs)
{
  static const size_t payload_len = sizeof(struct cpacket_footer_with_fcs) - 1;
  static const uint32_t time_s = 34567;
  static const uint32_t time_ns = 45678;
  static const uint num_iovs_limit = 1;
  struct sc_cpacket_ts state = {.has_fcs=true,
                                .check_nic_time=false,
                                .keep_cpacket_footer=false,
                                .bytes_to_remove_from_footer=sizeof(struct cpacket_footer_with_fcs),
                                .is_metamako=false};
  struct packet_counts_in_iovs pkt_counts = {.packet_counts = {1}};
  uint num_iovs;
  for( num_iovs = 1; num_iovs <= num_iovs_limit; ++num_iovs ) {
    pkt_counts.number_of_iovs = num_iovs;
    struct sc_packet* stream = generate_packed_stream_cpackets(
                                    payload_len, pkt_counts, time_s, time_ns,
                                    state.has_fcs, GOOD_PS_TS_FLAGS, NULL);
    process_packed_stream_packet(stream, &state);
    unsigned iovi;
    for( iovi = 0; iovi < num_iovs; ++iovi ) {
      struct sc_packed_packet* pph = stream->iov[iovi].iov_base;
      ck_assert_int_eq(pph->ps_ts_sec, 0);
      ck_assert_int_eq(pph->ps_ts_nsec, 0);
      ck_assert(!(pph->ps_flags & SC_PS_FLAG_CLOCK_SET));
      ck_assert(!(pph->ps_flags & SC_PS_FLAG_CLOCK_IN_SYNC));
      ck_assert_uint_eq(pph->ps_cap_len, payload_len);
      ck_assert_uint_eq(pph->ps_orig_len, payload_len);
    }
    free_cpacket(stream);
  }
}
END_TEST


START_TEST(TEST_timestamp_difference_within_threshold_works)
{
  static const size_t payload_len = 500;
  static const uint32_t time_s = 1;
  static const uint32_t time_ns = 0;
  static const uint num_iovs_limit = 1;
  struct sc_cpacket_ts state = {.has_fcs=false,
                                .check_nic_time=true,
                                .max_diff_from_nic_time_ns=SC_NS_IN_S,
                                .keep_cpacket_footer=false,
                                .bytes_to_remove_from_footer=sizeof(struct cpacket_footer),
                                .is_metamako=false};
  struct packet_counts_in_iovs pkt_counts = {.packet_counts = {1}};
  uint num_iovs;
  for( num_iovs = 1; num_iovs <= num_iovs_limit; ++num_iovs ) {
    pkt_counts.number_of_iovs = num_iovs;
    struct sc_packet* stream = generate_packed_stream_cpackets(
                                    payload_len, pkt_counts, time_s, time_ns,
                                    state.has_fcs, GOOD_PS_TS_FLAGS, NULL);
    process_packed_stream_packet(stream, &state);
    unsigned iovi;
    for( iovi = 0; iovi < num_iovs; ++iovi ) {
      struct sc_packed_packet* pph = stream->iov[iovi].iov_base;
      ck_assert_int_eq(pph->ps_ts_sec, time_s);
      ck_assert_int_eq(pph->ps_ts_nsec, time_ns);
      ck_assert(pph->ps_flags & SC_PS_FLAG_CLOCK_SET);
      ck_assert(pph->ps_flags & SC_PS_FLAG_CLOCK_IN_SYNC);
      ck_assert_uint_eq(pph->ps_cap_len, payload_len - sizeof(struct cpacket_footer));
      ck_assert_uint_eq(pph->ps_orig_len, payload_len - sizeof(struct cpacket_footer));
    }
    free_cpacket(stream);
  }
}
END_TEST


START_TEST(TEST_timestamp_difference_outside_of_threshold_fails)
{
  static const size_t payload_len = 500;
  static const uint32_t time_s = 1;
  static const uint32_t time_ns = 1;
  static const uint num_iovs_limit = 1;
  struct sc_cpacket_ts state = {.has_fcs=false,
                                .check_nic_time=true,
                                .max_diff_from_nic_time_ns=SC_NS_IN_S,
                                .keep_cpacket_footer=false,
                                .bytes_to_remove_from_footer=sizeof(struct cpacket_footer),
                                .is_metamako=false};
  struct packet_counts_in_iovs pkt_counts = {.packet_counts = {1}};
  uint num_iovs;
  for( num_iovs = 1; num_iovs <= num_iovs_limit; ++num_iovs ) {
    pkt_counts.number_of_iovs = num_iovs;
    struct sc_packet* stream = generate_packed_stream_cpackets(
                                    payload_len, pkt_counts, time_s, time_ns,
                                    state.has_fcs, GOOD_PS_TS_FLAGS, NULL);
    process_packed_stream_packet(stream, &state);
    unsigned iovi;
    for( iovi = 0; iovi < num_iovs; ++iovi ) {
      struct sc_packed_packet* pph = stream->iov[iovi].iov_base;
      ck_assert_int_eq(pph->ps_ts_sec, 0);
      ck_assert_int_eq(pph->ps_ts_nsec, 0);
      ck_assert(!(pph->ps_flags & SC_PS_FLAG_CLOCK_SET));
      ck_assert(!(pph->ps_flags & SC_PS_FLAG_CLOCK_IN_SYNC));
      ck_assert_uint_eq(pph->ps_cap_len, payload_len);
      ck_assert_uint_eq(pph->ps_orig_len, payload_len);
    }
    free_cpacket(stream);
  }
}
END_TEST


START_TEST(TEST_timestamp_difference_within_threshold_but_without_clock_set_fails)
{
  static const size_t payload_len = 500;
  static const uint32_t time_s = 1;
  static const uint32_t time_ns = 0;
  static const uint num_iovs_limit = 1;
  struct sc_cpacket_ts state = {.has_fcs=false,
                                .check_nic_time=true,
                                .max_diff_from_nic_time_ns=SC_NS_IN_S,
                                .keep_cpacket_footer=false,
                                .bytes_to_remove_from_footer=sizeof(struct cpacket_footer),
                                .is_metamako=false};
  struct packet_counts_in_iovs pkt_counts = {.packet_counts = {1}};
  uint num_iovs;
  for( num_iovs = 1; num_iovs <= num_iovs_limit; ++num_iovs ) {
    pkt_counts.number_of_iovs = num_iovs;
    struct sc_packet* stream = generate_packed_stream_cpackets(
                                    payload_len, pkt_counts, time_s, time_ns,
                                    state.has_fcs, 0, NULL);
    process_packed_stream_packet(stream, &state);
    unsigned iovi;
    for( iovi = 0; iovi < num_iovs; ++iovi ) {
      struct sc_packed_packet* pph = stream->iov[iovi].iov_base;
      ck_assert_int_eq(pph->ps_ts_sec, 0);
      ck_assert_int_eq(pph->ps_ts_nsec, 0);
      ck_assert(!(pph->ps_flags & SC_PS_FLAG_CLOCK_SET));
      ck_assert(!(pph->ps_flags & SC_PS_FLAG_CLOCK_IN_SYNC));
      ck_assert_uint_eq(pph->ps_cap_len, payload_len);
      ck_assert_uint_eq(pph->ps_orig_len, payload_len);
    }
    free_cpacket(stream);
  }
}
END_TEST


START_TEST(TEST_that_a_packed_stream_buffer_with_single_packet_with_bad_ns_field_sets_correct_flags)
{
  static const size_t payload_len = 200;
  static const uint32_t time_s = 34567;
  static const uint32_t time_ns = SC_NS_IN_S;
  static const uint num_iovs_limit = 1;
  struct sc_cpacket_ts state = {.has_fcs=false,
                                .check_nic_time=false,
                                .keep_cpacket_footer=false,
                                .bytes_to_remove_from_footer=sizeof(struct cpacket_footer),
                                .is_metamako=false};
  struct packet_counts_in_iovs pkt_counts = {.packet_counts = {1}};
  uint num_iovs;
  for( num_iovs = 1; num_iovs <= num_iovs_limit; ++num_iovs ) {
    pkt_counts.number_of_iovs = num_iovs;
    struct sc_packet* stream = generate_packed_stream_cpackets(
                                    payload_len, pkt_counts, time_s, time_ns,
                                    state.has_fcs, GOOD_PS_TS_FLAGS, NULL);
    process_packed_stream_packet(stream, &state);
    unsigned iovi;
    for( iovi = 0; iovi < num_iovs; ++iovi ) {
      struct sc_packed_packet* pph = stream->iov[iovi].iov_base;
      ck_assert_int_eq(pph->ps_ts_sec, 0);
      ck_assert_int_eq(pph->ps_ts_nsec, 0);
      ck_assert(!(pph->ps_flags & SC_PS_FLAG_CLOCK_SET));
      ck_assert(!(pph->ps_flags & SC_PS_FLAG_CLOCK_IN_SYNC));
      ck_assert_uint_eq(pph->ps_cap_len, payload_len);
      ck_assert_uint_eq(pph->ps_orig_len, payload_len);
    }
    free_cpacket(stream);
  }
}
END_TEST


START_TEST(TEST_that_update_time_sets_the_right_flags_when_it_has_a_bad_ns_field) {
  static const size_t short_and_aligned = 64;
  static const uint32_t time_s = 34567;
  static const uint32_t time_ns = SC_NS_IN_S;
  static const bool has_fcs = true;
  struct sc_packet* packet = generate_cpacket(short_and_aligned, time_s,
                                              time_ns, has_fcs, NULL);
  struct sc_cpacket_ts state = {.has_fcs=true,
                                .check_nic_time=false,
                                .keep_cpacket_footer=false,
                                .bytes_to_remove_from_footer=sizeof(struct cpacket_footer),
                                .is_metamako=false};
  uint32_t original_time_s = packet->ts_sec;
  uint32_t original_time_ns = packet->ts_nsec;
  ck_assert(!process_packet(packet, &state));
  ck_assert_int_eq(packet->ts_sec, original_time_s);
  ck_assert_int_eq(packet->ts_nsec, original_time_ns);
  free_cpacket(packet);
}
END_TEST


/* TLV extensions tests ---------------------------------------------------- */
/* single_tlv_ext_len()  */
#define TEL_SSW TEST_SINGLE_TLV_EXT_LEN(single_tlv, single_word, with_fcs)
START_TEST(TEL_SSW) {
  static const uint32_t time_s = 56789;
  static const uint32_t time_ns = 12345;
  static const size_t shortish = 93;
  static const bool has_fcs = true;
  struct sc_packet *packet = generate_cpacket(shortish, time_s,
                                              time_ns, has_fcs,
                                              &tlv_single_ext_single_word);
  struct sc_cpacket_ts state = {
    .has_fcs = has_fcs,
    .check_nic_time = false,
    .keep_cpacket_footer = false,
    .bytes_to_remove_from_footer = sizeof(struct cpacket_footer),
    .is_metamako = true
  };
  int res_len = single_tlv_ext_len(&state, packet);
  ck_assert_int_eq(tlv_single_ext_single_word.len, res_len);
  free_cpacket(packet);
}
END_TEST

#define TEL_SSO TEST_SINGLE_TLV_EXT_LEN(single_tlv, single_word, without_fcs)
START_TEST(TEL_SSO) {
  static const uint32_t time_s = 56789;
  static const uint32_t time_ns = 12345;
  static const size_t shortish = 93;
  static const bool has_fcs = false;
  struct sc_packet *packet = generate_cpacket(shortish, time_s,
                                              time_ns, has_fcs,
                                              &tlv_single_ext_single_word);
  struct sc_cpacket_ts state = {
    .has_fcs = has_fcs,
    .check_nic_time = false,
    .keep_cpacket_footer = false,
    .bytes_to_remove_from_footer = sizeof(struct cpacket_footer),
    .is_metamako = true
  };
  int res_len = single_tlv_ext_len(&state, packet);
  ck_assert_int_eq(tlv_single_ext_single_word.len, res_len);
  free_cpacket(packet);
}
END_TEST

#define TEL_SMW TEST_SINGLE_TLV_EXT_LEN(single_tlv, multi_word, with_fcs)
START_TEST(TEL_SMW) {
  static const uint32_t time_s = 56789;
  static const uint32_t time_ns = 12345;
  static const size_t shortish = 93;
  static const bool has_fcs = true;
  struct sc_packet *packet = generate_cpacket(shortish, time_s,
                                              time_ns, has_fcs,
                                              &tlv_single_ext_multi_word);
  struct sc_cpacket_ts state = {
    .has_fcs = has_fcs,
    .check_nic_time = false,
    .keep_cpacket_footer = false,
    .bytes_to_remove_from_footer = sizeof(struct cpacket_footer),
    .is_metamako = true
  };
  int res_len = single_tlv_ext_len(&state, packet);
  ck_assert_int_eq(tlv_single_ext_multi_word.len, res_len);
  free_cpacket(packet);
}
END_TEST

#define TEL_MSW TEST_SINGLE_TLV_EXT_LEN(multi_tlv, single_word, with_fcs)
START_TEST(TEL_MSW) {
  static const uint32_t time_s = 56789;
  static const uint32_t time_ns = 12345;
  static const size_t shortish = 93;
  static const bool has_fcs = true;
  struct sc_packet *packet = generate_cpacket(shortish, time_s,
                                              time_ns, has_fcs,
                                              &tlv_multi_ext_single_word);
  struct sc_cpacket_ts state = {
    .has_fcs = has_fcs,
    .check_nic_time = false,
    .keep_cpacket_footer = false,
    .bytes_to_remove_from_footer = sizeof(struct cpacket_footer),
    .is_metamako = true
  };
  int res_len = single_tlv_ext_len(&state, packet);
  ck_assert_int_eq(tlv_multi_ext_single_word.len, res_len);
  free_cpacket(packet);
}
END_TEST

#define TEL_ESW TEST_SINGLE_TLV_EXT_LEN(secondary_tlv, single_word, with_fcs)
START_TEST(TEL_ESW) {
  static const uint32_t time_s = 56789;
  static const uint32_t time_ns = 12345;
  static const size_t shortish = 93;
  static const bool has_fcs = false;
  struct sc_packet *packet = generate_cpacket(shortish, time_s,
                                              time_ns, has_fcs,
                                              &tlv_secondary_ext);
  struct sc_cpacket_ts state = {
    .has_fcs = has_fcs,
    .check_nic_time = false,
    .keep_cpacket_footer = false,
    .bytes_to_remove_from_footer = sizeof(struct cpacket_footer),
    .is_metamako = true
  };
  int res_len = single_tlv_ext_len(&state, packet);
  ck_assert_int_eq(tlv_secondary_ext.len, res_len);
  free_cpacket(packet);
}
END_TEST

#define TEZ_NF TEST_SINGLE_TLV_EXT_LEN_ZERO(no_final)
START_TEST(TEZ_NF) {
  static const uint32_t time_s = 56789;
  static const uint32_t time_ns = 12345;
  static const size_t shortish = 93;
  static const bool has_fcs = false;
  struct sc_packet *packet = generate_cpacket(shortish, time_s,
                                              time_ns, has_fcs,
                                              &tlv_ext_no_final);
  struct sc_cpacket_ts state = {
    .has_fcs = has_fcs,
    .check_nic_time = false,
    .keep_cpacket_footer = false,
    .bytes_to_remove_from_footer = sizeof(struct cpacket_footer),
    .is_metamako = true
  };
  int res_len = single_tlv_ext_len(&state, packet);
  ck_assert_int_eq(0, res_len);
  free_cpacket(packet);
}
END_TEST


/* process_single_packet() */
#define SPT_IN TEST_SINGLE_PROCESS_TLV(ignores_tlv, no_tlv_ext)
START_TEST(SPT_IN) {
  static const uint32_t time_s = 56789;
  static const uint32_t time_ns = 12345;
  static const size_t shortish = 93;
  static const bool has_fcs = false;
  struct sc_packet *packet = generate_cpacket(shortish, time_s,
                                              time_ns, has_fcs,
                                              &tlv_ext_not_present);
  struct sc_cpacket_ts state = {
    .has_fcs = has_fcs,
    .check_nic_time = false,
    .keep_cpacket_footer = false,
    .bytes_to_remove_from_footer = sizeof(struct cpacket_footer),
    .is_metamako = true
  };

  int frame_len = packet->frame_len - sizeof(struct cpacket_footer);
  process_single_packet(packet, &state);
  ck_assert_int_eq(frame_len, packet->frame_len);
  free_cpacket(packet);
}
END_TEST

#define SPT_SW TEST_SINGLE_PROCESS_TLV(shortens, with_fcs)
START_TEST(SPT_SW) {
  static const uint32_t time_s = 56789;
  static const uint32_t time_ns = 12345;
  static const size_t shortish = 93;
  static const bool has_fcs = true;
  struct sc_packet *packet = generate_cpacket(shortish, time_s,
                                              time_ns, has_fcs,
                                              &tlv_single_ext_single_word);
  struct sc_cpacket_ts state = {
    .has_fcs = has_fcs,
    .check_nic_time = false,
    .keep_cpacket_footer = false,
    .bytes_to_remove_from_footer = sizeof(struct cpacket_footer),
    .is_metamako = true
  };
  int frame_len = packet->frame_len - sizeof(struct cpacket_footer) -
                  tlv_single_ext_single_word.len;
  process_single_packet(packet, &state);
  ck_assert_int_eq(frame_len, packet->frame_len);
  free_cpacket(packet);
}
END_TEST

#define SPT_SO TEST_SINGLE_PROCESS_TLV(shortens, without_fcs)
START_TEST(SPT_SO) {
  static const uint32_t time_s = 56789;
  static const uint32_t time_ns = 12345;
  static const size_t shortish = 93;
  static const bool has_fcs = false;
  struct sc_packet *packet = generate_cpacket(shortish, time_s,
                                              time_ns, has_fcs,
                                              &tlv_single_ext_single_word);
  struct sc_cpacket_ts state = {
    .has_fcs = has_fcs,
    .check_nic_time = false,
    .keep_cpacket_footer = false,
    .bytes_to_remove_from_footer = sizeof(struct cpacket_footer),
    .is_metamako = true
  };
  process_single_packet(packet, &state);
  ck_assert_int_eq(shortish, packet->frame_len);
  free_cpacket(packet);
}
END_TEST

#define SPT_FI TEST_SINGLE_PROCESS_TLV(sets_flags_and_shortens, with_invalid_tlv_fcs)
START_TEST(SPT_FI) {
  static const uint32_t time_s = 56789;
  static const uint32_t time_ns = 12345;
  static const size_t shortish = 93;
  static const bool has_fcs = true;
  struct sc_packet *packet = generate_cpacket(shortish, time_s,
                                              time_ns, has_fcs,
                                              &tlv_ext_no_valid_fcs);
  struct sc_cpacket_ts state = {
    .has_fcs = has_fcs,
    .check_nic_time = false,
    .keep_cpacket_footer = false,
    .bytes_to_remove_from_footer = sizeof(struct cpacket_footer),
    .is_metamako = true
  };
  int frame_len = packet->frame_len - sizeof(struct cpacket_footer) -
                  tlv_ext_no_valid_fcs.len;
  process_single_packet(packet, &state);
  ck_assert(packet->flags & SC_CRC_ERROR);
  ck_assert_int_eq(frame_len, packet->frame_len);
  free_cpacket(packet);
}
END_TEST


/* process_packed_stream_packet() with packed_tlv_ext_len()  */
#define PPT_SW TEST_PACKED_PROCESS_TLV(shortens, with_fcs)
START_TEST(PPT_SW) {
  static const size_t payload_len = 351;
  static const uint32_t time_s = 1;
  static const uint32_t time_ns = 2;
  static const uint num_iovs_limit = 2;
  struct sc_cpacket_ts state = {
    .has_fcs = true,
    .keep_cpacket_footer = false,
    .bytes_to_remove_from_footer = sizeof(struct cpacket_footer),
    .is_metamako = true
  };
  struct packet_counts_in_iovs pkt_counts = {.packet_counts = {1, 1}};
  uint num_iovs;
  for( num_iovs = 1; num_iovs <= num_iovs_limit; ++num_iovs ) {
    pkt_counts.number_of_iovs = num_iovs;
    struct sc_packet* stream = generate_packed_stream_cpackets(
                                    payload_len, pkt_counts,
                                    time_s, time_ns, state.has_fcs,
                                    GOOD_PS_TS_FLAGS,
                                    &tlv_single_ext_single_word);
    process_packed_stream_packet(stream, &state);
    unsigned iovi;
    for( iovi = 0; iovi < num_iovs; ++iovi ) {
      struct sc_packed_packet* pph = stream->iov[iovi].iov_base;
      int tlv_len = tlv_single_ext_single_word.len;
      ck_assert_int_eq(pph->ps_cap_len, payload_len -
                       sizeof(struct cpacket_footer) - tlv_len);
    }
    free_cpacket(stream);
  }
}
END_TEST

#define PPT_SO TEST_PACKED_PROCESS_TLV(shortens, without_fcs)
START_TEST(PPT_SO) {
  static const size_t payload_len = 351;
  static const uint32_t time_s = 1;
  static const uint32_t time_ns = 2;
  static const uint num_iovs_limit = 2;
  struct sc_cpacket_ts state = {
    .has_fcs = false,
    .keep_cpacket_footer = false,
    .bytes_to_remove_from_footer = sizeof(struct cpacket_footer),
    .is_metamako = true
  };
  struct packet_counts_in_iovs pkt_counts = {.packet_counts = {1, 1}};
  uint num_iovs;
  for( num_iovs = 1; num_iovs <= num_iovs_limit; ++num_iovs ) {
    pkt_counts.number_of_iovs = num_iovs;
    struct sc_packet* stream = generate_packed_stream_cpackets(
                                    payload_len, pkt_counts,
                                    time_s, time_ns, state.has_fcs,
                                    GOOD_PS_TS_FLAGS,
                                    &tlv_single_ext_single_word);
    process_packed_stream_packet(stream, &state);
    unsigned iovi;
    for( iovi = 0; iovi < num_iovs; ++iovi ) {
      struct sc_packed_packet* pph = stream->iov[iovi].iov_base;
      int tlv_len = tlv_single_ext_single_word.len;
      ck_assert_int_eq(pph->ps_cap_len, payload_len -
                       sizeof(struct cpacket_footer) - tlv_len);
    }
    free_cpacket(stream);
  }
}
END_TEST

#define PPT_SI TEST_PACKED_PROCESS_TLV(sets_flags_and_shortens, with_invalid_tlv_fcs)
START_TEST(PPT_SI) {
  static const size_t payload_len = 351;
  static const uint32_t time_s = 1;
  static const uint32_t time_ns = 2;
  static const uint num_iovs_limit = 2;
  struct sc_cpacket_ts state = {
    .has_fcs = true,
    .keep_cpacket_footer = false,
    .bytes_to_remove_from_footer = sizeof(struct cpacket_footer),
    .is_metamako = true
  };
  struct packet_counts_in_iovs pkt_counts = {.packet_counts = {1, 1}};
  uint num_iovs;
  for( num_iovs = 1; num_iovs <= num_iovs_limit; ++num_iovs ) {
    pkt_counts.number_of_iovs = num_iovs;
    struct sc_packet* stream = generate_packed_stream_cpackets(
                                    payload_len, pkt_counts,
                                    time_s, time_ns, state.has_fcs,
                                    GOOD_PS_TS_FLAGS,
                                    &tlv_ext_no_valid_fcs);
    process_packed_stream_packet(stream, &state);
    unsigned iovi;
    for( iovi = 0; iovi < num_iovs; ++iovi ) {
      struct sc_packed_packet* pph = stream->iov[iovi].iov_base;
      int tlv_len = tlv_single_ext_single_word.len;
      ck_assert(pph->ps_flags & SC_PS_FLAG_BAD_FCS);
      ck_assert_int_eq(pph->ps_cap_len, payload_len -
                       sizeof(struct cpacket_footer) - tlv_len);
    }
    free_cpacket(stream);
  }
}
END_TEST

/* set up and run --------------------------------------------------------- */

int main(int argc, const char *argv[]) {
  int number_failed;
  Suite *s = suite_create("sc_cpacket_ts_node");
  TCase *tc_footer = tcase_create("CPacket Fetch Footer");
  tcase_add_test(tc_footer,
                 TEST_that_given_a_packet_with_aligned_footer_fetch_footer_returns_a_pointer_to_the_footer);
  tcase_add_test(tc_footer,
                 TEST_that_given_a_packet_with_aligned_footer_with_no_fcs_fetch_footer_returns_a_pointer_to_the_footer);
  tcase_add_test(tc_footer,
                 TEST_that_given_a_packet_with_nonaligned_footer_fetch_footer_returns_a_pointer_to_the_footer);
  tcase_add_test(tc_footer,
                 TEST_that_given_a_packet_with_nonaligned_footer_with_no_fcs_fetch_footer_returns_a_pointer_to_the_footer);
  tcase_add_test(tc_footer,
                 TEST_that_given_a_two_iovec_packet_with_split_footer_fetch_footer_a_pointer_to_the_footer);
  tcase_add_test(tc_footer,
                 TEST_that_given_a_three_iovec_packet_with_split_footer_fetch_footer_a_pointer_to_the_footer);
  tcase_add_test(tc_footer,
                 TEST_that_given_a_three_iovec_packet_with_split_footer_and_no_fcs_fetch_footer_a_pointer_to_the_footer);
  tcase_add_test(tc_footer,
                 TEST_that_given_a_three_iovec_packet_with_the_footer_in_the_penultimate_iovec_and_no_fcs_fetch_footer_returns_a_pointer_to_the_footer);
  suite_add_tcase(s, tc_footer);

  TCase *tc_packet = tcase_create("CPacket sc_packet");
  tcase_add_test(tc_packet,
                 TEST_that_update_time_updates_the_sc_packet_time_fields);
  tcase_add_test(tc_packet,
                 TEST_that_give_a_single_iovec_packet_with_fcs_remove_footer_removes_exactly_the_cpacket_footer);
  tcase_add_test(tc_packet,
                 TEST_that_give_a_single_iovec_packet_without_fcs_remove_footer_removes_exactly_the_cpacket_footer);
  tcase_add_test(tc_packet,
                 TEST_that_process_packet_returns_false_when_there_is_no_next_single_packet);
  tcase_add_test(tc_packet,
                 TEST_that_process_packet_returns_true_when_there_is_a_next_single_packet);
  tcase_add_test(tc_packet,
                 TEST_that_process_packet_returns_false_when_there_is_no_next_stream_packet);
  tcase_add_test(tc_packet,
                 TEST_that_process_packet_returns_true_when_there_is_a_next_stream_packet);
  suite_add_tcase(s, tc_packet);

  TCase *tc_packed_stream = tcase_create("CPacket sc_packed_stream");
  tcase_add_test(tc_packed_stream,
                 TEST_that_given_a_packed_stream_containing_a_single_packet_process_stream_leaves_the_sc_packet_unchanged);
  tcase_add_test(tc_packed_stream,
                 TEST_that_given_a_packed_stream_containing_a_single_packet_process_stream_shortens_the_contained_packet);
  tcase_add_test(tc_packed_stream,
                 TEST_that_given_a_packed_stream_containing_a_single_packet_process_stream_updates_the_time_in_the_contained_packet);
  tcase_add_test(tc_packed_stream,
                 TEST_that_given_a_packed_stream_containing_three_packets_process_stream_updates_the_times_and_removes_the_footers_for_all_the_contained_packets);
  tcase_add_test(tc_packed_stream,
                 TEST_that_given_a_packed_stream_containing_a_single_packet_process_stream_does_not_shortens_the_contained_packet_for_keep_footer_mode);
  suite_add_tcase(s, tc_packed_stream);

  TCase *tc_runt_packet = tcase_create("CPacket packed stream runt packets");
  tcase_add_test(tc_runt_packet,
                 TEST_that_a_packed_stream_buffer_with_single_runt_packet_has_correct_flags_set_without_fcs);
  tcase_add_test(tc_runt_packet,
                 TEST_that_a_packed_stream_buffer_with_single_runt_packet_has_correct_flags_set_with_fcs);
  suite_add_tcase(s, tc_runt_packet);

  TCase *tc_timestamp_difference = tcase_create("Cpacket invalid timestamp checks");
  tcase_add_test(tc_timestamp_difference,
                 TEST_timestamp_difference_within_threshold_works);
  tcase_add_test(tc_timestamp_difference,
                 TEST_timestamp_difference_outside_of_threshold_fails);
  tcase_add_test(tc_timestamp_difference,
                 TEST_timestamp_difference_within_threshold_but_without_clock_set_fails);
  tcase_add_test(tc_timestamp_difference,
                 TEST_that_a_packed_stream_buffer_with_single_packet_with_bad_ns_field_sets_correct_flags);
  tcase_add_test(tc_timestamp_difference,
                 TEST_that_update_time_sets_the_right_flags_when_it_has_a_bad_ns_field);
  suite_add_tcase(s, tc_timestamp_difference);

  TCase *tc_tlv_single = tcase_create("CPacket sc_packet Metamako TLVs");
  tcase_add_test(tc_tlv_single,
                 TEST_SINGLE_TLV_EXT_LEN(single_tlv, single_word, with_fcs));
  tcase_add_test(tc_tlv_single,
                 TEST_SINGLE_TLV_EXT_LEN(single_tlv, single_word, without_fcs));
  tcase_add_test(tc_tlv_single,
                 TEST_SINGLE_TLV_EXT_LEN(single_tlv, multi_word, with_fcs));
  tcase_add_test(tc_tlv_single,
                 TEST_SINGLE_TLV_EXT_LEN(multi_tlv, single_word, with_fcs));
  tcase_add_test(tc_tlv_single,
                 TEST_SINGLE_TLV_EXT_LEN(secondary_tlv, single_word, with_fcs));
  tcase_add_test(tc_tlv_single,
                 TEST_SINGLE_TLV_EXT_LEN_ZERO(no_final));
  tcase_add_test(tc_tlv_single,
                 TEST_SINGLE_PROCESS_TLV(ignores_tlv, no_tlv_ext));
  tcase_add_test(tc_tlv_single,
                 TEST_SINGLE_PROCESS_TLV(shortens, with_fcs));
  tcase_add_test(tc_tlv_single,
                 TEST_SINGLE_PROCESS_TLV(shortens, without_fcs));
  tcase_add_test(tc_tlv_single,
                 TEST_SINGLE_PROCESS_TLV(sets_flags_and_shortens,
                                         with_invalid_tlv_fcs));
  suite_add_tcase(s, tc_tlv_single);

  TCase *tc_tlv_packed = tcase_create("CPacket sc_packed_stream Metamako TLVs");
  tcase_add_test(tc_tlv_packed,
                 TEST_PACKED_PROCESS_TLV(shortens, with_fcs));
  tcase_add_test(tc_tlv_packed,
                 TEST_PACKED_PROCESS_TLV(shortens, without_fcs));
  tcase_add_test(tc_tlv_packed,
                 TEST_PACKED_PROCESS_TLV(sets_flags_and_shortens,
                                         with_invalid_tlv_fcs));
  suite_add_tcase(s, tc_tlv_packed);


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
