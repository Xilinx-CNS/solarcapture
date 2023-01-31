/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \node{sc_cpacket_ts}
 *
 * \brief Node to replace card arrival timestamp with CPacket footer timestamp.
 *
 * \nodedetails
 * Node to replace card arrival timestamp with CPacket footer timestamp.
 *
 * \nodeargs
 * Argument           | Optional? | Default   | Type           | Description
 * ------------------ | --------- | --------- | -------------- | ----------------------------------------------------------------------------------------------------
 * has_fcs            | No        | N/A       | ::SC_PARAM_INT | Whether the input packets still have their trailing frame checksums
 * keep_cpacket_footer| Yes       | 0(false)  | ::SC_PARAM_INT | Whether the CPacket footer information should be kept
 * is_metamako        | Yes       | 0(false)  | ::SC_PARAM_INT | Whether the CPacket footer has Arista-Metamako TLV extensions
 *
 * \namedinputlinks
 * None
 *
 * \outputlinks
 * Link           | Description
 * -------------- | -----------------------------------
 *  ""            | Packets with timestamps set from CPacket footer, (and optionally footer stripped off).
 *
 *
 *
 * \internal
 *
 * \nodeargs
 * Argument                  | Optional? | Default   | Type           | Description
 * ------------------------- | --------- | --------- | -------------- | ----------------------------------------------------------------------------------------------------
 * max_diff_from_nic_time_ms | Yes       | None      | ::SC_PARAM_INT | The max difference that cpacket will allow from nic time before unsetting SC_PS_CLOCK_SET (packed stream only).
 *
 * \cond NODOC
 */

#include "cpacket_offsets.h"

#include "solar_capture/ext_packet.h"
#include "sc_internal/packed_stream.h"
#include "sc_internal.h"

#include <stdint.h>
#include <errno.h>


struct sc_cpacket_ts {
  const struct sc_node_link* next_hop;

  size_t                     bytes_to_remove_from_footer;
  uint64_t                   max_diff_from_nic_time_ns;

  /* config parameters */
  bool                       check_nic_time;
  bool                       has_fcs;
  bool                       keep_cpacket_footer;
  bool                       is_metamako;
};


/**
 * \param[in/out]  buffer  A pointer to a struct cpacket_data_fcs.
 * \param[in]  packet  The packet to fetch a CPacket footer from.
 * \param[in]  has_fcs A 'bool': Is the FCS still at the end of the packet?
 *
 */
static inline void fetch_cpacket_data(struct cpacket_data* buffer,
                                      struct sc_packet* packet,
                                      bool has_fcs)
{
  if( has_fcs ) {
    struct cpacket_footer_with_fcs initial_buffer;
    sc_iovec_copy_from_end(&initial_buffer, packet->iov, packet->iovlen,
        sizeof(initial_buffer));
    *buffer = initial_buffer.data;
  }
  else {
    struct cpacket_footer initial_buffer;
    sc_iovec_copy_from_end(&initial_buffer, packet->iov, packet->iovlen,
        sizeof(initial_buffer));
    *buffer = initial_buffer.data;
  }
}


static inline void update_time(struct sc_packet* packet,
                               struct cpacket_time* time)
{
  packet->ts_sec = ntohl(time->s);
  packet->ts_nsec = ntohl(time->ns);
}


static inline void remove_footer(struct sc_packet* packet, size_t bytes_to_remove_from_footer)
{
  sc_iovec_trim_end(packet->iov, &packet->iovlen, bytes_to_remove_from_footer);
  packet->frame_len -= bytes_to_remove_from_footer;
}


/* In metamako case cpacket trailer might contain TLVs:
 * [ PKT DATA | OLD FCS | non or more TLVs | CPACKET INFO | CPACKET FCS ]
 *
 * CPACKET INFO:
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +---------------------------------------------------------------+
 * |                            Seconds                            |
 * +---------------------------------------------------------------+
 * |                          Nanoseconds                          |
 * +---------------------------------------------------------------+
 * |  Reserved |X|V|            DeviceID           |     PortID    |
 * +---------------------------------------------------------------+
 *
 * X - eXtensions present (1/0)
 * V - original FCS Valid (1/0)
 *
 * Primary trailer extension header:
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +---------------------------------------------------------------+
 * |                      Data                     |Len|F|   Tag   |
 * +---------------------------------------------------------------+
 *
 * Tag - type of the Data, special value is 0x1F (secondary extension)
 * F - if this Final extension (1/0)
 * Len - the number of additional 32bit words of payload that precede
 * this header word.
 *
 * Note: zero Len is allowed, as the inline 24bits may be sufficient.
 *
 * Secondary trailer extension header:
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +---------------------------------------------------------------+
 * |                              Data                             |
 * +---------------------------------------------------------------+
 * |              Tag2             |        Len        |F|  11111  |
 * +---------------------------------------------------------------+
 *
 * Len - the number of additional 32bit words of payload that precede
 * these two words.
 */
#define METAMAKO_FLAG_TLV_PRESENT 0x2
#define METAMAKO_FLAG_FCS_VALID 0x1
#define METAMAKO_FINAL 0x20
#define METAMAKO_TAG_MASK 0x1F
#define METAMAKO_TAG_SECONDARY 0x1F
#define METAMAKO_LEN_SHIFT 6
#define METAMAKO_LEN_MASK_PRIMARY 0x3
#define METAMAKO_LEN_MASK_SECONDARY 0x3FF


static inline size_t tlv_header_word_get_len(uint32_t header_word) {
  uint32_t len = header_word >> METAMAKO_LEN_SHIFT;
  if( (header_word & METAMAKO_TAG_MASK) == METAMAKO_TAG_SECONDARY )
    len = (len & METAMAKO_LEN_MASK_SECONDARY) + 1;
  else
    len = len & METAMAKO_LEN_MASK_PRIMARY;
  return len + 1;
}


/* Should be called only if METAMAKO_FLAG_TLV_PRESENT check passed */
static inline size_t packed_tlv_ext_len(const struct sc_cpacket_ts* state,
                                        const struct sc_packed_packet* pkt) {
  size_t offset = state->has_fcs ? sizeof(fcs_t) : 0;
  char* endptr = (char*) sc_packed_packet_payload(pkt) + pkt->ps_cap_len;
  uint32_t tlv_len = 0;
  uint32_t header_word;
  offset += sizeof(struct cpacket_data);
  endptr -= offset;

  while( pkt->ps_cap_len > offset + tlv_len + sizeof(header_word) ) {
    memcpy(&header_word, endptr - tlv_len - sizeof(header_word),
           sizeof(header_word));
    header_word = ntohl(header_word);
    tlv_len += tlv_header_word_get_len(header_word) * sizeof(header_word);

    if( header_word & METAMAKO_FINAL )
      return tlv_len;
  }
  return 0;
}


/* Should be called only if METAMAKO_FLAG_TLV_PRESENT check passed */
static inline size_t single_tlv_ext_len(const struct sc_cpacket_ts* state,
                                        const struct sc_packet* pkt) {
  size_t offset = state->has_fcs ? sizeof(fcs_t) : 0;
  uint32_t tlv_len = 0;
  uint32_t header_word;
  offset += sizeof(struct cpacket_data);

  while( pkt->frame_len > offset + tlv_len + sizeof(header_word) ) {
    sc_iovec_copy_from_end_offset(&header_word, pkt->iov,  pkt->iovlen,
                                  sizeof(header_word), offset + tlv_len);
    header_word = ntohl(header_word);
    tlv_len += tlv_header_word_get_len(header_word) * sizeof(header_word);

    if( header_word & METAMAKO_FINAL )
      return tlv_len;
  }
  return 0;
}


static inline struct sc_packet* process_packed_stream_packet(
    struct sc_packet* pkt, const struct sc_cpacket_ts* state)
{
  unsigned iovi;
  for( iovi = 0; pkt->iovlen > iovi; ++iovi ) {
    SC_TEST(pkt->iov[iovi].iov_len >= sizeof(struct sc_packed_packet));
    struct sc_packed_packet* ps_pkt = sc_packet_iov_packed_first(pkt, iovi);
    SC_TEST(ps_pkt->ps_orig_len == ps_pkt->ps_cap_len);
    struct cpacket_footer* cpf;
    while (ps_pkt < sc_packet_iov_packed_end(pkt, iovi)) {
      if( ps_pkt->ps_cap_len < cpacket_footer_length(state->has_fcs) ||
          (state->check_nic_time &&
           !(ps_pkt->ps_flags & SC_PS_FLAG_CLOCK_SET)) ||
          ps_pkt->ps_flags & SC_PS_FLAG_BAD_FCS ) {
        /* Packet has been truncated, previously marked invalid or has FCS error, can't trust cpacket timestamp. */
        ps_pkt->ps_flags &= ~SC_PS_FLAG_CLOCK_SET;
        ps_pkt->ps_flags &= ~SC_PS_FLAG_CLOCK_IN_SYNC;
      }
      else {
        /* Decode cpacket timestamp from footer */
        cpf = (struct cpacket_footer*)
            &(((char *) sc_packed_packet_payload(ps_pkt))[
                ps_pkt->ps_cap_len - cpacket_footer_length(state->has_fcs)]);
        uint32_t cpacket_secs = ntohl(cpf->data.time.s);
        uint32_t cpacket_nsecs = ntohl(cpf->data.time.ns);

        if( state->check_nic_time ) {
          uint64_t cpacket_nsecs_since_epoch = cpacket_secs * SC_NS_IN_S + cpacket_nsecs;
          uint64_t nic_nsecs_since_epoch = ps_pkt->ps_ts_sec * SC_NS_IN_S + ps_pkt->ps_ts_nsec;
          uint64_t abs_time_diff = cpacket_nsecs_since_epoch > nic_nsecs_since_epoch ? cpacket_nsecs_since_epoch - nic_nsecs_since_epoch : nic_nsecs_since_epoch - cpacket_nsecs_since_epoch;
          if( abs_time_diff > state->max_diff_from_nic_time_ns ) {
            /* Cpacket time is too far from NIC time, are servers synced up? */
            ps_pkt->ps_flags &= ~SC_PS_FLAG_CLOCK_SET;
            ps_pkt->ps_flags &= ~SC_PS_FLAG_CLOCK_IN_SYNC;
          }
        }

        if( cpacket_nsecs >= SC_NS_IN_S ) {
          /* This probably means we have packet corruption or some other error */
          ps_pkt->ps_flags &= ~SC_PS_FLAG_CLOCK_SET;
          ps_pkt->ps_flags &= ~SC_PS_FLAG_CLOCK_IN_SYNC;
        }
        else if( !state->check_nic_time ||
                 (ps_pkt->ps_flags & SC_PS_FLAG_CLOCK_SET &&
                  ps_pkt->ps_flags & SC_PS_FLAG_CLOCK_IN_SYNC) ) {
          /* If we're not checking against nic time then
           * we don't care whether it's correct.
           */

          /* All checks passed, update packet capture times */
          ps_pkt->ps_ts_sec = cpacket_secs;
          ps_pkt->ps_ts_nsec = cpacket_nsecs;

          /* remove footer */
          int remove_bytes = state->bytes_to_remove_from_footer;
          if( remove_bytes > 0 && state->is_metamako &&
              cpf->data.version & METAMAKO_FLAG_TLV_PRESENT ){
            remove_bytes += packed_tlv_ext_len(state, ps_pkt);
            if( !(cpf->data.version & METAMAKO_FLAG_FCS_VALID) )
              ps_pkt->ps_flags |= SC_PS_FLAG_BAD_FCS;
          }
          ps_pkt->ps_orig_len -= remove_bytes;
          ps_pkt->ps_cap_len -= remove_bytes;
        }
      }

      ps_pkt = sc_packed_packet_next(ps_pkt);
    }
  }
  return pkt->next;
}


static inline struct sc_packet* process_single_packet(
    struct sc_packet* pkt, const struct sc_cpacket_ts* state)
{
  if( pkt->flags & SC_CRC_ERROR ) {
    /* Can't trust cpacket timestamps from packets with FCS errors */
    return pkt->next;
  }

  struct cpacket_data buffer;
  fetch_cpacket_data(&buffer, pkt, state->has_fcs);
  uint32_t cpacket_ns = ntohl(buffer.time.ns);
  uint32_t cpacket_s = ntohl(buffer.time.s);

  if( state->check_nic_time ) {
    uint64_t buf_ns = cpacket_s * SC_NS_IN_S + cpacket_ns;
    uint64_t nic_ns = pkt->ts_sec * SC_NS_IN_S + pkt->ts_nsec;
    uint64_t abs_time_diff = buf_ns > nic_ns ? buf_ns - nic_ns : nic_ns - buf_ns;
    if( abs_time_diff > state->max_diff_from_nic_time_ns ) {
      /* Cpacket time is too far from NIC time, are servers synced up? */
      return pkt->next;
    }
  }

  if( cpacket_ns >= SC_NS_IN_S ) {
    /* This probably means we have packet corruption or some other error */
    return pkt->next;
  }

  /* All checks passed, update packet capture times */
  update_time(pkt, &buffer.time);

  int remove_bytes = state->bytes_to_remove_from_footer;
  if( remove_bytes > 0 ) {
    if( state->is_metamako && (buffer.version & METAMAKO_FLAG_TLV_PRESENT) ) {
      remove_bytes += single_tlv_ext_len(state, pkt);
      if( !(buffer.version & METAMAKO_FLAG_FCS_VALID) )
        pkt->flags |= SC_CRC_ERROR;
    }
    remove_footer(pkt, remove_bytes);
  }
  return pkt->next;
}


static inline struct sc_packet* process_packet(
    struct sc_packet* pkt, const struct sc_cpacket_ts* state)
{
  if( pkt->flags & SC_PACKED_STREAM )
    return process_packed_stream_packet(pkt, state);
  else
    return process_single_packet(pkt, state);
}


static void sc_cpacket_ts_pkts(struct sc_node* node,
                               struct sc_packet_list* pl)
{
  const struct sc_cpacket_ts* state = node->nd_private;
  struct sc_packet* pkt = pl->head;
  while ((pkt = process_packet(pkt, state)))
    ;
  sc_forward_list2(state->next_hop, pl);
}


static void sc_cpacket_ts_end_of_stream(struct sc_node* node)
{
  const struct sc_cpacket_ts* state = node->nd_private;
  sc_node_link_end_of_stream2(state->next_hop);
}


static int sc_cpacket_ts_prep(struct sc_node* node,
                              const struct sc_node_link* const * links,
                              int n_links)
{
  struct sc_cpacket_ts* state = node->nd_private;
  state->next_hop = sc_node_prep_get_link_or_free(node, "");
  return sc_node_prep_check_links(node);
}


static int sc_cpacket_ts_init(struct sc_node* node, const struct sc_attr* attr,
                              const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if (nt == NULL) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_prep_fn = sc_cpacket_ts_prep;
    nt->nt_pkts_fn = sc_cpacket_ts_pkts;
    nt->nt_end_of_stream_fn = sc_cpacket_ts_end_of_stream;
  }
  node->nd_type = nt;

  struct sc_cpacket_ts* state = sc_thread_calloc(sc_node_get_thread(node),
                                                 sizeof(*state));

  uint64_t max_diff_from_nic_time_ms;
  if( sc_barg(&state->has_fcs, node, "has_fcs", false)                                               < 0 ||
      sc_barg(&state->keep_cpacket_footer, node, "keep_cpacket_footer", false)                       < 0 ||
      sc_barg(&state->is_metamako, node, "is_metamako", false)                                       < 0 ||
      sc_iarg(&max_diff_from_nic_time_ms, node, "max_diff_from_nic_time_ms", INT64_MAX)              < 0 )
    return -1;

  state->check_nic_time = (max_diff_from_nic_time_ms != INT64_MAX);
  state->max_diff_from_nic_time_ns = state->check_nic_time ? max_diff_from_nic_time_ms * SC_NS_IN_MS : INT64_MAX;

  /* If the packet arrived with an FCS it should leave with one,
   * If it arrived without, it should leave without.
   * This means that if we are removing the footer we should always strip
   * the same amount off because the cpacket format is
   *
   * [ PKT DATA | OLD FCS | CPACKET INFO | CPACKET FCS ]
   */
  state->bytes_to_remove_from_footer = state->keep_cpacket_footer ? 0 : sizeof(struct cpacket_footer);

  node->nd_private = state;
  return 0;
}


const struct sc_node_factory sc_cpacket_ts_sc_node_factory = {
  .nf_node_api_ver = SC_API_VER,
  .nf_name = "sc_cpacket_ts",
  .nf_source_file = __FILE__,
  .nf_init_fn = sc_cpacket_ts_init,
};

/** \endcond NODOC */
