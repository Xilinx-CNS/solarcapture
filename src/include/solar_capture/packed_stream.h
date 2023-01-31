/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \file
 * \brief sc_packed_packet: The packed-stream encapsulation.
 */

#ifndef __SOLAR_CAPTURE_PACKED_STREAM__H__
#define __SOLAR_CAPTURE_PACKED_STREAM__H__


/** Mask for ::sc_packed_packet flags, clock set */
#define SC_PS_FLAG_CLOCK_SET        0x1
/** Mask for ::sc_packed_packet flags, clock in sync */
#define SC_PS_FLAG_CLOCK_IN_SYNC    0x2
/** Mask for ::sc_packed_packet flags, bad FCS */
#define SC_PS_FLAG_BAD_FCS          0x4
/** Mask for ::sc_packed_packet flags, bad layer 4 checksum */
#define SC_PS_FLAG_BAD_L4_CSUM      0x8
/** Mask for ::sc_packed_packet flags, bad layer 3 checksum */
#define SC_PS_FLAG_BAD_L3_CSUM      0x10


/**
 * \brief A packed-stream packet.
 *
 * Packed-stream is an encapsulation that encodes multiple packets or other
 * data in a buffer.  Each packet is represented by an ::sc_packed_packet
 * header which gives information about the packet stored and the offset to
 * the next packet in the buffer.
 *
 * The offset of the last packet in the buffer must generate a pointer that
 * lies beyond the end of the buffer containing packed-stream data.
 *
 * The following example code shows how to iterate over the set of packets
 * stored in an ::sc_packet that contains packed-stream packets:
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * void do_something_to_each(struct sc_packet* pkt)
 * {
 *   struct sc_packed_packet* ps_pkt = sc_packet_packed_first(pkt);
 *   struct sc_packed_packet* ps_end = sc_packet_packed_end(pkt);
 *   for( ; ps_pkt < ps_end; ps_pkt = sc_packed_packet_next(ps_pkt) )
 *     do_something(sc_packed_packet_payload(ps_pkt), ps_pkt->ps_cap_len);
 * }
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
struct sc_packed_packet {
  /** Offset of next packet from start of this struct. */
  uint16_t  ps_next_offset;
  /** Offset of packet payload from start of this struct. */
  uint8_t   ps_pkt_start_offset;
  /** SC_PS_FLAG_* flags. */
  uint8_t   ps_flags;
  /** Number of bytes of packet payload stored. */
  uint16_t  ps_cap_len;
  /** Original length of the frame. */
  uint16_t  ps_orig_len;
  /** Timestamp (seconds). */
  uint32_t  ps_ts_sec;
  /** Timestamp (nanoseconds). */
  uint32_t  ps_ts_nsec;
} __attribute__((packed));
/*
 * Doxygen might output an error that references the line above, saying
 * "Member __attribute__((packed)) (function) of file packed_stream.h is not
 * documented". This error can be ignored.
 */


/**
 * \brief Iterate from one packed-stream header to the next.
 *
 * \param ps_pkt  A packed-stream packet header
 *
 * \return The next packed-stream packet in the buffer.
 */
static inline struct sc_packed_packet*
  sc_packed_packet_next(const struct sc_packed_packet* ps_pkt)
{
  return (struct sc_packed_packet*) ((char*) ps_pkt + ps_pkt->ps_next_offset);
}


/**
 * \brief Return a pointer to the packet payload.
 *
 * \param ps_pkt  A packed-stream packet header
 *
 * \return The start of the packet payload.
 */
static inline void*
  sc_packed_packet_payload(const struct sc_packed_packet* ps_pkt)
{
  return (char*) ps_pkt + ps_pkt->ps_pkt_start_offset;
}


/**
 * \brief Return the first packet header in a packed-stream buffer.
 *
 * \param pkt  An ::sc_packet containing packed-stream encoded packets
 *
 * \return The ::sc_packed_packet header for the first packet.
 */
static inline struct sc_packed_packet*
  sc_packet_packed_first(struct sc_packet* pkt)
{
  return (struct sc_packed_packet*) pkt->iov[0].iov_base;
}


/**
 * \brief Return a pointer to the end of a packed-stream buffer.
 *
 * \param pkt  An ::sc_packet containing packed-stream encoded packets
 *
 * \return A pointer to the end of the buffer.  This can be compared with
 *         the pointer returned by sc_packed_packet_next() to determine
 *         whether the last packet has been consumed.
 */
static inline struct sc_packed_packet*
  sc_packet_packed_end(struct sc_packet* pkt)
{
  return ( (struct sc_packed_packet*)
           ((uint8_t*) pkt->iov[0].iov_base + pkt->iov[0].iov_len) );
}


static inline struct sc_packed_packet*
  sc_packet_iov_packed_first(struct sc_packet* pkt, unsigned iov_i)
{
  assert( iov_i < (unsigned) pkt->iovlen );
  return (struct sc_packed_packet*) pkt->iov[iov_i].iov_base;
}


static inline struct sc_packed_packet*
  sc_packet_iov_packed_end(struct sc_packet* pkt, unsigned iov_i)
{
  assert( iov_i < (unsigned) pkt->iovlen );
  return ( (struct sc_packed_packet*)
           ((uint8_t*) pkt->iov[iov_i].iov_base + pkt->iov[iov_i].iov_len) );
}


#endif /* __SOLAR_CAPTURE_PACKED_STREAM__H__ */
/** @} */
