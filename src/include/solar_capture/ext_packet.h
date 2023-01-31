/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \file
 * \brief sc_packet: The representation of a packet or other data.
 */

#ifndef __SOLAR_CAPTURE_EXT_PACKET_H__
#define __SOLAR_CAPTURE_EXT_PACKET_H__

#include <stdlib.h>
#include <stdint.h>
#include <sys/uio.h>


#if defined(__x86_64__) || defined(__i386__)
# define SC_CACHE_LINE_SIZE   64
#elif defined(__PPC__)
# define SC_CACHE_LINE_SIZE   128
#else
# error "Need to define SC_CACHE_LINE_SIZE"
#endif

/**
 * \brief Calculate memory offset of a field within a struct
 * \param c_type     The struct type.
 * \param mbr_name   The field name to calculate the offset of.
 */
#define SC_MEMBER_OFFSET(c_type, mbr_name)              \
  ((uint32_t) (uintptr_t)(&((c_type*)0)->mbr_name))

/**
 * \brief Calculate the size of a field within a struct
 * \param c_type     The struct type.
 * \param mbr_name   The field to calculate the size of.
 */
#define SC_MEMBER_SIZE(c_type, mbr_name)        \
  (sizeof(((c_type*)0)->mbr_name))


/**
 * \brief Representation of a packet.
 *
 * This data-structure describes a packet.  It includes pointers to the
 * packet contents, meta-data relating to the packet and fields to support
 * creating lists of packets.
 *
 * Each sc_packet instance is usually associated with a buffer that holds
 * the packet contents.  A packet may span multiple such buffers, in which
 * case the 'head' buffer uses @p frags and @p frags_tail to identify the
 * remaining buffers (which are linked via the @p next field).  Nodes should
 * generally not use the @p frags, @p frags_n and @p frags_tail fields, because
 * they are sometimes used in special ways.  Instead nodes should use @p iov
 * and @p iovlen to find the buffer(s) underlying an sc_packet.
 */
struct sc_packet {
  uint64_t              ts_sec;    /**< timestamp (seconds) */
  uint32_t              ts_nsec;   /**< timestamp (nanoseconds) */

  uint16_t              flags;     /**< flags defined below */
  uint16_t              frame_len; /**< original frame length in bytes */
  uint8_t               frags_n;   /**< number of fragments in @p frags chain */
  uint8_t               iovlen;    /**< number of entries in @p iov array */

  uint16_t              reserved1; /**< reserved */
  uint32_t              reserved2; /**< reserved */

  struct iovec*         iov;       /**< identifies packet data */
  struct sc_packet*     next;      /**< next packet in a packet list */
  struct sc_packet*     frags;     /**< list of chained fragments */
  struct sc_packet**    frags_tail;/**< last fragment in chain */
  uintptr_t*            metadata;  /**< packet metadata */
};

/**
 * \brief struct ::sc_packet.frame_len holds this special value to indicate
 * that the frame is "large". (Meaning it would overflow ::sc_packet.frame_len).
 */
#define SC_FRAME_LEN_LARGE  UINT16_MAX

/**
 * \brief struct ::sc_packet.flags will have this set if the packet has
 * a checksum error
 */
#define SC_CSUM_ERROR         (1 << 0)

/**
 * \brief struct ::sc_packet.flags will have this set if the packet has
 * a crc error
 */
#define SC_CRC_ERROR          (1 << 1)

/**
 * \brief struct ::sc_packet.flags will have this set if the packet has
 * been truncated
 */
#define SC_TRUNCATED          (1 << 2)

/**
 * \brief struct ::sc_packet.flags will have this set if the packet is
 * for a multicast group the host hasn't joined
 */
#define SC_MCAST_MISMATCH     (1 << 3)

/**
 * \brief struct ::sc_packet.flags will have this set if the packet is
 * for a unicast address not matching the host's
 */
#define SC_UCAST_MISMATCH     (1 << 4)


/**
 * \cond NODOC
 * \brief These bits are used internally by SolarCapture. Do not modify.
 */
#define SC_RESERVED_3     (1 << 13)
#define SC_RESERVED_2     (1 << 14)
#define SC_RESERVED_1     (1 << 15)
/** \endcond */

/**
 * \brief Return the size of the packet data in bytes
 * \param p          A packet object.
 * \return           The size of the packet data in bytes.
 */
static inline int sc_packet_bytes(struct sc_packet* p)
{
  int i, bytes = 0;
  for( i = 0; i < p->iovlen; ++i )
    bytes += p->iov[i].iov_len;
  return bytes;
}


/**
 * \brief Return a packet's last fragment.
 *
 * \param p          A packet object.
 *
 * \return           The packet's last fragment.
 *
 * The result is only valid if the packet has at least one fragment.
 */
static inline struct sc_packet* sc_packet_frags_tail(struct sc_packet* p)
{
  return (struct sc_packet*)
    ((char*) p->frags_tail - SC_MEMBER_OFFSET(struct sc_packet, next));
}

/**
 * \brief Prefetch a packet for reading.
 *
 * \param p          A packet object.
 *
 */
static inline void sc_packet_prefetch_r(struct sc_packet* p)
{
  __builtin_prefetch(p, 0, 2);
  __builtin_prefetch((char *) p + SC_CACHE_LINE_SIZE, 0, 2);
}

/**
 * \brief Prefetch a packet for reading and writing.
 *
 * \param p          A packet object.
 *
 */
static inline void sc_packet_prefetch_rw(struct sc_packet* p)
{
  __builtin_prefetch(p, 1, 2);
  __builtin_prefetch((char *) p + SC_CACHE_LINE_SIZE, 1, 2);
}

/**
 * \brief Return the timestamp of the packet in timespec format
 * \param p          A packet object.
 * \return           The timestamp of the packet in timespec format.
 */
static inline struct timespec sc_packet_timespec(const struct sc_packet* p)
{
  struct timespec ts = { (time_t)p->ts_sec, (long)p->ts_nsec };
  return ts;
}


#endif  /* __SOLAR_CAPTURE_EXT_PACKET_H__ */
/** @} */
