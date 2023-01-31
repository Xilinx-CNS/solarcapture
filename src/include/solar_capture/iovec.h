/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \file
 * \brief sc_iovec_ptr: Supports iterating over a 'struct iovec'.
 */

#ifndef __SOLAR_CAPTURE_IOVEC_H__
#define __SOLAR_CAPTURE_IOVEC_H__

#include <string.h>


/**
 * \brief An sc_iovec_ptr provides a convenient way to iterate over an iovec
 * array without modifying it.
 */
struct sc_iovec_ptr {
  const struct iovec* iov;      /**< Pointer to start of  array */
  int                 iovlen;   /**< Length of iovec array */
  struct iovec        io;       /**< Currently iterated iovec */
};

/** \cond NODOC */
/**
 * \brief Initialise a struct sc_iovec_ptr.
 *
 * \param iovp         The sc_iovec_ptr to initialise
 * \param iov          Pointer to array of 'struct iovec's
 * \param iovlen       Length of the @p iov array
 *
 * NB. The first element of @p iov must be dereferenceable even if @p iovlen is
 * zero.
 */
static inline void __sc_iovec_ptr_init(struct sc_iovec_ptr* iovp,
                                       const struct iovec* iov, int iovlen)
{
  iovp->iovlen = iovlen;
  iovp->iov = iov;
  iovp->io = iov[0];
}
/** \endcond */


/**
 * \brief Initialise a struct ::sc_iovec_ptr.
 *
 * \param iovp         The ::sc_iovec_ptr to initialise
 * \param iov          Pointer to array of 'struct iovec's
 * \param iovlen       Length of the @p iov array
 */
static inline void sc_iovec_ptr_init(struct sc_iovec_ptr* iovp,
                                     const struct iovec* iov, int iovlen)
{
  iovp->iovlen = iovlen;
  iovp->iov = iov;
  if( iovlen )
    iovp->io = iov[0];
}


/**
 * \brief Initialise a struct ::sc_iovec_ptr with a contiguous buffer.
 *
 * \param iovp         The ::sc_iovec_ptr to initialise
 * \param buf          Pointer to the start of the buffer
 * \param len          Length of the buffer
 */
static inline void sc_iovec_ptr_init_buf(struct sc_iovec_ptr* iovp,
                                         void* buf, int len)
{
  iovp->iovlen = 1;
  iovp->iov = NULL;
  iovp->io.iov_base = buf;
  iovp->io.iov_len = len;
}


/**
 * \brief Initialise a struct ::sc_iovec_ptr to point at packet data.
 *
 * \param iovp         The ::sc_iovec_ptr to initialise
 * \param packet       The packet
 */
static inline void sc_iovec_ptr_init_packet(struct sc_iovec_ptr* iovp,
                                            const struct sc_packet* packet)
{
  __sc_iovec_ptr_init(iovp, packet->iov, packet->iovlen);
}


/**
 * \brief Returns the number of bytes represented by an ::sc_iovec_ptr.
 *
 * \param iovp         The sc_iovec_ptr
 *
 * \return             The number of bytes represented by the sc_iovec_ptr
 */
static inline int sc_iovec_ptr_bytes(const struct sc_iovec_ptr* iovp)
{
  int i, bytes = 0;
  if( iovp->iovlen ) {
    bytes += iovp->io.iov_len;
    for( i = 1; i < iovp->iovlen; ++i )
      bytes += iovp->iov[i].iov_len;
  }
  return bytes;
}


/**
 * \brief Skip forward over an iovec.
 *
 * \param iovp          An ::sc_iovec_ptr
 * \param bytes_to_skip Number of bytes to skip over
 *
 * \return The number of bytes skipped, which may be fewer than
 * @p bytes_to_skip if the total amount of memory referenced by @p iovp is
 * less.
 */
#if SC_API_VER >= 1
extern int sc_iovec_ptr_skip(struct sc_iovec_ptr* iovp, int bytes_to_skip);
#endif


/**
 * \brief Find offset of character in iovec.
 *
 * \param iovp         An ::sc_iovec_ptr
 * \param c            Character to find
 *
 * \return The offset of first occurrence of character @p c in the memory
 * reference by @p iovp, or -1 if not found.
 */
#if SC_API_VER >= 1
extern int sc_iovec_ptr_find_chr(const struct sc_iovec_ptr* iovp, int c);
#endif


/**
 * \brief Copy data out of an ::sc_iovec_ptr.
 *
 * \param dest         Buffer to copy to
 * \param iovp         An ::sc_iovec_ptr
 * \param max_bytes    Max number of bytes to copy (length of @p dest)
 *
 * \return The number of bytes copied.
 */
#if SC_API_VER >= 4
extern int sc_iovec_ptr_copy_out(void* dest, struct sc_iovec_ptr* iovp,
                                 int max_bytes);
#endif


/**
 * \brief Copy data out of the end with the offset of a ::sc_iovec_ptr.
 *
 * \param dest_buf     Buffer to copy to.
 * \param iov          A pointer to an array of iovec objects.
 * \param iovlen       The number of iovec objects in @p iov. This must be > 0.
 * \param bytes        Number of bytes to copy.
 * \param offset       Number of bytes to offset.
 *
 * Note: The caller must ensure that at least @p bytes + @p offset of
 * data are available in @p iov
 */
static inline void sc_iovec_copy_from_end_offset(void* dest_buf,
                                                 const struct iovec* iov,
                                                 int iovlen, int bytes,
                                                 int offset)
{
  iov += iovlen - 1;
  while( 1 ) {
    unsigned n = offset + bytes;
    if( n > iov->iov_len )
      n = iov->iov_len;
    if( n > (unsigned) offset ) {
      n -= offset;
      memcpy((char*) dest_buf + bytes - n,
             (const char*) iov->iov_base + iov->iov_len - offset - n, n);
      offset = 0;
      if( (bytes -= n) == 0 )
        break;
    }
    else
      offset -= n;

    --iov;
    --iovlen;
    assert(iovlen > 0);
  }
}


/**
 * \brief Copy data to the end with the offset of a ::sc_iovec_ptr,
 * overwriting any existing data.
 *
 * \param iov          A pointer to an array of iovec objects.
 * \param src_buf      Buffer to copy from.
 * \param iovlen       The number of iovec objects in @p iov. This must be > 0.
 * \param bytes        Number of bytes to copy.
 * \param offset       Number of bytes to offset.
 *
 * Note: The caller must ensure that at least @p bytes + @p offset of
 * data are available in @p iov
 */
static inline void sc_iovec_copy_to_end_offset(struct iovec* iov,
                                               const void* src_buf, int iovlen,
                                               int bytes, int offset)
{
  iov += iovlen - 1;
  while( 1 ) {
    unsigned n = offset + bytes;
    if( n > iov->iov_len )
      n = iov->iov_len;
    if( n > (unsigned) offset ) {
      n -= offset;
      memcpy((char*) iov->iov_base + iov->iov_len - n - offset,
             (const char*) src_buf + bytes - n, n);
      offset = 0;
      if( (bytes -= n) == 0 )
        break;
    }
    else
      offset -= n;

    --iov;
    --iovlen;
    assert(iovlen > 0);
  }
}


/**
 * \brief Copy data out of the end of a ::sc_iovec_ptr.
 *
 * \param dest_buf     Buffer to copy to.
 * \param iov          A pointer to an array of iovec objects.
 * \param iovlen       The number of iovec objects in @p iov. This must be > 0.
 * \param bytes        Number of bytes to copy.
 *
 * Note: The caller must ensure that at least @p bytes of data are available in
 * @p iov
 */
static inline void sc_iovec_copy_from_end(void* dest_buf,
                                          const struct iovec* iov,
                                          int iovlen, int bytes)
{
  sc_iovec_copy_from_end_offset(dest_buf, iov, iovlen, bytes, 0);
}


/**
 * \brief Remove data from the end of an iovec
 * \param iov               A pointer to an array of iovec objects.
 * \param iovlen            The number of iovec objects in @p iov.
 * \param bytes             The number of bytes to trim.
 *
 * Note: Caller must ensure that at least @p bytes of data are available in
 * @p iov.
 */
static inline void sc_iovec_trim_end(struct iovec* iov, uint8_t* iovlen,
                                     int bytes)
{
  iov += *iovlen - 1;
  while( 1 ) {
    if( bytes < (int) iov->iov_len ) {
      iov->iov_len -= bytes;
      return;
    }
    bytes -= iov->iov_len;
    --iov;
    --(*iovlen);
    if( bytes == 0 )
      break;
    assert(*iovlen > 0);
  }
}


#endif  /* __SOLAR_CAPTURE_IOVEC_H__ */
/**@}*/
