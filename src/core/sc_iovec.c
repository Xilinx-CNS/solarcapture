/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#include "internal.h"


int sc_iovec_ptr_skip(struct sc_iovec_ptr* iovp, int bytes_to_skip)
{
  int skipped = 0;
  while( iovp->iovlen ) {
    if( bytes_to_skip < iovp->io.iov_len ) {
      iovp->io.iov_len -= bytes_to_skip;
      iovp->io.iov_base = (uint8_t*) iovp->io.iov_base + bytes_to_skip;
      return skipped + bytes_to_skip;
    }
    else {
      skipped += iovp->io.iov_len;
      bytes_to_skip -= iovp->io.iov_len;
      ++(iovp->iov);
      --(iovp->iovlen);
      if( iovp->iovlen == 0 )
        return skipped;
      iovp->io = iovp->iov[0];
    }
  }
  return skipped;
}


int sc_iovec_ptr_find_chr(const struct sc_iovec_ptr* iovp, int c)
{
  if( iovp->iovlen ) {
    char* p = memchr(iovp->io.iov_base, c, iovp->io.iov_len);
    if( p != NULL )
      return p - (char*) iovp->io.iov_base;
    int i, off = iovp->io.iov_len;
    for( i = 1; i < iovp->iovlen; ++i ) {
      p = memchr(iovp->iov[i].iov_base, c, iovp->iov[i].iov_len);
      if( p != NULL )
        return p - (char*) iovp->iov[i].iov_base + off;
      off += iovp->iov[i].iov_len;
    }
  }
  return -1;
}


int sc_iovec_ptr_copy_out(void* dest, struct sc_iovec_ptr* iovp, int max_bytes)
{
  int copied = 0;
  if( iovp->iovlen != 0 )
    while( 1 ) {
      int n = iovp->io.iov_len < max_bytes ? iovp->io.iov_len : max_bytes;
      memcpy((char*) dest + copied, iovp->io.iov_base, n);
      copied += n;
      if( n == iovp->io.iov_len ) {
        ++(iovp->iov);
        if( --(iovp->iovlen) == 0 )
          return copied;
        iovp->io = iovp->iov[0];
      }
      else {
        iovp->io.iov_base = (uint8_t*) iovp->io.iov_base + n;
        iovp->io.iov_len -= n;
      }
      if( n == max_bytes )
        return copied;
      max_bytes -= n;
    }
  return 0;
}
