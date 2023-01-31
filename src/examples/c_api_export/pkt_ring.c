/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/*
 * Simple memory ring buffer allowing passing data between two threads:
 * a producer and a consumer.
 *
 * NB. This is a sample code and it is deliberatly kept simple rather than
 * efficient.
 */

#include "pkt_ring.h"

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <assert.h>


#define TEST(x)                                                 \
  do {                                                          \
    if( ! (x) ) {                                               \
      fprintf(stderr, "ERROR: TEST(%s) failed\n", #x);          \
      fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__); \
      exit(1);                                                  \
    }                                                           \
  } while( 0 )


#define sc_compiler_barrier()    __asm__ __volatile__("" ::: "memory")
#if defined(__x86_64__) || defined(__i386__)
# define sc_read_acquire()       sc_compiler_barrier()
# define sc_write_release()      sc_compiler_barrier()
#elif defined(__PPC__)
# define sc_read_acquire()       __asm__ __volatile__("lwsync" ::: "memory")
# define sc_write_release()      __asm__ __volatile__("lwsync" ::: "memory")
#else
# error "Need barriers for this arch."
#endif


struct pkt_ring {
  char*         ring;
  unsigned long size;
  unsigned long rd;
  unsigned long rd_next;
  unsigned long wr;
  unsigned long last_len;
};


int pkt_ring_alloc(struct pkt_ring** ring_out, unsigned long size)
{
  TEST((size & (size - 1)) == 0);  /* Size must be a power-of-2. */
  struct pkt_ring* ring = calloc(1, sizeof(*ring));
  ring->ring = malloc(size);
  memset(ring->ring, 0, size);  /* touch -- ensure mmap is filled */
  ring->size = size;
  *ring_out = ring;
  return 0;
}


int pkt_ring_put(struct pkt_ring* ring, const void* payload, int len)
{
  unsigned long fill_level = ring->wr - ring->rd;
  sc_read_acquire();
  assert(fill_level <= ring->size);
  if( ring->size - fill_level >= 1 + sizeof(len) + len ) {
    unsigned long off = ring->wr & (ring->size - 1);
    int inc = 0, contig_space = ring->size - off;
    if( contig_space < 1 + sizeof(len) + len ) {
      ring->ring[off] = 0;
      inc = contig_space;
      assert(((ring->wr + inc) & (ring->size - 1)) == 0);
      off = 0;
    }
    ring->ring[off++] = 1;
    memcpy(ring->ring + off, &len, sizeof(len));
    off += sizeof(len);
    memcpy(ring->ring + off, payload, len);
    sc_write_release();
    ring->wr += inc + 1 + sizeof(len) + len;
    return 0;
  }
  return -1;
}


int pkt_ring_get(struct pkt_ring* ring, void** payload, int* len_out)
{
  sc_write_release();
  ring->rd = ring->rd_next;

  if( ring->rd - ring->wr ) {
    unsigned long off = ring->rd & (ring->size - 1);
    sc_read_acquire();
    if( ring->ring[off] == 0 ) {
      ring->rd_next += ring->size - off;
      off = 0;
      assert(ring->ring[off] == 1);
    }
    int len;
    memcpy(&len, ring->ring + off + 1, sizeof(len));
    *payload = ring + off + 1 + sizeof(len);
    *len_out = len;
    ring->rd_next += 1 + sizeof(len) + len;
    return 0;
  }
  return -1;
}
