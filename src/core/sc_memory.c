/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#include "internal.h"

#include <sys/param.h>


struct sc_allocator {
  char* start;
  char* block;
  char* block_end;
};


void sc_allocator_alloc(struct sc_allocator** out)
{
  struct sc_allocator* ma = calloc(1, sizeof(*ma));
  TEST(ma != NULL);
  void* p;
  int block_align = 4096/*??*/;
  int block_size = 2*1024*1024/*??*/;
  TEST(posix_memalign(&p, block_align, block_size) == 0);
  ma->start = p;
  ma->block = p;
  ma->block_end = ma->block + block_size;
  memset(ma->block, 0, block_size);
  *out = ma;
}


void sc_allocator_free(struct sc_allocator* ma)
{
  free(ma->start);
  free(ma);
}


void* sc_allocator_calloc(struct sc_allocator* ma, size_t bytes)
{
  TEST(bytes <= (char*) ma->block_end -  (char*) ma->block); /* ?? fixme */
  void* ret = ma->block;
  ma->block = (char*) ma->block + roundup(bytes, sizeof(void*));
  return ret;
}


void* sc_allocator_calloc_aligned(struct sc_allocator* ma,
                                  size_t bytes, int align)
{
  SC_TEST(powerof2(align));
  ma->block = (void*) roundup((uintptr_t) ma->block, align);
  return sc_allocator_calloc(ma, bytes);
}


void sc_allocator_mfree(struct sc_allocator* ma, void* mem)
{
  /* ?? todo */
}


/**********************************************************************
 * sc_thread memory allocation interface
 */

void* sc_thread_calloc(struct sc_thread* t, size_t bytes)
{
  return sc_allocator_calloc(t->ma, bytes);
}


void* sc_thread_calloc_aligned(struct sc_thread* t, size_t bytes, int align)
{
  return sc_allocator_calloc_aligned(t->ma, bytes, align);
}


void sc_thread_mfree(struct sc_thread* t, void* mem)
{
  sc_allocator_mfree(t->ma, mem);
}
