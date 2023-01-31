/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#ifndef __SC_MEMORY_H__
#define __SC_MEMORY_H__


struct sc_allocator;


extern void sc_allocator_alloc(struct sc_allocator**);

extern void sc_allocator_free(struct sc_allocator*);

extern void* sc_allocator_calloc(struct sc_allocator*, size_t);

extern void* sc_allocator_calloc_aligned(struct sc_allocator*, size_t, int);

extern void sc_allocator_mfree(struct sc_allocator*, void*);


#endif  /* __SC_MEMORY_H__ */
