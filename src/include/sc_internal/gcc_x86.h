/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#ifndef __SC_GCC_X86_H__
#define __SC_GCC_X86_H__


/* The terminology below is adapted from
 * http://preshing.com/20120913/acquire-and-release-semantics and
 * http://preshing.com/20120710/memory-barriers-are-like-source-control-operations.
 * 'l' means Load, 's' means Store.
 *
 * Look at Intel Manual 3a, Section: 8.2 for more details.
 */
#define sc_llb()   sc_compiler_barrier()                       /* 8.2.3.2 */
#define sc_ssb()   sc_compiler_barrier()                       /* 8.2.3.2 */
#define sc_lsb()   sc_compiler_barrier()                       /* 8.2.3.3 */
#define sc_slb()   __asm__ __volatile__("mfence" ::: "memory") /* 8.2.3.4,
                                                                  8.2.5 */

/* Enforce ordering of two loads that have a data dependency. */
#define sc_llb_data_depends()   do {} while (0)

/* Read acquire semantics: Prevent reordering of read with reads and writes
 * that follow.
 *
 * Equiv to sc_llb() + sc_lsb().
 */
#define sc_read_acquire()       sc_compiler_barrier()

/* Write release semantics: Prevent reordering of write with reads and
 * writes that precede it.
 *
 * Equiv to sc_lsb() + sc_ssb().
 */
#define sc_write_release()      sc_compiler_barrier()


#endif  /* __SC_GCC_X86_H__ */
