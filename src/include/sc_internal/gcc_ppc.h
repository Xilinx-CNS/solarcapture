/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#ifndef __SC_GCC_PPC_H__
#define __SC_GCC_PPC_H__


#define __sc_ppc_lwsync         __asm__ __volatile__("lwsync" ::: "memory")
#define __sc_ppc_sync           __asm__ __volatile__("sync" ::: "memory")


/* The terminology below is adapted from
 * http://preshing.com/20120913/acquire-and-release-semantics and
 * http://preshing.com/20120710/memory-barriers-are-like-source-control-operations.
 * 'l' means Load, 's' means Store.
 */
#define sc_llb()                __sc_ppc_lwsync
#define sc_ssb()                __sc_ppc_lwsync
#define sc_lsb()                __sc_ppc_lwsync
#define sc_slb()                __sc_ppc_sync


/* Enforce ordering of two loads that have a data dependency. */
#define sc_llb_data_depends()   do {} while (0)

/* Read acquire semantics: Prevent reordering of read with reads and writes
 * that follow.
 *
 * Equiv to sc_llb() + sc_lsb().
 */
#define sc_read_acquire()       __sc_ppc_lwsync

/* Write release semantics: Prevent reordering of write with reads and
 * writes that precede it.
 *
 * Equiv to sc_lsb() + sc_ssb().
 */
#define sc_write_release()      __sc_ppc_lwsync


#endif  /* __SC_GCC_PPC_H__ */
