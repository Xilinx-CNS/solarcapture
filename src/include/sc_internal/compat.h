/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#ifndef __SC_COMPAT_H__
#define __SC_COMPAT_H__


#if defined(__GNUC__)

# define sc_compiler_barrier()  __asm__ __volatile__("" ::: "memory")

# if defined(__x86_64__) || defined(__i386__)
#  include <sc_internal/gcc_x86.h>
# elif defined(__powerpc__)
#  include <sc_internal/gcc_ppc.h>
# else
#  error Unknown processor - GNU C
# endif
#else
#error Unknown compiler
#endif

#endif  /* __SC_COMPAT_H__ */
