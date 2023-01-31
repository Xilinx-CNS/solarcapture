/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#ifndef __CHECK_HELPERS_H__
#define __CHECK_HELPERS_H__

#include <check.h>

#if CHECK_MAJOR_VERSION <= 0
#if CHECK_MINOR_VERSION <= 9
#if CHECK_MICRO_VERSION <= 9

#pragma message "Found old check version, using fallback wrappers..."

#define ck_assert_uint_eq(val_1, val_2) ck_assert_msg((val_1) == (val_2), \
                                                      "ERROR: %s: %u != %s: %u", \
                                                      #val_1, (val_1), \
                                                      #val_2, (val_2))

#define ck_assert_ptr_eq(val_1, val_2) ck_assert_msg((val_1) == (val_2), \
                                                      "ERROR: %s: %u != %s: %u", \
                                                      #val_1, (val_1), \
                                                      #val_2, (val_2))

#define ck_assert_ptr_ne(val_1, val_2) ck_assert_msg((val_1) != (val_2), \
                                                     "ERROR: %s: %u != %s: %u", \
                                                     #val_1, (val_1), \
                                                     #val_2, (val_2))

#endif
#endif
#endif

#endif
