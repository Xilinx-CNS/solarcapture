/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#ifndef __SCT_H__
#define __SCT_H__

#include <stdio.h>
#include <stdlib.h>


#define TEST(x)                                                         \
  do {                                                                  \
    if( ! (x) ) {                                                       \
      fprintf(stderr, "ERROR: %s: TEST(%s) failed\n", __func__, #x);    \
      fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__);         \
      abort();                                                          \
    }                                                                   \
  } while( 0 )


#define TRY(x)                                                          \
  do {                                                                  \
    int __rc = (x);                                                     \
    if( __rc < 0 ) {                                                    \
      fprintf(stderr, "ERROR: %s: TRY(%s) failed\n", __func__, #x);     \
      fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__);         \
      fprintf(stderr, "ERROR: rc=%d errno=%d (%s)\n",                   \
              __rc, errno, strerror(errno));                            \
      abort();                                                          \
    }                                                                   \
  } while( 0 )


#endif  /* __SCT_H__ */
