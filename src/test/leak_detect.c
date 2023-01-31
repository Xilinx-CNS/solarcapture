/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#define SC_API_VER 5
#include <solar_capture.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>


#define TRY(x)                                                  \
  do {                                                          \
    int __rc = (x);                                             \
    if( __rc < 0 ) {                                            \
      fprintf(stderr, "ERROR: TRY(%s) failed\n", #x);           \
      fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__); \
      fprintf(stderr, "ERROR: rc=%d errno=%d (%s)\n",           \
              __rc, errno, strerror(errno));                    \
      exit(1);                                                  \
    }                                                           \
  } while( 0 )


int main(int argc, char* argv[])
{
  int i, n = 10;

  struct sc_attr* attr;
  TRY( sc_attr_alloc(&attr) );

  for( i = 0; i < n; ++i ) {
    struct sc_session* scs;
    TRY( sc_session_alloc(&scs, attr) );
    if( 1 ) {
      struct sc_thread* t;
      TRY( sc_thread_alloc(&t, attr, scs) );
    }
    sc_session_destroy(scs);
  }

  sc_attr_free(attr);
  return 0;
}
