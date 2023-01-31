/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#include <sc_internal.h>
#include <errno.h>

int main()
{
  int in[50];
  int out[50];
  struct sc_hash_table* hash_table;

  printf("IN\n");
  sc_hash_table_alloc(&hash_table, sizeof(int), sizeof(int), 100);
  float* val;
  for( unsigned i = 0; i < 50; ++i ) {
    if( sc_hash_table_get(hash_table, &i, 1, (void**)&val) == -ENOSPC )
      break;
    *val = i*10;
    in[i] = *val;
    printf("KEY: %u VALUE: %f\n", i, *val);
  }

  printf("\nOUT\n");
  unsigned* key;
  unsigned scratch = 0;
  int rc = 0;
  while( !rc )
    if( (rc = sc_hash_table_get_next_entry(hash_table, (void**)&key, (void**)&val, &scratch)) == 0) {
      printf("KEY: %u VALUE: %f\n", *key, *val);
      out[*key] = *val;
    }

  for(unsigned i = 0; i < 50; ++i) {
    if( in[i] != out[i] ) {
      printf("DON'T MATCH in[%u] = %u != out[%u] = %u\n", i, in[i], i, out[i]);
      return -1;
    }
  }

  printf("MATCHES\n");
}
