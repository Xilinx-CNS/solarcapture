/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#include "internal.h"


#define SC_BITMASK_MAX_LIST_LEN 1024

#define MIN(_a, _b) ((_a < _b)? _a:_b)


void sc_bitmask_init(struct sc_bitmask* masks)
{
  masks->bm_num_masks = 0;
  masks->bm_masks = NULL;
}


void sc_bitmask_clear_all(struct sc_bitmask* masks)
{
  int i;
  for( i = 0; i < masks->bm_num_masks; i++)
    masks->bm_masks[i] = 0;
}


void sc_bitmask_free(struct sc_bitmask* masks)
{
  free(masks->bm_masks);
  masks->bm_masks = NULL;
  masks->bm_num_masks = 0;
}


void sc_bitmask_set(struct sc_bitmask* masks, int bit_id)
{
  SC_TEST( masks->bm_num_masks >= 0 );
  if (bit_id >= masks->bm_num_masks * SC_BITMASK_PER_MASK_LEN) {
    int num_masks = (bit_id + SC_BITMASK_PER_MASK_LEN)/SC_BITMASK_PER_MASK_LEN;
    SC_REALLOC(&masks->bm_masks, num_masks);
    int i;
    for( i = masks->bm_num_masks; i < num_masks; i++)
      masks->bm_masks[i] = 0;
    masks->bm_num_masks = num_masks;
  }
  SC_TEST(bit_id/SC_BITMASK_PER_MASK_LEN < masks->bm_num_masks);
  SC_TEST(SC_BITMASK_PER_MASK_LEN == 64);
  masks->bm_masks[bit_id/SC_BITMASK_PER_MASK_LEN] |= 1llu << (bit_id % SC_BITMASK_PER_MASK_LEN);
}


bool sc_bitmask_is_set(const struct sc_bitmask* masks, int bit_id)
{
  SC_TEST(SC_BITMASK_PER_MASK_LEN == 64);
  return ( (bit_id / SC_BITMASK_PER_MASK_LEN < masks->bm_num_masks) &&
           (masks->bm_masks[bit_id / SC_BITMASK_PER_MASK_LEN] & (1llu << (bit_id % SC_BITMASK_PER_MASK_LEN))) );
}


void sc_bitmask_or(struct sc_bitmask* dest, const struct sc_bitmask* src)
{
  int i;
  for( i = 0; i < MIN(dest->bm_num_masks, src->bm_num_masks); i++ )
    dest->bm_masks[i] |= src->bm_masks[i];

  if( src->bm_num_masks > dest->bm_num_masks ) {
    SC_REALLOC(&dest->bm_masks, src->bm_num_masks);
    for( i = dest->bm_num_masks; i < src->bm_num_masks; i++)
      dest->bm_masks[i] = src->bm_masks[i];
    dest->bm_num_masks = src->bm_num_masks;
  }
}


void sc_bitmask_and(struct sc_bitmask* dest, const struct sc_bitmask* src)
{
  int i;
  for( i = 0; i < dest->bm_num_masks; i++ )
    dest->bm_masks[i] &= (src->bm_num_masks > i) ? src->bm_masks[i] : 0;
}


int sc_bitmask_ffs(const struct sc_bitmask* masks)
{
  int i, bit_id;
  SC_TEST(SC_BITMASK_PER_MASK_LEN == 64);
  for( i = 0; i < masks->bm_num_masks; i++ ) {
    bit_id = ffsll(masks->bm_masks[i]);
    if( bit_id > 0 )
      return i * SC_BITMASK_PER_MASK_LEN + bit_id;
  }
  return 0;
}


char* sc_bitmask_fmt(const struct sc_bitmask* masks)
{
  static __thread char bits_list[SC_BITMASK_MAX_LIST_LEN];
  int i;
  int count = 0;
  int bit;
  char tmp_str[10];
  uint64_t mask;
  bits_list[0] = '\0';

  for( i = 0; i < masks->bm_num_masks; i++ ) {
    mask = masks->bm_masks[i];
    bit = 0;
    while( mask ) {
      if( mask & 0x01 ) {
        snprintf(tmp_str, 10, (count==0)? "%d":",%d", bit + (i * SC_BITMASK_PER_MASK_LEN));
        count++;
        SC_TEST( strlen(tmp_str) + strlen(bits_list) < SC_BITMASK_MAX_LIST_LEN );
        strcat(bits_list, tmp_str);
      }
      mask >>= 1;
      bit++;
    }
  }
  return bits_list;
}


bool sc_bitmask_is_single_bit(const struct sc_bitmask* masks, int bit_id)
{
  int word_i = bit_id / SC_BITMASK_PER_MASK_LEN;
  if( word_i >= masks->bm_num_masks )
    return false;
  if( masks->bm_masks[word_i] != (1llu << (bit_id % SC_BITMASK_PER_MASK_LEN)) )
    return false;
  int i;
  for( i = 0; i < word_i; ++i )
    if( masks->bm_masks[i] )
      return false;
  for( i = word_i + 1; i < masks->bm_num_masks; ++i )
    if( masks->bm_masks[i] )
      return false;
  return true;
}


void sc_bitmask_duplicate(struct sc_bitmask* dest, const struct sc_bitmask* src)
{
  dest->bm_num_masks = src->bm_num_masks;
  dest->bm_masks = NULL;
  SC_REALLOC(&dest->bm_masks, dest->bm_num_masks);
  memcpy(dest->bm_masks, src->bm_masks,
         dest->bm_num_masks * sizeof(dest->bm_masks[0]));
}
