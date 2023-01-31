/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <math.h>
#include <limits.h>

#include <check.h>
#include <check_helpers.h>

#include "sc_hash_table.c"


#define MAX_LOGFILE_PATH_LENGTH 512
#define TEST_TABLE_CAPACITY 5000
#define TEST_TABLE_SIZE 256


static void
check_delete_val(struct sc_hash_table* table, struct sc_hash_table_hash* hash,
                 unsigned key, unsigned expected_entry_no)
{
  struct sc_hash_table_entry* entry = get_entry(table, expected_entry_no);
  ck_assert_uint_eq(key, *(unsigned*)entry->key);
  ck_assert_uint_eq(1, entry->valid);
  ck_assert_int_eq(sc_hash_table_del_val(table, entry_value(table, entry)), 0);
  ck_assert_uint_eq(0, entry->valid);

}


static void check_table_cleared(struct sc_hash_table* table)
{
  unsigned int i;
  for( i = 0; i <= table->table_mask; ++i ) {
    ck_assert_uint_eq(get_entry(table, i)->valid, 0);
    ck_assert_uint_eq(get_entry(table, i)->hop_count, 0);
  }
  ck_assert_uint_eq(table->n_entries, 0);
}


static struct sc_hash_table*
create_table_with_capacity_and_check_initialised(unsigned key_size,
                                                 unsigned val_size,
                                                 unsigned capacity)
{
  struct sc_hash_table* table;
  ck_assert_msg(sc_hash_table_alloc(&table, key_size, val_size, capacity) == 0,
                "Non zero return code");
  ck_assert_uint_eq(table->key_size, key_size);
  ck_assert_uint_eq(table->val_size, val_size);
  uint32_t expected_mask = capacity > 1 ? (1UL << ((unsigned)log2((capacity / 4) * 5)) + 1) - 1 : 0;
  ck_assert_uint_eq(table->table_mask, expected_mask);

  check_table_cleared(table);
  return table;
}


static struct sc_hash_table*
create_table_with_num_entries_and_check_initialised(unsigned key_size,
                                                    unsigned val_size,
                                                    unsigned num_entries,
                                                    unsigned max_hops)
{
  struct sc_hash_table* table;
  ck_assert_msg(sc_hash_table_alloc_with_num_entries(&table, key_size, val_size,
                                                    num_entries, max_hops) == 0,
                "Non zero return code");
  ck_assert_uint_eq(table->key_size, key_size);
  ck_assert_uint_eq(table->val_size, val_size);
  ck_assert_uint_eq(table->table_mask, num_entries - 1);
  check_table_cleared(table);
  return table;
}


static void
add_hop_route(struct sc_hash_table* table, unsigned start_position,
              unsigned step_size, unsigned number_of_hops)
{
  unsigned position = start_position;
  unsigned i = 0;
  unsigned end_position = start_position + number_of_hops * step_size;

  position = start_position;
  while( position < end_position ) {
    struct sc_hash_table_entry* entry = get_entry(table, position & table->table_mask);
    entry->valid = 1;
    entry->hop_count += 1;
    memcpy(entry->key, &i, sizeof(i));
    memcpy(entry_value(table, entry), &i, sizeof(i));
    ++i;
    position += step_size;
  }
  table->n_entries += number_of_hops;
}


static struct sc_hash_table*
create_empty_hash_table()
{
  return create_table_with_num_entries_and_check_initialised(sizeof(unsigned),
                                                             sizeof(unsigned),
                                                             TEST_TABLE_SIZE,
                                                             DEFAULT_HOP_MAX);
}


static struct sc_hash_table*
create_and_populate_hash_table_with_route(unsigned start_position,
                                          unsigned step_size,
                                          unsigned number_of_hops)
{
  struct sc_hash_table* table = create_empty_hash_table();
  add_hop_route(table, start_position, step_size, number_of_hops);
  return table;
}


static void
check_found_key_value(struct sc_hash_table* table,
                      struct sc_hash_table_hash* hash,
                      unsigned expected_value)
{
  struct sc_hash_table_entry* entry;
  ck_assert_int_eq(find_key(table, hash, &entry), 0);
  ck_assert_uint_eq(*(unsigned*)entry->key, *(unsigned*)hash->key);
  ck_assert_uint_eq(*(unsigned*)entry_value(table, entry), expected_value);
}


static void
check_key_not_found(struct sc_hash_table* table,
                    struct sc_hash_table_hash* hash,
                    int expected_errno)
{
  struct sc_hash_table_entry* entry;
  ck_assert_int_eq(find_key(table, hash, &entry), expected_errno);
  if( expected_errno == -ENOENT )
    ck_assert(entry->valid == 0);
}


static void
set_hop_count(struct sc_hash_table* table, unsigned pos, unsigned hop_count)
{
  get_entry(table, pos)->hop_count = hop_count;
}


static void
set_valid_field(struct sc_hash_table* table, unsigned pos, bool state)
{
  get_entry(table, pos)->valid = state;
}


static void check_remove_key_at_entry(struct sc_hash_table* table,
                                      struct sc_hash_table_hash* hash,
                                      struct sc_hash_table_entry* entry,
                                      unsigned expected_entry_no)
{
  unsigned num_hops_expected = (expected_entry_no - hash->entry_no) / hash->step_size;
  unsigned hops_before_insert[table->max_hops];
  unsigned i;
  for( i = 0; i < table->max_hops; ++i )
    hops_before_insert[i] = get_entry(table, hash->entry_no + i * hash->step_size)->hop_count;

  remove_key(table, hash, entry);

  for( i = 0; i < num_hops_expected; ++i )
    ck_assert_uint_eq(get_entry(table, hash->entry_no + i * hash->step_size)->hop_count,
                      hops_before_insert[i] - 1);

  for(i = num_hops_expected; i < table->max_hops; ++i )
    ck_assert_uint_eq(get_entry(table, hash->entry_no + i * hash->step_size)->hop_count,
                      hops_before_insert[i]);

  ck_assert_uint_eq(get_entry(table, expected_entry_no)->valid, 0);
}


static void check_insert_key_at_entry(struct sc_hash_table* table,
                                      struct sc_hash_table_hash* hash,
                                      struct sc_hash_table_entry* entry,
                                      unsigned expected_entry_no)
{
  unsigned num_hops_expected = (expected_entry_no - hash->entry_no) / hash->step_size;
  unsigned hops_before_insert[table->max_hops];
  unsigned i;
  for( i = 0; i < table->max_hops; ++i )
    hops_before_insert[i] = get_entry(table, hash->entry_no + i * hash->step_size)->hop_count;
  insert_key(table, hash, entry);

  for( i = 0; i < num_hops_expected; ++i )
    ck_assert_uint_eq(get_entry(table, hash->entry_no + i * hash->step_size)->hop_count,
                      hops_before_insert[i] + 1);

  for(i = num_hops_expected; i < table->max_hops; ++i )
    ck_assert_uint_eq(get_entry(table, hash->entry_no + i * hash->step_size)->hop_count,
                      hops_before_insert[i]);
  ck_assert(memcmp(get_entry(table, expected_entry_no)->key, hash->key, table->key_size) == 0);
}


static void
check_get(struct sc_hash_table* table,
          unsigned key,
          bool insert_if_not_found,
          int expected_rc,
          unsigned expected_val_out)
{
  unsigned* val_out;
  int rc = sc_hash_table_get(table, &key, insert_if_not_found, (void**)&val_out);
  ck_assert_int_eq(rc, expected_rc);
  if( rc > 0 ) {
    ck_assert_uint_eq(*val_out, expected_val_out);
    ck_assert_uint_eq(key, *(unsigned*)sc_hash_table_val_to_key(table, val_out));
  }

}


static void
check_entries(struct sc_hash_table* table, unsigned* valid_entries,
              unsigned num_entries)
{
  add_hop_route(table, 0, 1, table->table_mask + 1);

  unsigned i;
  for( i = 0; i < table->table_mask + 1; ++i )
    get_entry(table, i)->valid = 0;

  for( i = 0; i < num_entries; ++i )
    get_entry(table, valid_entries[i])->valid = 1;

  bool seen_entry[table->table_mask + 1];
  memset(seen_entry, 0, sizeof(*seen_entry) * (table->table_mask + 1));

  unsigned scratch = 0;
  unsigned* key_out;
  unsigned* val_out;
  while( sc_hash_table_get_next_entry(table, (void**)&key_out, (void**)&val_out,
                                     &scratch) != -ENOENT ) {
    ck_assert(!seen_entry[*key_out]);
    seen_entry[*key_out] = true;
    ck_assert_uint_eq(*key_out, *val_out);
  }
  unsigned j;
  for( i = 0; i < table->table_mask + 1; ++i ) {
    bool in_valid_list = false;
    for( j = 0; j < num_entries; ++j )
      if( valid_entries[j] == i ) {
        in_valid_list = true;
        break;
      }

    if( in_valid_list )
      ck_assert(seen_entry[i]);
    else
      ck_assert(!seen_entry[i]);
  }
}


static void
check_delete(struct sc_hash_table* table, struct sc_hash_table_hash* hash,
             unsigned key, unsigned expected_entry_no)
{
  ck_assert_uint_eq(key, *(unsigned*)get_entry(table, expected_entry_no)->key);
  ck_assert_uint_eq(1, get_entry(table, expected_entry_no)->valid);
  ck_assert_int_eq(sc_hash_table_del(table, &key), 0);
  ck_assert_uint_eq(0, get_entry(table, expected_entry_no)->valid);

}


static void check_grown_table(struct sc_hash_table* table_to_grow,
                              size_t max_size, int rc)
{
  unsigned num_entries = table_to_grow->n_entries;
  unsigned keys_in_original[num_entries];
  unsigned vals_in_original[num_entries];
  unsigned scratch = 0;
  unsigned* key;
  unsigned* value;

  int i = 0;
  while( sc_hash_table_get_next_entry(table_to_grow, (void**)&key,
                                    (void**)&value, &scratch) == 0 ) {
    keys_in_original[i] = *key;
    vals_in_original[i] = *value;
    i++;
  }
  ck_assert_uint_eq(num_entries, i);

  void* old_ptr = table_to_grow->table;
  ck_assert_int_eq(sc_hash_table_grow(table_to_grow, max_size), rc);

  if( rc != 0 ) {
    ck_assert_ptr_eq(table_to_grow->table, old_ptr);
  }
  else {
    ck_assert_ptr_ne(table_to_grow->table, old_ptr);
    ck_assert_uint_eq(table_to_grow->n_entries, num_entries);
    for( i = 0; i < num_entries; ++i ) {
      ck_assert_int_eq(sc_hash_table_get(table_to_grow,
                                         (void*)&keys_in_original[i], false,
                                         (void**)&value), 0);
      ck_assert_uint_eq(*value, vals_in_original[i]);
    }
  }
}


static copy_and_check_entries(struct sc_hash_table* table_to_copy_into,
                              struct sc_hash_table* table_to_copy,
                              int expected_rc)
{
  ck_assert_int_eq(copy_hash_table_into_hash_table(table_to_copy_into,
                                                   table_to_copy), expected_rc);
  if( expected_rc == 0 ) {
    ck_assert_uint_eq(table_to_copy_into->n_entries, table_to_copy->n_entries);
    unsigned* key;
    unsigned* value_in_table_copied_into;
    unsigned* value_in_table_copied_from;
    unsigned scratch = 0;
    while( sc_hash_table_get_next_entry(table_to_copy_into, (void**)&key,
                                      (void**)&value_in_table_copied_from, &scratch) == 0 ) {
      ck_assert_int_eq(sc_hash_table_get(table_to_copy_into, (void*)key,
                                         false, (void**)&value_in_table_copied_into), 0);
      ck_assert_uint_eq(*value_in_table_copied_from, *value_in_table_copied_into);
    }
  }
}


static struct sc_hash_table* create_fully_populated_table()
{
  struct sc_hash_table* table = create_empty_hash_table();
  /* This will be using the dummy hash function in which case the 32 bit hash
   * is constructed from the first byte of the key repeated 4 times. This means
   * entry no will be this number masked by table mask and step size will be
   * equal to entry_no or'd with 1
   *
   * TEST_TABLE_SIZE is 256 which is the largest number we can get from the first
   * byte, happily this will mean that the lowest 8 bits of the key gives us the
   * entry_no and step size that will be generated by the dummy hash.
   */
  unsigned i;
  struct sc_hash_table_entry* entry;
  for( i = 0; i <= table->table_mask; ++i ) {
    entry = get_entry(table, i);
    memcpy(entry->key, &i, table->key_size);
    entry->valid = 1;
    entry->hop_count = 0;
    memcpy(entry_value(table, entry), &i, table->val_size);
  }
  table->n_entries = table->table_mask + 1;
  return table;
}


static struct sc_hash_table*
create_table_with_collision_on_copy()
{
  struct sc_hash_table* table = create_empty_hash_table();
  unsigned i;
  struct sc_hash_table_entry* entry;
  for( i = 0; i < DEFAULT_HOP_MAX + 1; ++i ) {
    entry = get_entry(table, i);
    unsigned* key = (unsigned*)(entry->key);
    *key = 1u << (i + 8);
    entry->valid = 1;
  }
  table->n_entries = DEFAULT_HOP_MAX + 1;
  return table;
}


START_TEST(ceil_to_power_of_two_test)
{
  unsigned i, j;
  uint32_t value_in, expected_output, output;
  for( i = 0; i < 31; ++i ) {
      for( j = 0; j < i; ++j ) {
          value_in = (1u << i) | (1u << j);
          expected_output = 1u << (i + 1);
          output = ceil_to_power_of_two(value_in);
          ck_assert_msg( output == expected_output,
                        "(ceil_to_power_of_two(%u) = %"PRIu32") != %u",
                        value_in, output, expected_output);
      }
  }
}
END_TEST

START_TEST(num_entries_from_small_capacity_test)
{
  ck_assert_uint_eq(calculate_num_entries_from_capacity(1), 1);
  ck_assert_uint_eq(calculate_num_entries_from_capacity(2), 2);
  ck_assert_uint_eq(calculate_num_entries_from_capacity(3), 4);
  ck_assert_uint_eq(calculate_num_entries_from_capacity(4), 8);
}
END_TEST


START_TEST(num_entries_from_large_capacity_test)
{
  unsigned i;
  for( i = MAX_HASH_TABLE_SIZE; i > MAX_HASH_TABLE_SIZE - 10; --i )
    ck_assert_uint_eq(calculate_num_entries_from_capacity(i), (1u << 31));
}
END_TEST


START_TEST(capacity_table_alloc_test_bad_key_size)
{
  struct sc_hash_table* table;
  ck_assert_msg(sc_hash_table_alloc(&table, 0, 0, 10) < 0,
                "No error for invalid key size");
}
END_TEST

START_TEST(capacity_table_alloc_test_bad_capacity)
{
  struct sc_hash_table* table;
  ck_assert_msg(sc_hash_table_alloc(&table, 1, 0, 0) < 0,
                "No error for invalid capacity");
}
END_TEST

START_TEST(capacity_table_alloc_test_with_reasonable_capacity)
{
  sc_hash_table_free(create_table_with_capacity_and_check_initialised(2, 2, 150));
}
END_TEST

START_TEST(capacity_table_alloc_test_with_large_capacity)
{
  sc_hash_table_free(create_table_with_capacity_and_check_initialised(2, 2, UINT16_MAX));
}
END_TEST

START_TEST(capacity_table_alloc_test_with_min_capacity)
{
  sc_hash_table_free(create_table_with_capacity_and_check_initialised(2, 2, 1));
}
END_TEST

START_TEST(capacity_table_alloc_test_with_reasonable_key_size)
{
  sc_hash_table_free(create_table_with_capacity_and_check_initialised(10, 2, 150));
}
END_TEST

START_TEST(capacity_table_alloc_test_with_min_key_size)
{
  sc_hash_table_free(create_table_with_capacity_and_check_initialised(1, 2, 150));
}
END_TEST

START_TEST(capacity_table_alloc_test_with_large_key_size)
{
  sc_hash_table_free(create_table_with_capacity_and_check_initialised(UINT16_MAX, 2, 150));

}
END_TEST

START_TEST(capacity_table_alloc_test_with_reasonable_val_size)
{
  sc_hash_table_free(create_table_with_capacity_and_check_initialised(10, 100, 150));
}
END_TEST

START_TEST(capacity_table_alloc_test_with_min_val_size)
{
  sc_hash_table_free(create_table_with_capacity_and_check_initialised(10, 0, 150));
}
END_TEST

START_TEST(capacity_table_alloc_test_with_large_val_size)
{
  sc_hash_table_free(create_table_with_capacity_and_check_initialised(10, UINT16_MAX, 150));
}
END_TEST

START_TEST(table_alloc_test_bad_key_size)
{
  struct sc_hash_table* table;
  ck_assert_msg(sc_hash_table_alloc_with_num_entries(&table, 0, 0, 10, 10) < 0,
                "No error for invalid key size");
}
END_TEST

START_TEST(table_alloc_test_bad_num_entries)
{
  struct sc_hash_table* table;
  ck_assert_msg(sc_hash_table_alloc_with_num_entries(&table, 1, 0, 10, 10) < 0,
                "No error for invalid num entries");
  unsigned i, j;
  for( i = 1; i < 32; ++i )
    for( j = 0; j < i; ++j )
      ck_assert_msg(sc_hash_table_alloc_with_num_entries(&table, 1, 0, (1u << i) | (1u << j), 10) < 0,
                      "No error for invalid num entries");
}
END_TEST

START_TEST(table_alloc_test_bad_max_hops)
{
  struct sc_hash_table* table;
  ck_assert_msg(sc_hash_table_alloc_with_num_entries(&table, 1, 0, 10, MAX_HOP_COUNT) < 0,
                "No error for invalid hop count");
}
END_TEST

START_TEST(table_alloc_test_with_reasonable_key_size)
{
  sc_hash_table_free(create_table_with_num_entries_and_check_initialised(10, 2, 16, 2));
}
END_TEST

START_TEST(table_alloc_test_with_min_key_size)
{
  sc_hash_table_free(create_table_with_num_entries_and_check_initialised(1, 2, 16, 2));
}
END_TEST

START_TEST(table_alloc_test_with_large_key_size)
{
  sc_hash_table_free(create_table_with_num_entries_and_check_initialised(UINT16_MAX, 2, 16, 2));
}
END_TEST

START_TEST(table_alloc_test_with_reasonable_val_size)
{
  sc_hash_table_free(create_table_with_num_entries_and_check_initialised(1, 10, 16, 2));
}
END_TEST

START_TEST(table_alloc_test_with_min_val_size)
{
  sc_hash_table_free(create_table_with_num_entries_and_check_initialised(1, 0, 16, 2));
}
END_TEST

START_TEST(table_alloc_test_with_large_val_size)
{
  sc_hash_table_free(create_table_with_num_entries_and_check_initialised(1, UINT16_MAX, 16, 2));
}
END_TEST

START_TEST(table_alloc_test_with_reasonable_num_entries)
{
  sc_hash_table_free(create_table_with_num_entries_and_check_initialised(1, 0, (1u << 16), 2));
}
END_TEST

START_TEST(table_alloc_test_with_min_num_entries)
{
  sc_hash_table_free(create_table_with_num_entries_and_check_initialised(1, 0, 1, 2));
}
END_TEST

START_TEST(table_alloc_test_with_large_num_entries)
{
  sc_hash_table_free(create_table_with_num_entries_and_check_initialised(1, 0, (1u << 18), 2));
}
END_TEST

START_TEST(table_alloc_test_with_reasonable_max_hops)
{
  sc_hash_table_free(create_table_with_num_entries_and_check_initialised(1, 0, 16, 10));
}
END_TEST

START_TEST(table_alloc_test_with_min_max_hops)
{
  sc_hash_table_free(create_table_with_num_entries_and_check_initialised(1, 0, 16, 0));
}
END_TEST

START_TEST(table_alloc_test_with_max_max_hops)
{
  sc_hash_table_free(create_table_with_num_entries_and_check_initialised(1, 0, 16, MAX_HOP_COUNT));
}
END_TEST

START_TEST(find_key_test_no_hop)
{
  struct sc_hash_table* table = create_and_populate_hash_table_with_route(1, 2, 10);
  unsigned key = 0;
  struct sc_hash_table_hash hash = {.key=(uint8_t*)&key, .entry_no=1, .step_size=2};
  check_found_key_value(table, &hash, 0);
  sc_hash_table_free(table);
}
END_TEST

START_TEST(find_key_test_all_positions_upto_hop_max)
{
  unsigned i;
  for( i = 0; i < DEFAULT_HOP_MAX; ++i ) {
    struct sc_hash_table* table = create_and_populate_hash_table_with_route(1, 3, DEFAULT_HOP_MAX);
    struct sc_hash_table_hash hash = {.key=(uint8_t*)&i, .entry_no=1, .step_size=3};
    check_found_key_value(table, &hash, i);
    sc_hash_table_free(table);
  }
}
END_TEST

START_TEST(find_key_test_entry_empty)
{
  struct sc_hash_table* table = create_empty_hash_table();
  unsigned key = 0;
  struct sc_hash_table_hash hash = {.key=(uint8_t*)&key, .entry_no=1, .step_size=2};
  check_key_not_found(table, &hash, -ENOENT);
  sc_hash_table_free(table);
}
END_TEST

START_TEST(find_key_test_entry_empty_all_positions_upto_hop_max)
{
  unsigned i;
  for( i = 0; i < DEFAULT_HOP_MAX - 1; ++i ) {
    struct sc_hash_table* table = create_and_populate_hash_table_with_route(1, 5, i);
    unsigned key = i + 1;
    struct sc_hash_table_hash hash = {.key=(uint8_t*)&key, .entry_no=1, .step_size=5};
    check_key_not_found(table, &hash, -ENOENT);
    sc_hash_table_free(table);
  }
}
END_TEST

START_TEST(find_key_test_no_match_all_entries_used)
{
  struct sc_hash_table* table = create_and_populate_hash_table_with_route(1, 5, DEFAULT_HOP_MAX);
  unsigned key = DEFAULT_HOP_MAX + 1;
  struct sc_hash_table_hash hash = {.key=(uint8_t*)&key, .entry_no=1, .step_size=5};
  check_key_not_found(table, &hash, -ENOSPC);
  sc_hash_table_free(table);
}
END_TEST


START_TEST(find_key_test_match_after_a_max_hop_count_entry)
{
  unsigned i;
  for( i = 0; i < DEFAULT_HOP_MAX - 1; ++i ) {
    struct sc_hash_table* table = create_and_populate_hash_table_with_route(1, 5, DEFAULT_HOP_MAX);
    set_hop_count(table, MAX_HOP_COUNT, i);
    unsigned key = i;
    struct sc_hash_table_hash hash = {.key=(uint8_t*)&key, .entry_no=1, .step_size=5};
    check_found_key_value(table, &hash, i);
    sc_hash_table_free(table);
  }
}
END_TEST

START_TEST(find_key_test_no_match_after_a_max_hop_count_entry)
{
  unsigned i;
  for( i = 0; i < DEFAULT_HOP_MAX - 1; ++i ) {
    struct sc_hash_table* table = create_and_populate_hash_table_with_route(1, 5, DEFAULT_HOP_MAX);
    set_hop_count(table, MAX_HOP_COUNT, i);
    unsigned key = DEFAULT_HOP_MAX + 1;
    struct sc_hash_table_hash hash = {.key=(uint8_t*)&key, .entry_no=1, .step_size=5};
    check_key_not_found(table, &hash, -ENOSPC);
    sc_hash_table_free(table);
  }
}
END_TEST

START_TEST(find_key_test_get_first_gap_on_no_key)
{
  struct sc_hash_table* table = create_and_populate_hash_table_with_route(1, 2, DEFAULT_HOP_MAX);
  unsigned key = 0;
  struct sc_hash_table_hash hash = {.key=(uint8_t*)&key, .entry_no=1, .step_size=2};
  set_valid_field(table, hash.entry_no, false);
  check_key_not_found(table, &hash, -ENOENT);
  sc_hash_table_free(table);
}
END_TEST

START_TEST(find_key_test_get_first_empty_position_if_gap_before_max_hop_entry_on_no_key)
{
  unsigned i, j;
  for( i = 0; i < DEFAULT_HOP_MAX - 1; ++i ) {
    for( j = 0; j <= i; ++j ) {
      struct sc_hash_table* table = create_and_populate_hash_table_with_route(1, 5, DEFAULT_HOP_MAX);
      unsigned key = DEFAULT_HOP_MAX + 1;
      struct sc_hash_table_hash hash = {.key=(uint8_t*)&key, .entry_no=1, .step_size=5};
      set_valid_field(table, hash.entry_no  + j * hash.step_size, false);
      set_hop_count(table, hash.entry_no + (i + 1)* hash.step_size, MAX_HOP_COUNT);
      check_key_not_found(table, &hash, -ENOENT);
      sc_hash_table_free(table);
    }
  }
}
END_TEST

START_TEST(find_key_test_get_no_empty_position_if_gap_after_max_hop_entry_on_no_key)
{
  unsigned i, j;
  for( i = 0; i < DEFAULT_HOP_MAX - 1; ++i ) {
    for( j= 0; j > i; ++j ) {
      struct sc_hash_table* table = create_and_populate_hash_table_with_route(1, 5, DEFAULT_HOP_MAX);
      unsigned key = DEFAULT_HOP_MAX + 1;
      struct sc_hash_table_hash hash = {.key=(uint8_t*)&key, .entry_no=1, .step_size=5};
      set_valid_field(table, hash.entry_no  + j * hash.step_size, false);
      set_hop_count(table, hash.entry_no + (i + 1)* hash.step_size, MAX_HOP_COUNT);
      check_key_not_found(table, &hash, -ENOSPC);
      sc_hash_table_free(table);
    }
  }
}
END_TEST

START_TEST(find_key_test_key_found_on_wrap_around)
{
  struct sc_hash_table* table = create_table_with_capacity_and_check_initialised(sizeof(unsigned),
                                                                   sizeof(unsigned),
                                                                   10);
  add_hop_route(table, table->table_mask, 5, 3);
  unsigned key = 1;
  struct sc_hash_table_hash hash = {.key=(uint8_t*)&key, .entry_no=table->table_mask, .step_size=5};
  check_found_key_value(table, &hash, key);
  sc_hash_table_free(table);
}
END_TEST

START_TEST(find_key_test_no_key_on_back_to_start_no_space)
{
  struct sc_hash_table* table = create_table_with_capacity_and_check_initialised(sizeof(unsigned),
                                                                   sizeof(unsigned),
                                                                   10);

  add_hop_route(table, 4, 4, DEFAULT_HOP_MAX); /* capacity of 10 gives size 16 */
  unsigned key = DEFAULT_HOP_MAX + 1;
  struct sc_hash_table_hash hash = {.key=(uint8_t*)&key, .entry_no=4, .step_size=4};
  check_key_not_found(table, &hash, -ENOSPC);
  sc_hash_table_free(table);
}
END_TEST

START_TEST(find_key_test_no_key_on_back_to_start_space)
{
  struct sc_hash_table* table = create_table_with_capacity_and_check_initialised(sizeof(unsigned),
                                                                   sizeof(unsigned),
                                                                   10);

  add_hop_route(table, 4, 4, DEFAULT_HOP_MAX); /* capacity of 10 gives size 16 */
  set_valid_field(table, 12, false);
  unsigned key = DEFAULT_HOP_MAX + 1;
  struct sc_hash_table_hash hash = {.key=(uint8_t*)&key, .entry_no=4, .step_size=4};
  check_key_not_found(table, &hash, -ENOENT);
  sc_hash_table_free(table);
}
END_TEST

START_TEST(insert_key_test_insert_first_position)
{
  struct sc_hash_table* table = create_and_populate_hash_table_with_route(1, 10, DEFAULT_HOP_MAX);
  unsigned key = 0;
  struct sc_hash_table_hash hash = {.key=(uint8_t*)&key, .entry_no=1, .step_size=10};
  struct sc_hash_table_entry* entry = get_entry(table, hash.entry_no);
  check_insert_key_at_entry(table, &hash, entry, hash.entry_no);
  sc_hash_table_free(table);
}
END_TEST

START_TEST(insert_key_test_insert_all_positions)
{
  unsigned i;
  for( i = 0; i < DEFAULT_HOP_MAX; ++i ) {
    struct sc_hash_table* table = create_and_populate_hash_table_with_route(1, 10, DEFAULT_HOP_MAX);
    unsigned key = 0;
    struct sc_hash_table_hash hash = {.key=(uint8_t*)&key, .entry_no=1, .step_size=10};
    struct sc_hash_table_entry* entry = get_entry(table, hash.entry_no + i * hash.step_size);
    check_insert_key_at_entry(table, &hash, entry, hash.entry_no + i * hash.step_size);
    sc_hash_table_free(table);
  }
}
END_TEST

START_TEST(remove_key_test_remove_first_position)
{
  struct sc_hash_table* table = create_and_populate_hash_table_with_route(1, 10, DEFAULT_HOP_MAX);
  unsigned key = 0;
  struct sc_hash_table_hash hash = {.key=(uint8_t*)&key, .entry_no=1, .step_size=10};
  struct sc_hash_table_entry* entry = get_entry(table, hash.entry_no);
  check_remove_key_at_entry(table, &hash, entry, hash.entry_no);
  sc_hash_table_free(table);
}
END_TEST

START_TEST(remove_key_test_remove_all_positions)
{
  unsigned i;
  for( i = 0; i < DEFAULT_HOP_MAX; ++i ) {
    struct sc_hash_table* table = create_and_populate_hash_table_with_route(1, 10, DEFAULT_HOP_MAX);
    unsigned key = 0;
    struct sc_hash_table_hash hash = {.key=(uint8_t*)&key, .entry_no=1, .step_size=10};
    struct sc_hash_table_entry* entry = get_entry(table, hash.entry_no + i * hash.step_size);
    check_remove_key_at_entry(table, &hash, entry, hash.entry_no + i * hash.step_size);
    sc_hash_table_free(table);
  }
}
END_TEST

START_TEST(get_next_entry_test_loop_over_everything)
{
  struct sc_hash_table* table = create_empty_hash_table();
  unsigned valid_entries[table->table_mask + 1];
  unsigned i;
  for( i = 0; i < table->table_mask + 1; ++i )
      valid_entries[i] = i;
  check_entries(table, valid_entries, table->table_mask + 1);
  sc_hash_table_free(table);
}
END_TEST

START_TEST(get_next_entry_test_loop_over_nothing)
{
  struct sc_hash_table* table = create_empty_hash_table();
  check_entries(table, NULL, 0);
  sc_hash_table_free(table);
}
END_TEST

START_TEST(get_next_entry_test_all_but_one_valid)
{
  struct sc_hash_table* table = create_empty_hash_table();
  unsigned valid_entries[table->table_mask + 1];
  unsigned i;
  unsigned j = 0;
  for( i = 0; i < table->table_mask + 1; ++i )
    if( i != 42 )
      valid_entries[j++] = i;
  check_entries(table, valid_entries, table->table_mask + 1);
  sc_hash_table_free(table);
}
END_TEST

START_TEST(get_next_entry_test_all_but_one_invalid)
{
  struct sc_hash_table* table = create_empty_hash_table();
  unsigned valid_entries[] = {42};
  check_entries(table, valid_entries, 1);
  sc_hash_table_free(table);
}
END_TEST

START_TEST(hash_table_get_test_finds_key_with_insert_flag)
{
  struct sc_hash_table* table = create_empty_hash_table();
  unsigned key = 123;
  struct sc_hash_table_hash hash;
  sc_hash_table_double_hash(table, (uint8_t*)&key, &hash);
  unsigned i;
  for( i = 0; i < table->max_hops; ++i) {
    sc_hash_table_clear(table);
    add_hop_route(table, hash.entry_no, hash.step_size, MAX_HOP_COUNT);
    memcpy(get_entry(table, (hash.entry_no + i * hash.step_size) & table->table_mask)->key, &key, sizeof(key));
    check_get(table, key, true, 0, i);
  }
  sc_hash_table_free(table);
}
END_TEST

START_TEST(hash_table_get_test_finds_key_without_insert_flag)
{
  struct sc_hash_table* table = create_empty_hash_table();
  unsigned key = 123;
  struct sc_hash_table_hash hash;
  sc_hash_table_double_hash(table, (uint8_t*)&key, &hash);
  unsigned i;
  for( i = 0; i < table->max_hops; ++i) {
    sc_hash_table_clear(table);
    add_hop_route(table, hash.entry_no, hash.step_size, MAX_HOP_COUNT);
    memcpy(get_entry(table, (hash.entry_no + i * hash.step_size) & table->table_mask)->key, &key, sizeof(key));
    check_get(table, key, false, 0, i);
  }
  sc_hash_table_free(table);
}
END_TEST

START_TEST(hash_table_get_test_fails_to_find_key_can_insert_with_insert_flag)
{
  struct sc_hash_table* table = create_empty_hash_table();
  unsigned key = 123;
  struct sc_hash_table_hash hash;
  sc_hash_table_double_hash(table, (uint8_t*)&key, &hash);
  unsigned i;
  for( i = 0; i < table->max_hops; ++i) {
    sc_hash_table_clear(table);
    add_hop_route(table, hash.entry_no, hash.step_size, MAX_HOP_COUNT);
    set_valid_field(table, (hash.entry_no + i * hash.step_size) & table->table_mask, false);
    check_get(table, key, true, 1, i);
  }
  sc_hash_table_free(table);
}
END_TEST

START_TEST(hash_table_get_test_fails_to_find_key_can_insert_without_insert_flag)
{
  struct sc_hash_table* table = create_empty_hash_table();
  unsigned key = 123;
  struct sc_hash_table_hash hash;
  sc_hash_table_double_hash(table, (uint8_t*)&key, &hash);
  unsigned i;
  for( i = 0; i < table->max_hops; ++i) {
    sc_hash_table_clear(table);
    add_hop_route(table, hash.entry_no, hash.step_size, MAX_HOP_COUNT);
    set_valid_field(table, (hash.entry_no + i * hash.step_size) & table->table_mask, false);
    check_get(table, key, false, -ENOENT, -1);
  }
  sc_hash_table_free(table);
}
END_TEST

START_TEST(hash_table_get_test_fails_to_find_key_cannot_insert_with_insert_flag)
{
  struct sc_hash_table* table = create_empty_hash_table();
  unsigned key = 123;
  struct sc_hash_table_hash hash;
  sc_hash_table_double_hash(table, (uint8_t*)&key, &hash);
  add_hop_route(table, hash.entry_no, hash.step_size, MAX_HOP_COUNT);
  check_get(table, key, true, -ENOSPC, -1);
  sc_hash_table_free(table);
}
END_TEST

START_TEST(hash_table_get_test_fails_to_find_key_cannot_insert_without_insert_flag)
{
  struct sc_hash_table* table = create_empty_hash_table();
  unsigned key = 123;
  struct sc_hash_table_hash hash;
  sc_hash_table_double_hash(table, (uint8_t*)&key, &hash);
  add_hop_route(table, hash.entry_no, hash.step_size, MAX_HOP_COUNT);
  check_get(table, key, false, -ENOENT, -1);
  sc_hash_table_free(table);
}
END_TEST

START_TEST(hash_table_del_test_finds_key)
{
  struct sc_hash_table* table = create_empty_hash_table();
  unsigned key = 123;
  struct sc_hash_table_hash hash;
  sc_hash_table_double_hash(table, (uint8_t*)&key, &hash);
  unsigned i;
  for( i = 0; i < table->max_hops; ++i) {
    sc_hash_table_clear(table);
    add_hop_route(table, hash.entry_no, hash.step_size, MAX_HOP_COUNT);
    unsigned entry_no = (hash.entry_no + i * hash.step_size) & table->table_mask;
    memcpy(get_entry(table, entry_no)->key, &key, sizeof(key));
    check_delete(table, &hash, key, entry_no);
  }
  sc_hash_table_free(table);
}
END_TEST

START_TEST(hash_table_del_test_does_not_find_key)
{
  struct sc_hash_table* table = create_empty_hash_table();
  unsigned key = 123;
  struct sc_hash_table_hash hash;
  sc_hash_table_double_hash(table, (uint8_t*)&key, &hash);
  add_hop_route(table, hash.entry_no, hash.step_size, MAX_HOP_COUNT);
  ck_assert_int_eq(sc_hash_table_del(table, (void**)&key), -ENOENT);
  sc_hash_table_free(table);
}
END_TEST

START_TEST(hash_table_del_val_test_finds_key)
{
  struct sc_hash_table* table = create_empty_hash_table();
  unsigned key = 123;
  struct sc_hash_table_hash hash;
  sc_hash_table_double_hash(table, (uint8_t*)&key, &hash);
  unsigned i;
  for( i = 0; i < table->max_hops; ++i) {
    sc_hash_table_clear(table);
    add_hop_route(table, hash.entry_no, hash.step_size, MAX_HOP_COUNT);
    unsigned entry_no = (hash.entry_no + i * hash.step_size) & table->table_mask;
    memcpy(get_entry(table, entry_no)->key, &key, sizeof(key));
    check_delete_val(table, &hash, key, entry_no);
  }
  sc_hash_table_free(table);
}
END_TEST

START_TEST(hash_table_del_val_test_does_not_find_key)
{
  struct sc_hash_table* table = create_empty_hash_table();
  unsigned key = 123;
  struct sc_hash_table_hash hash;
  sc_hash_table_double_hash(table, (uint8_t*)&key, &hash);
  add_hop_route(table, hash.entry_no, hash.step_size, MAX_HOP_COUNT);
  struct sc_hash_table_entry* entry = get_entry(table, 2);
  entry->valid = 0;
  ck_assert_int_eq(sc_hash_table_del_val(table, entry_value(table, entry)), -ENOENT);
  sc_hash_table_free(table);
}
END_TEST

START_TEST(hash_table_clear_test_clear_works)
{
  struct sc_hash_table* table = create_and_populate_hash_table_with_route(1, 10, DEFAULT_HOP_MAX);
  sc_hash_table_clear(table);
  check_table_cleared(table);
  sc_hash_table_free(table);
}
END_TEST

START_TEST(hash_table_copy_test_hash_table_empty_copy_works)
{
  struct sc_hash_table* table = create_empty_hash_table();
  struct sc_hash_table* table_to_copy = create_empty_hash_table();
  copy_and_check_entries(table, table_to_copy, 0);
  sc_hash_table_free(table);
  sc_hash_table_free(table_to_copy);
}
END_TEST

START_TEST(hash_table_copy_test_hash_table_with_entries_copy_no_hops_works)
{
  struct sc_hash_table* table_to_copy = create_fully_populated_table();
  struct sc_hash_table* table = create_empty_hash_table();
  copy_and_check_entries(table, table_to_copy, 0);
  sc_hash_table_free(table);
  sc_hash_table_free(table_to_copy);
}
END_TEST

START_TEST(hash_table_copy_test_hash_table_with_entries_copy_with_hops_works)
{
  struct sc_hash_table* table_to_copy = create_and_populate_hash_table_with_route(0, 1, DEFAULT_HOP_MAX);
  struct sc_hash_table* table = create_empty_hash_table();
  copy_and_check_entries(table, table_to_copy, 0);
  sc_hash_table_free(table);
  sc_hash_table_free(table_to_copy);
}
END_TEST

START_TEST(hash_table_copy_test_hash_table_with_too_many_collisions_fails)
{

  struct sc_hash_table* table_to_copy = create_table_with_collision_on_copy();
  struct sc_hash_table* table = create_empty_hash_table();
  copy_and_check_entries(table, table_to_copy, -ENOSPC);
  sc_hash_table_free(table);
  sc_hash_table_free(table_to_copy);
}
END_TEST


START_TEST(hash_table_grow_test_on_successful_copy_works)
{
  struct sc_hash_table* table_to_grow = create_fully_populated_table();
  size_t max_size = table_to_grow->entry_size * (table_to_grow->table_mask + 1) * 2;
  check_grown_table(table_to_grow, max_size, 0);
  sc_hash_table_free(table_to_grow);
}
END_TEST

START_TEST(hash_table_grow_test_on_bad_copy_fails)
{
  struct sc_hash_table* table_to_grow = create_table_with_collision_on_copy();
  size_t max_size = table_to_grow->entry_size * (table_to_grow->table_mask + 1) * 2;
  check_grown_table(table_to_grow, max_size, -ENOSPC);
  sc_hash_table_free(table_to_grow);
}
END_TEST

START_TEST(hash_table_grow_test_on_not_enough_space_fails)
{
  struct sc_hash_table* table_to_grow = create_fully_populated_table();
  size_t max_size = table_to_grow->entry_size * (table_to_grow->table_mask + 1) * 2 - 1;
  check_grown_table(table_to_grow, max_size, -ENOSPC);
  sc_hash_table_free(table_to_grow);
}
END_TEST

START_TEST(hash_table_grow_test_on_no_limit_works)
{
  struct sc_hash_table* table_to_grow = create_fully_populated_table();
  check_grown_table(table_to_grow, 0, 0);
  sc_hash_table_free(table_to_grow);
}
END_TEST

Suite * sc_logger_suite(void)
{
  Suite* s = suite_create("sc_hash_table");

  TCase* tc_maths_helpers = tcase_create("maths helpers");
  tcase_add_test(tc_maths_helpers, ceil_to_power_of_two_test);
  tcase_add_test(tc_maths_helpers, num_entries_from_small_capacity_test);
  tcase_add_test(tc_maths_helpers, num_entries_from_large_capacity_test);
  suite_add_tcase(s, tc_maths_helpers);

  TCase* tc_capacity_alloc_bad_args = tcase_create("capacity table alloc with bad args");
  tcase_add_test(tc_capacity_alloc_bad_args, capacity_table_alloc_test_bad_key_size);
  tcase_add_test(tc_capacity_alloc_bad_args, capacity_table_alloc_test_bad_capacity);
  suite_add_tcase(s, tc_capacity_alloc_bad_args);

  TCase* tc_capacity_alloc_good_args = tcase_create("capacity table alloc with good args");
  tcase_add_test(tc_capacity_alloc_good_args, capacity_table_alloc_test_with_reasonable_capacity);
  tcase_add_test(tc_capacity_alloc_good_args, capacity_table_alloc_test_with_min_capacity);
  tcase_add_test(tc_capacity_alloc_good_args, capacity_table_alloc_test_with_large_capacity);
  tcase_add_test(tc_capacity_alloc_good_args, capacity_table_alloc_test_with_reasonable_key_size);
  tcase_add_test(tc_capacity_alloc_good_args, capacity_table_alloc_test_with_min_key_size);
  tcase_add_test(tc_capacity_alloc_good_args, capacity_table_alloc_test_with_large_key_size);
  tcase_add_test(tc_capacity_alloc_good_args, capacity_table_alloc_test_with_reasonable_val_size);
  tcase_add_test(tc_capacity_alloc_good_args, capacity_table_alloc_test_with_min_val_size);
  tcase_add_test(tc_capacity_alloc_good_args, capacity_table_alloc_test_with_large_val_size);
  suite_add_tcase(s, tc_capacity_alloc_good_args);

  TCase* tc_size_alloc_bad_args = tcase_create("table size table alloc with bad args");
  tcase_add_test(tc_size_alloc_bad_args, table_alloc_test_bad_key_size);
  tcase_add_test(tc_size_alloc_bad_args, table_alloc_test_bad_max_hops);
  tcase_add_test(tc_size_alloc_bad_args, table_alloc_test_bad_num_entries);
  suite_add_tcase(s, tc_size_alloc_bad_args);

  TCase* tc_size_alloc_good_args = tcase_create("table size table alloc with good args");
  tcase_add_test(tc_size_alloc_good_args, table_alloc_test_with_reasonable_key_size);
  tcase_add_test(tc_size_alloc_good_args, table_alloc_test_with_min_key_size);
  tcase_add_test(tc_size_alloc_good_args, table_alloc_test_with_large_key_size);
  tcase_add_test(tc_size_alloc_good_args, table_alloc_test_with_reasonable_val_size);
  tcase_add_test(tc_size_alloc_good_args, table_alloc_test_with_min_val_size);
  tcase_add_test(tc_size_alloc_good_args, table_alloc_test_with_large_val_size);
  tcase_add_test(tc_size_alloc_good_args, table_alloc_test_with_reasonable_num_entries);
  tcase_add_test(tc_size_alloc_good_args, table_alloc_test_with_min_num_entries);
  tcase_add_test(tc_size_alloc_good_args, table_alloc_test_with_large_num_entries);
  tcase_add_test(tc_size_alloc_good_args, table_alloc_test_with_reasonable_max_hops);
  tcase_add_test(tc_size_alloc_good_args, table_alloc_test_with_min_max_hops);
  tcase_add_test(tc_size_alloc_good_args, table_alloc_test_with_max_max_hops);
  suite_add_tcase(s, tc_size_alloc_good_args);

  TCase* tc_find_key = tcase_create("find key function");
  tcase_add_test(tc_find_key, find_key_test_no_hop);
  tcase_add_test(tc_find_key, find_key_test_all_positions_upto_hop_max);
  tcase_add_test(tc_find_key, find_key_test_entry_empty);
  tcase_add_test(tc_find_key, find_key_test_entry_empty_all_positions_upto_hop_max);
  tcase_add_test(tc_find_key, find_key_test_no_match_all_entries_used);
  tcase_add_test(tc_find_key, find_key_test_match_after_a_max_hop_count_entry);
  tcase_add_test(tc_find_key, find_key_test_no_match_after_a_max_hop_count_entry);
  tcase_add_test(tc_find_key, find_key_test_get_first_gap_on_no_key);
  tcase_add_test(tc_find_key, find_key_test_get_first_empty_position_if_gap_before_max_hop_entry_on_no_key);
  tcase_add_test(tc_find_key, find_key_test_get_no_empty_position_if_gap_after_max_hop_entry_on_no_key);
  tcase_add_test(tc_find_key, find_key_test_no_key_on_back_to_start_space);
  tcase_add_test(tc_find_key, find_key_test_no_key_on_back_to_start_no_space);
  tcase_add_test(tc_find_key, find_key_test_key_found_on_wrap_around);
  suite_add_tcase(s, tc_find_key);

  TCase* tc_insert_key = tcase_create("insert key function");
  tcase_add_test(tc_insert_key, insert_key_test_insert_first_position);
  tcase_add_test(tc_insert_key, insert_key_test_insert_all_positions);
  suite_add_tcase(s, tc_insert_key);

  TCase* tc_remove_key = tcase_create("remove key function");
  tcase_add_test(tc_remove_key, remove_key_test_remove_first_position);
  tcase_add_test(tc_remove_key, remove_key_test_remove_all_positions);
  suite_add_tcase(s, tc_remove_key);

  TCase* tc_hash_table_loop = tcase_create("get next entry function");
  tcase_add_test(tc_hash_table_loop, get_next_entry_test_loop_over_everything);
  tcase_add_test(tc_hash_table_loop, get_next_entry_test_loop_over_nothing);
  tcase_add_test(tc_hash_table_loop, get_next_entry_test_all_but_one_valid);
  tcase_add_test(tc_hash_table_loop, get_next_entry_test_all_but_one_invalid);
  suite_add_tcase(s, tc_hash_table_loop);

  TCase* tc_hash_table_get = tcase_create("get entry function");
  tcase_add_test(tc_hash_table_get, hash_table_get_test_finds_key_with_insert_flag);
  tcase_add_test(tc_hash_table_get, hash_table_get_test_finds_key_without_insert_flag);
  tcase_add_test(tc_hash_table_get, hash_table_get_test_fails_to_find_key_can_insert_with_insert_flag);
  tcase_add_test(tc_hash_table_get, hash_table_get_test_fails_to_find_key_can_insert_without_insert_flag);
  tcase_add_test(tc_hash_table_get, hash_table_get_test_fails_to_find_key_cannot_insert_with_insert_flag);
  tcase_add_test(tc_hash_table_get, hash_table_get_test_fails_to_find_key_cannot_insert_without_insert_flag);
  suite_add_tcase(s, tc_hash_table_get);

  TCase* tc_hash_table_del = tcase_create("del entry function");
  tcase_add_test(tc_hash_table_del, hash_table_del_test_finds_key);
  tcase_add_test(tc_hash_table_del, hash_table_del_test_does_not_find_key);
  suite_add_tcase(s, tc_hash_table_del);

  TCase* tc_hash_table_del_val = tcase_create("del val entry function");
  tcase_add_test(tc_hash_table_del_val, hash_table_del_val_test_finds_key);
  tcase_add_test(tc_hash_table_del_val, hash_table_del_val_test_does_not_find_key);
  suite_add_tcase(s, tc_hash_table_del_val);

  TCase* tc_hash_table_clear = tcase_create("clear function");
  tcase_add_test(tc_hash_table_del_val, hash_table_clear_test_clear_works);
  suite_add_tcase(s, tc_hash_table_clear);

  TCase* tc_hash_table_copy_into_hash_table = tcase_create("hash table copy");
  tcase_add_test(tc_hash_table_copy_into_hash_table, hash_table_copy_test_hash_table_empty_copy_works);
  tcase_add_test(tc_hash_table_copy_into_hash_table, hash_table_copy_test_hash_table_with_entries_copy_no_hops_works);
  tcase_add_test(tc_hash_table_copy_into_hash_table, hash_table_copy_test_hash_table_with_entries_copy_with_hops_works);
  tcase_add_test(tc_hash_table_copy_into_hash_table, hash_table_copy_test_hash_table_with_too_many_collisions_fails);
  suite_add_tcase(s, tc_hash_table_copy_into_hash_table);

  TCase* tc_hash_table_grow_hash_table = tcase_create("hash table grow");
  tcase_add_test(tc_hash_table_grow_hash_table, hash_table_grow_test_on_successful_copy_works);
  tcase_add_test(tc_hash_table_grow_hash_table, hash_table_grow_test_on_bad_copy_fails);
  tcase_add_test(tc_hash_table_grow_hash_table, hash_table_grow_test_on_not_enough_space_fails);
  tcase_add_test(tc_hash_table_grow_hash_table, hash_table_grow_test_on_no_limit_works);
  suite_add_tcase(s, tc_hash_table_grow_hash_table);

  return s;
}


int main(int argc, char ** argv)
{
  Suite* s = sc_logger_suite();
  SRunner* sr = srunner_create(s);;
  srunner_run_all(sr, CK_NORMAL);
  unsigned number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);
  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
