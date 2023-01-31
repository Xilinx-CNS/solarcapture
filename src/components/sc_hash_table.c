/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/** \cond NODOC */
#include <sc_internal.h>
#include <sc_internal/hash.h>

#include <errno.h>
#include <string.h>
#include <stdbool.h>

#define HALF_UINT32_BITS  16u
#define MAX_HOP_COUNT     0x7f
#define DEFAULT_HOP_MAX   10
#define MAX_HASH_TABLE_SIZE (1u << 31)

struct sc_hash_table_entry {
  uint8_t   hop_count : 7;
  uint8_t   valid : 1;
  uint8_t   key[1];
};


struct sc_hash_table {
  uint8_t*  table;
  unsigned  table_mask;
  unsigned  max_hops;
  unsigned  n_entries;
  unsigned  key_size;
  unsigned  val_size;
  size_t    entry_size;
};


struct sc_hash_table_hash {
  const uint8_t*      key;
  unsigned            entry_no;
  unsigned            step_size;
};



static inline struct sc_hash_table_entry*
get_entry(struct sc_hash_table* table, unsigned i)
{
  assert(i <= table->table_mask);
  void* p = table->table + i * table->entry_size;
  return p;
}

static inline bool is_power_of_two(unsigned value)
{
  return (value & (value - 1)) == 0;
}


static inline bool entry_is_end_of_list(struct sc_hash_table* table,
                                        struct sc_hash_table_entry* entry)
{
  return (entry->hop_count == 0) && !(entry->valid);
}


static inline void* entry_value(struct sc_hash_table* table,
                                struct sc_hash_table_entry* entry)
{
  return (uint8_t*)(entry->key) + table->key_size;
}


static inline struct sc_hash_table_entry*
get_entry_from_value(struct sc_hash_table* table, const void* value)
{
  return (struct sc_hash_table_entry*)((uint8_t*)value - table->key_size -
                                        sizeof(struct sc_hash_table_entry) + 1);
}


static inline unsigned hop_to_next_entry(struct sc_hash_table* table,
                                         unsigned entry_no,
                                         unsigned step_size)
{
  return (entry_no + step_size) & (table->table_mask);
}


/* Creates a double hash for inserting or finding a key in the table.
 *
 * The first hash of size key size is used to calculate the entry no in the first
 * position in the table we should look to insert/find the key
 *
 * The second hash is used to calculate the step size. If we find a collision in
 * the table this tells us where to jump to next and try to find/insert our key
 * It is important that the number is odd and therefore co-prime with the table
 * size. This will mean that we have to go through every entry in the table
 * before we get back to our original starting point.
 */
static inline void
sc_hash_table_double_hash(struct sc_hash_table* table, const uint8_t* key,
                          struct sc_hash_table_hash* hash)
{
  uint32_t raw_hash = sc_hash(key, table->key_size);
  hash->key = key;
  hash->step_size = ((raw_hash >> 5u) & table->table_mask) | 1;
  hash->entry_no = raw_hash & table->table_mask;
}


static inline uint32_t ceil_to_power_of_two(unsigned value)
{
  if( value == 1 )
    return 1;
  else
    return 1 << (32u - __builtin_clz(value - 1));
}


/*
 * This function updates the state of the entries in the table when an entry is
 * removed or inserted.
 *
 * When we insert or remove a key from a table we must update the hop count for
 * entry we are inserting into / removing and all the entries we jumped to
 * in getting from the hash entry_no to it.
 */
static void update_hop_count(struct sc_hash_table* table,
                             struct sc_hash_table_hash* hash,
                             struct sc_hash_table_entry* stop_entry,
                             int count_modifier)
{
  struct sc_hash_table_entry* entry;
  unsigned entry_no = hash->entry_no;
  while( 1 ) {
    entry = get_entry(table, entry_no);
    if( entry == stop_entry )
      return;
    entry->hop_count += count_modifier;
    entry_no = hop_to_next_entry(table, entry_no, hash->step_size);
  }
}


static int sc_hash_table_initialise(struct sc_hash_table* table, unsigned key_size,
                                    unsigned val_size, unsigned num_entries,
                                    unsigned max_hops)
{
  table->table_mask = num_entries - 1;
  table->max_hops = max_hops;
  table->n_entries = 0;
  table->key_size = key_size;
  table->val_size = val_size;

  struct sc_hash_table_entry* entry = NULL;
  table->entry_size = (uint8_t*)entry_value(table, entry) + val_size - (uint8_t*) entry;
  if( (table->table = malloc(num_entries * table->entry_size)) == NULL )
    return -ENOMEM;
  return 0;
}


int sc_hash_table_alloc_with_num_entries(struct sc_hash_table** table_out,
                                         unsigned key_size, unsigned val_size,
                                         unsigned num_entries, unsigned max_hops)
{
  if( key_size < 1 ||
      num_entries < 1 || !is_power_of_two(num_entries) ||
      max_hops > MAX_HOP_COUNT )
    return -EINVAL;

  struct sc_hash_table* table = calloc(1, sizeof(*table));
  if( table == NULL )
    return -ENOMEM;

  int rc;
  if( (rc = sc_hash_table_initialise(table, key_size, val_size, num_entries, max_hops)) != 0 ) {
    free(table);
    return rc;
  }

  sc_hash_table_clear(table);
  *table_out = table;
  return 0;
}



/* loop until one of these conditions is met;
 *    - We find an entry in the hash table with a key that matches.
 *
 *    - We reach a entry with a hop count of zero and no entry has been found
 *
 *    - We loop back round to our start point without finding the key
 *
 * If we find a key that matches we set final_entry_no to be the position where
 * we found it and set entry to point to the entry in the table.
 *
 * If we fail to find the key and we found a place where the key could have been
 * inserted we return -ENOENT set entry to point to the empty entry in the table.
 *
 * If we fail to find the key and don't find a space where an insert could be made
 * we return -ENOSPC.
 */
static inline int find_key(struct sc_hash_table* table,
                           struct sc_hash_table_hash* hash,
                           struct sc_hash_table_entry** entry)
{
  unsigned hops = 0;
  unsigned first_free_entry_no = 0;
  bool can_insert = true;
  bool found_first_free_entry = false;

  unsigned final_entry_no = hash->entry_no;
  do {
    *entry = get_entry(table, final_entry_no);
    if( (*entry)->valid ) {
      if( memcmp(hash->key, (*entry)->key, table->key_size) == 0 )
        return 0;
    }
    else {
      if( !found_first_free_entry ) {
        found_first_free_entry = true;
        first_free_entry_no = final_entry_no;
      }
      if( entry_is_end_of_list(table, *entry) )
            break;
    }

    if( (*entry)->hop_count == MAX_HOP_COUNT && !found_first_free_entry )
      can_insert = false;

    final_entry_no = hop_to_next_entry(table, final_entry_no, hash->step_size);
    ++hops;
  } while( final_entry_no != hash->entry_no && hops < table->max_hops );

  if( !can_insert || !found_first_free_entry )
    return -ENOSPC;

  *entry = get_entry(table, first_free_entry_no);
  return -ENOENT;
}


static inline void* insert_key(struct sc_hash_table* table,
                               struct sc_hash_table_hash* hash,
                               struct sc_hash_table_entry* entry)
{

  entry->valid = 1;
  update_hop_count(table, hash, entry, 1);
  ++(table->n_entries);
  memcpy(entry->key, hash->key, table->key_size);
  return entry_value(table, entry);
}


static inline void remove_key(struct sc_hash_table* table,
                              struct sc_hash_table_hash* hash,
                              struct sc_hash_table_entry* entry)
{
  entry->valid = 0;
  update_hop_count(table, hash, entry, -1);
  --(table->n_entries);
}


static inline unsigned calculate_num_entries_from_capacity(unsigned capacity)
{
  uint64_t promoted_capacity = ((uint64_t)capacity * 5) / 4;
  return ceil_to_power_of_two(promoted_capacity <= MAX_HASH_TABLE_SIZE ? promoted_capacity : MAX_HASH_TABLE_SIZE);
}


int sc_hash_table_alloc(struct sc_hash_table** table_out, unsigned key_size,
                        unsigned val_size, unsigned capacity)
{
  if( capacity < 1 || capacity > MAX_HASH_TABLE_SIZE )
    return -EINVAL;
  return sc_hash_table_alloc_with_num_entries(table_out, key_size, val_size,
                                              calculate_num_entries_from_capacity(capacity),
                                              DEFAULT_HOP_MAX);
}


void sc_hash_table_free(struct sc_hash_table* table)
{
  free(table->table);
  free(table);
}


static int copy_hash_table_into_hash_table(struct sc_hash_table* table,
                                           struct sc_hash_table* table_to_insert)
{
  assert(table->n_entries == 0);
  assert(table->table_mask >= table_to_insert->table_mask);
  assert(table->key_size == table_to_insert->key_size);
  assert(table->val_size == table_to_insert->val_size);
  unsigned scratch = 0;
  void* key;
  void* value;
  void* new_table_value;
  int rc;
  while( sc_hash_table_get_next_entry(table_to_insert, &key, &value,
                                      &scratch) == 0 ) {
    if( (rc = sc_hash_table_get(table, key, true, &new_table_value)) != 1 )
      return rc;
    memcpy(new_table_value, value, table->val_size);
  }
  return 0;
}


int sc_hash_table_grow(struct sc_hash_table* table, size_t max_size)
{
  if( table->table_mask & (1u << 31) )
    return -ENOSPC;

  unsigned new_num_entries = (table->table_mask + 1) * 2;
  if( max_size > 0 && table->entry_size * new_num_entries > max_size )
    return -ENOSPC;

  struct sc_hash_table old_table;
  memcpy(&old_table, table, sizeof(old_table));

  int rc;
  if( (rc = sc_hash_table_initialise(table, old_table.key_size, old_table.val_size,
                                     new_num_entries, old_table.max_hops)) != 0 ) {
    memcpy(table, &old_table, sizeof(*table));
    return rc;
  }

  if( (rc = copy_hash_table_into_hash_table(table, &old_table)) != 0 ) {
    free(table->table);
    memcpy(table, &old_table, sizeof(*table));
    return rc;
  }

  free(old_table.table);
  return 0;
}


int sc_hash_table_get_next_entry(struct sc_hash_table* table, void** key_out,
                                 void** val_out, unsigned* scratch)
{
  while( *scratch <= table->table_mask ) {
    struct sc_hash_table_entry* entry = get_entry(table, *scratch);
    *scratch += 1;
    if( entry->valid ) {
      *key_out = entry->key;
      *val_out = entry_value(table, entry);
      return 0;
    }
  }
  return -ENOENT;
}


int sc_hash_table_get(struct sc_hash_table* table, const void* key,
                      bool insert_if_not_found, void** val_out)
{
  struct sc_hash_table_entry* entry;
  struct sc_hash_table_hash hash;
  sc_hash_table_double_hash(table, key, &hash);
  int rc = find_key(table, &hash, &entry);
  if( rc == 0 ) {
    *val_out = entry_value(table, entry);
  }
  else if( rc == -ENOENT && insert_if_not_found ) {
    *val_out = insert_key(table, &hash, entry);
    rc = 1;
  }
  else if( rc == -ENOSPC && !insert_if_not_found ) {
    rc = -ENOENT;
  }
  return rc;
}


int sc_hash_table_del(struct sc_hash_table* table, const void* key)
{
  struct sc_hash_table_entry* entry;
  struct sc_hash_table_hash hash;
  sc_hash_table_double_hash(table, key, &hash);
  if( find_key(table, &hash, &entry) == 0) {
    remove_key(table, &hash, entry);
    return 0;
  }
  else {
    return -ENOENT;
  }
}


int sc_hash_table_del_val(struct sc_hash_table* table, const void* val)
{
  struct sc_hash_table_entry* entry = get_entry_from_value(table, val);
  if( entry->valid )
    return sc_hash_table_del(table, entry->key);
  return -ENOENT;
}


void sc_hash_table_clear(struct sc_hash_table* table)
{
  unsigned int i;
  for( i = 0; i <= table->table_mask; ++i ) {
    get_entry(table, i)->valid = 0;
    get_entry(table, i)->hop_count = 0;
  }
  table->n_entries = 0;
}


const void* sc_hash_table_val_to_key(struct sc_hash_table* table,
                                     const void* value)
{
  return (uint8_t*)value - table->key_size;
}


unsigned int sc_hash_table_key_size(struct sc_hash_table* table)
{
  return table->key_size;
}


unsigned int sc_hash_table_val_size(struct sc_hash_table* table)
{
  return table->val_size;
}


unsigned int sc_hash_table_num_entries(struct sc_hash_table* table)
{
  return table->n_entries;
}

/** \endcond NODOC */
