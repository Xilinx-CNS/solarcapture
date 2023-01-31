/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \file
 * \brief A hash table with open addressing and double hashing.
 */

#ifndef __SC_HASH_TABLE_H__
#define __SC_HASH_TABLE_H__


#if SC_API_VER >= 4
/**
 * \struct sc_hash_table
 * \brief A hash table
 *
 * This is an opaque pointer to a hash table created using
 * sc_hash_table_alloc().
 *
 * NOTE: Hash tables are only supported on x86_64 and x86 CPUs with the SSE
 * 4.2 instruction set.  In particular, the CRC32 instruction is required.
 */
struct sc_hash_table;


/**
 * \brief Allocate an ::sc_hash_table.
 *
 * \param table_out The allocated ::sc_hash_table is returned here
 * \param key_size  The size in bytes of keys
 * \param val_size  The size in bytes of values
 * \param capacity  The desired number of entries in the hash table.
 *
 * \return 0 on success, or a negative error code.
 *
 * Note the underlying table is sized so that there is a high probability
 * you be able to insert @p capacity entries, but this cannot be
 * guaranteed.
 */
extern int sc_hash_table_alloc(struct sc_hash_table** table_out,
                               unsigned key_size, unsigned val_size,
                               unsigned capacity);


/** \cond NODOC */

/**
 * \brief Allocate an ::sc_hash_table.
 *
 * \param table_out A pointer to the allocated ::sc_hash_table is returned here
 * \param key_size The size in bytes of keys in the hash table
 * \param val_size The size in bytes of values in the hash table
 * \param num_entries The desired number of entries in the hash table. This must
 *                    be a power of 2.
 * \param max_hops The maximum number of hops allowed when inserting a key after
 *                 a hash collision.
 *
 * \return 0 on success, or a negative error code.
 */
extern int sc_hash_table_alloc_with_num_entries(struct sc_hash_table** table_out,
                                                unsigned key_size,
                                                unsigned val_size,
                                                unsigned num_entries,
                                                unsigned max_hops);
/** \endcond */


/**
 * \brief Free an ::sc_hash_table.
 *
 * \param table   A hash table
 */
extern void sc_hash_table_free(struct sc_hash_table* table);


/**
 * \brief Increase the capacity of a hash table.
 *
 * After this call all key and value pointers will be stale.
 *
 * \param table     A hash table
 * \param max_size  Maximum size of storage in bytes, or 0 for unlimited
 *
 * \return
 *   * 0 On success
 *   * -ENOSPC if it is not possible to grow the table further
 */
extern int sc_hash_table_grow(struct sc_hash_table* table, size_t max_size);


/**
 * \brief Lookup or insert an entry in a hash table.
 *
 * If the entry matching @p key is found then a pointer to the
 * corresponding value is returned in @p val_out.  Otherwise if @p
 * insert_if_not_found is true, then a new entry is inserted.
 *
 * \param table               A hash table
 * \param key                 The key to look for in the table
 * \param insert_if_not_found If true then an entry is inserted if not found
 * \param val_out             Pointer to value buffer returned here
 *
 * \return
 *   * 0 if the matching entry was found
 *   * 1 if @p insert_if_not_found was true and a new entry was added
 *   * -ENOENT if an entry was not found and @p insert_if_not_found was false
 *   * -ENOSPC if an entry was not found and it was not possible to insert a
 *     new entry
 */
extern int sc_hash_table_get(struct sc_hash_table* table, const void* key,
                             bool insert_if_not_found, void** val_out);


/**
 * \brief Remove an entry from an ::sc_hash_table by key.
 *
 * \param table   A hash table
 * \param key     The key to remove
 *
 * \return
 *   * 0 on success
 *   * -ENOENT if @p key was not found
 */
extern int sc_hash_table_del(struct sc_hash_table* table, const void* key);


/**
 *  \brief Remove an entry from an ::sc_hash_table by value.
 *
 *  \param table  A hash table
 *  \param val    Pointer to the value of an entry in the hash table
 *
 * @p val must be a valid pointer to an existing value stored in the hash
 * table.  ie. It must have been returned by sc_hash_table_get() or
 * sc_hash_table_get_next_entry().
 *
 * \return
 *   * 0 if the key was successfully removed
 *   * -ENOENT if the value was not in the table
 */
extern int sc_hash_table_del_val(struct sc_hash_table* table, const void* val);


/**
 *  \brief Clear all entries from an ::sc_hash_table.
 *
 *  \param table  A hash table
 */
extern void sc_hash_table_clear(struct sc_hash_table* table);


/**
 *  \brief Return the key associated with a given value.
 *
 *  \param table  A hash table
 *  \param val    Pointer to the value of an entries in the hash table
 *
 * @p val must be a valid pointer to an existing value stored in the hash
 * table.  ie. It must have been returned by sc_hash_table_get() or
 * sc_hash_table_get_next_entry().
 *
 * \return A pointer the key in the hash table
 *
 * NOTE: This function cannot check the value pointer was valid.
 */
extern const void* sc_hash_table_val_to_key(struct sc_hash_table* table,
                                            const void* val);


/**
 * \brief Get the size in bytes of a hash table's keys.
 *
 * \param table  A hash table
 *
 * \return The size in bytes of the hash table's keys.
 */
extern unsigned sc_hash_table_key_size(struct sc_hash_table* table);


/**
 * \brief Get the size in bytes of each value buffer.
 *
 * \param table  A hash table
 *
 * \return The size in bytes of each value buffer.
 */
extern unsigned sc_hash_table_val_size(struct sc_hash_table* table);


/**
 * \brief Get the number of entries in an ::sc_hash_table.
 *
 * \param table  A hash table
 *
 * \return The number of entries in the hash table.
 */
extern unsigned sc_hash_table_num_entries(struct sc_hash_table* table);


/**
 * \brief Iterate over key-value pairs in an ::sc_hash_table.
 *
 * \param table     A hash table
 * \param key_out   Pointer to the next key returned here
 * \param val_out   Pointer to the next value returned here
 * \param iterator  State used by the implementation to iterate over entries
 *
 * @p iterator must point to storage allocated by the caller and
 * initialised to zero before the first call.
 *
 * NOTE: This function is relatively inefficient for hash tables with a low
 * fill level because it scans entries linearly.
 *
 * \return
 *   * 0 on successfully finding the entry
 *   * -ENOENT when no further entries remain
 */
extern int sc_hash_table_get_next_entry(struct sc_hash_table* table,
                                        void** key_out,
                                        void** val_out,
                                        unsigned* iterator);


#endif
#endif  /* __SC_HASH_TABLE_H__ */
/** @} */
