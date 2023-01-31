/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#include <check.h>
#include <check_helpers.h>

/* Include C directly so that we can test static functions */
#include "../../components/sc_flow_balancer.c"


struct hash_table_meta {
  int* orig_return_values;
  int* return_values;
  size_t n_return_values;
  struct sc_hash_table** hash_tables;
  size_t n_hash_tables;
};


struct sc_hash_table {
  bool freed;
  void* entries;
  size_t num_entries;
};


static struct flow_state* get_initial_flow_state_list(
  struct flow_state*** flow_state_list, size_t** num_flow_states)
{
  static struct flow_state** int_flow_state_list = NULL;
  static size_t int_num_flow_states = 0;
  if( int_flow_state_list == NULL )
    int_flow_state_list = malloc(sizeof(*int_flow_state_list));
  *flow_state_list = int_flow_state_list;
  *num_flow_states = &int_num_flow_states;
}


static struct hash_table_meta* get_meta(void)
{
  static struct hash_table_meta meta;
  return &meta;
}


static struct sc_hash_table* alloc_hash_table(void)
{
  struct hash_table_meta* meta = get_meta();
  meta->hash_tables = realloc(meta->hash_tables, sizeof(*meta->hash_tables)*(++(meta->n_hash_tables)));
  size_t new_table_index = meta->n_hash_tables - 1;
  meta->hash_tables[new_table_index] = malloc(sizeof(**meta->hash_tables));
  meta->hash_tables[new_table_index]->freed = false;
  meta->hash_tables[new_table_index]->num_entries = 0;
  return meta->hash_tables[new_table_index];
}


static void check_and_free_hash_tables(struct hash_table_meta* meta)
{
  unsigned i;
  unsigned last_entry = meta->n_hash_tables - 1;
  for( i = 0; i < last_entry; ++i ) {
    ck_assert(meta->hash_tables[i]->freed);
    free(meta->hash_tables[i]);
  }
  ck_assert(!meta->hash_tables[last_entry]->freed);
  free(meta->hash_tables[last_entry]);
  free(meta->hash_tables);
  meta->n_hash_tables = 0;
  meta->hash_tables = NULL;
}


static void _ut_sc_hash_table_setup(int* return_values,
                                    size_t n_return_values)
{
  struct hash_table_meta* meta = get_meta();
  assert(meta->return_values == NULL &&
         meta->orig_return_values == NULL &&
         meta->n_return_values == 0);
  meta->return_values = malloc(sizeof(*return_values) * n_return_values);
  memcpy(meta->return_values, return_values, n_return_values * sizeof(*return_values));
  meta->orig_return_values = meta->return_values;
  meta->n_return_values = n_return_values;
}


#define ut_sc_hash_table_setup(return_values) \
        _ut_sc_hash_table_setup((return_values), sizeof(return_values)/sizeof((return_values)[0]))

static int ut_sc_hash_table_get_return_value()
{
  struct hash_table_meta* meta = get_meta();
  assert(meta->n_return_values > 0);
  --meta->n_return_values;
  return *(meta->return_values++);
}


static int check_and_clear_meta()
{
  struct hash_table_meta* meta = get_meta();
  ck_assert_int_eq(meta->n_return_values, 0);
  free(meta->orig_return_values);
  meta->orig_return_values = NULL;
  meta->return_values = NULL;
  meta->n_return_values = 0;
  check_and_free_hash_tables(meta);
}


int sc_hash_table_alloc(struct sc_hash_table** table_out,
                        unsigned key_size, unsigned val_size,
                        unsigned capacity)
{
  *table_out = alloc_hash_table();
  return ut_sc_hash_table_get_return_value();
}


void sc_hash_table_free(struct sc_hash_table* table)
{
  table->freed = true;
}


int sc_hash_table_get(struct sc_hash_table* table, const void* key,
                      bool insert_if_not_found, void** val_out)
{
  int rc = ut_sc_hash_table_get_return_value();
  /* current tests only insert or fail */
  assert( rc == -ENOSPC || rc == 1 );
  if( rc == 1 )
    *val_out = malloc(sizeof(struct flow_state));
  return rc;
}


int sc_hash_table_del_val(struct sc_hash_table* table, const void* val)
{
  return ut_sc_hash_table_get_return_value();
}


const void* sc_hash_table_val_to_key(struct sc_hash_table* table, const void* val)
{
  return NULL;
}


static struct flow_balancer* get_and_init_node_struct(size_t capacity)
{
  static struct flow_balancer fb;
  static struct sc_flow_balancer_stats stats;
  fb.flow_table_capacity = capacity;
  fb.stats = &stats;
  fb.stats->flow_table_capacity = capacity;
  fb.n_grow_attempts = 3;
  struct sc_hash_table* flow_table = alloc_hash_table();
  /* assume that no malloc'd flow table has been placed on this struct */
  assert( fb.flow_table == NULL );
  fb.flow_table = flow_table;
  int i;
  for( i = 0; i < N_FLOW_TYPES; ++i )
    sc_dlist_init(&(fb.lru[i]));
  return &fb;
}


static void set_n_flows(struct flow_balancer* fb, size_t n_flows)
{
  struct flow_state** flow_state_list;
  size_t* num_states;
  get_initial_flow_state_list(&flow_state_list, &num_states);
  assert(*num_states == 0);
  *flow_state_list = malloc(sizeof(**flow_state_list) * n_flows);
  unsigned i;
  for( i = 0; i < n_flows; ++i )
  {
    (*flow_state_list)[i].output_id = i;
    /* Real node never seems to use flow type 1 */
    sc_dlist_push_tail(&(fb->lru[0]), &((*flow_state_list)[i].link));
  }
  *num_states = n_flows;
}


static void check_and_clean_up(struct flow_balancer* fb)
{
  check_and_clear_meta();
  fb->flow_table = NULL;
  struct flow_state** flow_state_list;
  size_t* num_states;
  get_initial_flow_state_list(&flow_state_list, &num_states);
  unsigned i;
  for( i = 0; i < *num_states; ++i )
  {
    ck_assert(!sc_dlist_is_empty(&fb->lru[0]));
    struct flow_state* fs = SC_CONTAINER(
      struct flow_state, link, sc_dlist_pop_head(&fb->lru[0])
    );
    ck_assert_int_eq(fs->output_id, (*flow_state_list)[i].output_id);
    free(fs);
  }
  ck_assert(sc_dlist_is_empty(&fb->lru[0]));
  ck_assert(sc_dlist_is_empty(&fb->lru[1]));
  if( *num_states > 0 )
    free(*flow_state_list);

  *flow_state_list = NULL;
  *num_states = 0;
}


/* test data -------------------------------------------------------------- */

START_TEST(TEST_that_it_can_grow_once_no_flows)
{
  size_t starting_capacity = 8;
  struct flow_balancer* fb = get_and_init_node_struct(starting_capacity);
  int return_values[] = {0}; /* alloc succeeds no other calls needed*/
  ut_sc_hash_table_setup(return_values);
  flow_table_grow(fb);
  ck_assert_int_eq(fb->stats->flow_table_capacity, starting_capacity * 2);
  ck_assert_int_eq(fb->flow_table_capacity, starting_capacity * 2);
  check_and_clean_up(fb);
}
END_TEST


START_TEST(TEST_that_it_can_grow_once_two_flows)
{
  size_t starting_capacity = 8;
  size_t num_flows = 2;
  struct flow_balancer* fb = get_and_init_node_struct(starting_capacity);
  int return_values[] = {
    0,  /* alloc succeeds */
    1,  /* get makes an insert in the new table */
    1   /* get makes an insert in the new table */
  };
  ut_sc_hash_table_setup(return_values);
  set_n_flows(fb, 2);
  flow_table_grow(fb);
  ck_assert_int_eq(fb->stats->flow_table_capacity, starting_capacity * 2);
  ck_assert_int_eq(fb->flow_table_capacity, starting_capacity * 2);
  check_and_clean_up(fb);
}
END_TEST


START_TEST(TEST_that_it_can_grow_twice_two_flows)
{
  size_t starting_capacity = 8;
  size_t num_flows = 2;
  struct flow_balancer* fb = get_and_init_node_struct(starting_capacity);
  int return_values[] = {
    0,  /* alloc succeeds */
    1,  /* get makes an insert in the new table */
    -ENOSPC,   /* get fails an insert in the new table */
    0,  /* alloc succeeds */
    1,  /* get makes an insert in the new table */
    1,  /* get makes an insert in the new table */
  };
  ut_sc_hash_table_setup(return_values);
  set_n_flows(fb, 2);
  flow_table_grow(fb);
  ck_assert_int_eq(fb->stats->flow_table_capacity, starting_capacity * 4);
  ck_assert_int_eq(fb->flow_table_capacity, starting_capacity * 4);
  check_and_clean_up(fb);
}
END_TEST


/* set up and run --------------------------------------------------------- */
int main(int argc, const char *argv[]) {
  int number_failed;
  Suite *s = suite_create("sc_flow_balancer tests");
  TCase *tc_node = tcase_create("sc_flow_balancer hash table grow tests");
  tcase_add_test(tc_node,
                 TEST_that_it_can_grow_once_no_flows);
  tcase_add_test(tc_node,
                 TEST_that_it_can_grow_once_two_flows);
  tcase_add_test(tc_node,
                 TEST_that_it_can_grow_twice_two_flows);
  suite_add_tcase(s, tc_node);
  SRunner *sr = srunner_create(s);
  const char *progname;
  char logfile[512];

  progname = strrchr(argv[0], '/');
  if (progname) {
    progname++;
  } else {
    progname = argv[0];
  }
  snprintf(logfile, sizeof(logfile), "%s.out", progname);

  srunner_set_log(sr, logfile);
  srunner_run_all(sr, CK_VERBOSE);
  number_failed = srunner_ntests_failed(sr);
  srunner_free(sr);

  return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
