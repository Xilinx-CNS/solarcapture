/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/*
 *  Functions to stub nodes.
 *
 *  In alphabetical order.
 *
 */
#include "internal.h"

void sc_forward_list2(const struct sc_node_link* hop,
                      struct sc_packet_list* pl) {}

void sc_forward2(const struct sc_node_link* link,
                        struct sc_packet* packet) {}

void sc_montype_field(struct sc_session* tg, const char* name,
                      const char* type, const char* kind, const char* more) {}

void sc_montype_flush(struct sc_session* tg) {}

void sc_montype_struct(struct sc_session* tg, const char* name) {}

void sc_montype_struct_end(struct sc_session* tg) {}

int sc_node_export_state(struct sc_node* node, const char* type_name,
                         int size, void* pp_area)
{
  return 0;
}

int sc_node_init_get_arg_int(int* v_out, struct sc_node* node,
                             const char* name, int v_default)
{
  return 1;
}

int sc_node_init_get_arg_str(const char** v_out, struct sc_node* node,
                             const char* name, const char* v_default)
{
  return 1;
}

struct sc_thread* sc_node_get_thread(const struct sc_node* node)
{
  return NULL;
}

void sc_node_link_end_of_stream2(const struct sc_node_link* link) {}

int sc_node_prep_check_links(struct sc_node* node)
{
  return 0;
}

const struct sc_node_link*
sc_node_prep_get_link_or_free(struct sc_node* node, const char* link_name)
{
  return NULL;
}

const struct sc_node_link*
sc_node_prep_get_link(struct sc_node* node, const char* link_name)
{
  return NULL;
}

int __sc_node_set_error(struct sc_node* node, const char* file, int line,
                        const char* func, int errno_code, const char* fmt, ...)
{
  return -1;
}

int sc_node_type_alloc(struct sc_node_type** nt_out,
                       const struct sc_attr* attr_opt,
                       const struct sc_node_factory* factory)
{
  return 0;
}

struct sc_session* sc_thread_get_session(const struct sc_thread* thread)
{
  return 0;
}

void sc_trace(struct sc_session* tg, const char* fmt, ...)
{
}

void sc_timer_expire_after_ns(struct sc_callback* cb, int64_t delta_ns)
{
}

int sc_pool_get_packets(struct sc_packet_list* list, struct sc_pool* pool,
                        int min_packets, int max_packets)
{
  return max_packets;
}

int sc_node_add_link(struct sc_node* from_node, const char* link_name,
                     struct sc_node* to_node, const char* to_name_opt)
{
  return 0;
}

int sc_callback_alloc2(struct sc_callback** cb_out, const struct sc_attr* attr,
                       struct sc_thread* thread, const char* description)
{
  return 0;
}

extern void* sc_thread_calloc(struct sc_thread* thread, size_t bytes)
{
  return NULL;
}

void sc_thread_mfree(struct sc_thread* thread, void* mem)
{
}

void sc_realloc(void* pp_area, size_t new_size)
{
  return;
}


void sc_node_add_info_str(struct sc_node* node,
  const char* field_name, const char* field_val)
{
}

void sc_node_add_info_int(struct sc_node* node,
  const char* field_name, int64_t field_val)
{
}

int sc_node_alloc_named(struct sc_node** node_out,
                        const struct sc_attr* attr,
                        struct sc_thread* thread,
                        const char* factory_name,
                        const char* lib_name,
                        const struct sc_arg* args, int n_args)
{
  return 0;
}

int sc_node_init_get_arg_int64(int64_t* v_out, struct sc_node* node,
                               const char* name, int64_t v_default)
{
  return 0;
}

struct sc_attr* sc_attr_dup(const struct sc_attr* attr)
{
  return NULL;
}

void sc_err(struct sc_session* tg, const char* fmt, ...)
{
  va_list va;
  va_start(va, fmt);
  vprintf(fmt, va);
  va_end(va);
}


static struct timespec node_stub_time;

void sc_thread_get_time(const struct sc_thread* t, struct timespec* time_out)
{
  *time_out = node_stub_time;
}


void node_stub_sc_thread_set_time(uint32_t sec, uint32_t nsec)
{
  node_stub_time.tv_sec = sec;
  node_stub_time.tv_nsec = nsec;
}
