/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#ifndef __SC_STATS_H__
#define __SC_STATS_H__


#define ST_CONSTANT(name, val)         enum { name = val };
#define ST_STRUCT(name)                struct name {
#define ST_FIELD_STR(name, len, kind)  char name[len];
#define ST_FIELD(type, name, kind)     type name;
#define ST_STRUCT_END                  };

#include "stats_tmpl.h"

#undef ST_CONSTANT
#undef ST_STRUCT
#undef ST_FIELD_STR
#undef ST_FIELD
#undef ST_STRUCT_END


extern int sc_stats_add_block(struct sc_thread*, const char* name,
                              const char* type_name, const char* type_code,
                              int id, int size, void* pp_area);

extern void sc_stats_add_info_str(struct sc_session*, const char* type_code,
                                  int id, const char* key, const char* val);

extern void sc_stats_add_info_int(struct sc_session*, const char* type_code,
                                  int id, const char* key, int64_t val);

extern void sc_stats_add_info_int_list(struct sc_session*,
                                       const char* type_code,
                                       int id, const char* key, int64_t val);

extern void sc_stats_add_info_nodelink(struct sc_session*, int from_id,
                                       const char* name, int to_id,
                                       const char* to_name_opt);


/* Initialise a 'stats' string field.  NB. The result may not be
 * nul-terminated.  That is okay for a stats field, but the result
 * must not be treated as a c-string.
 */
#define sc_stats_set_str(field, from)                   \
  sc_fill_char_buf((field), sizeof(field), (from))


#endif  /* __SC_STATS_H__ */
