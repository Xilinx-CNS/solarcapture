/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#include "internal.h"

#include <stdarg.h>


enum sc_attr_type {
  sc_attr_type_int,
  sc_attr_type_str,
};


#define SC_ATTR_TYPE_STORAGE_int  sc_attr_type_int
#define SC_ATTR_TYPE_STORAGE_size sc_attr_type_int
#define SC_ATTR_TYPE_STORAGE_str  sc_attr_type_str


struct sc_attr_info {
  const char*       name;
  enum sc_attr_type type;
  const char*       type_str;
  const char*       status;
  const char*       default_doc;
  const char*       objects;
  const char*       doc;
  int               offset;
  int               size;
  int (*parser)(void* dest, const char* val);
};


static int parse_str(void* dest, const char* val);


static int parse_int(void* dest, const char* val);


static int parse_size(void* dest, const char* val);


static struct sc_attr_info sc_attr_info[] = {
# define SC_ATTR(_type, _name, _status, _def_val, _def_doc, _objects, _doc) { \
  .name = #_name,                                                       \
  .type = SC_ATTR_TYPE_STORAGE_##_type,                                 \
  .type_str = #_type,                                                   \
  .status = #_status,                                                   \
  .default_doc = NULL,                                                  \
  .objects = _objects,                                                  \
  .doc = _doc,                                                          \
  .offset = SC_MEMBER_OFFSET(struct sc_attr, _name),                    \
  .size = SC_MEMBER_SIZE(struct sc_attr, _name),                        \
  .parser = parse_##_type                                               \
  },
# include <sc_internal/attr_tmpl.h>
# undef SC_ATTR
};


#define SC_ATTR_N                                       \
  (sizeof(sc_attr_info) / sizeof(sc_attr_info[0]))


static int sc_attr_from_str(struct sc_attr* attr, const char* str);


static void* get_field(struct sc_attr* attr, struct sc_attr_info* f)
{
  return (char*) attr + f->offset;
}


static char** get_field_str(struct sc_attr* attr, struct sc_attr_info* f)
{
  assert(f->type == sc_attr_type_str);
  return (char**) get_field(attr, f);
}


static void __sc_attr_free_fields(struct sc_attr* attr)
{
  struct sc_attr_info* f;
  for( f = sc_attr_info; f < sc_attr_info + SC_ATTR_N; ++f )
    if( f->type == sc_attr_type_str )
      free(*(get_field_str(attr, f)));
}


static void __sc_attr_reset(struct sc_attr* attr)
{
#define SC_ATTR(type, name, status, def_val, def_doc, objects, doc) \
  attr->name = def_val;
# include <sc_internal/attr_tmpl.h>
# undef SC_ATTR
}


static struct sc_attr* __sc_attr_alloc(void)
{
  struct sc_attr* attr = calloc(1, sizeof(struct sc_attr));
  if( attr == NULL )
    return NULL;
  sc_object_impl_init(&(attr->attr_obj), SC_OBJ_C_ATTR);
  __sc_attr_reset(attr);
  return attr;
}


int sc_attr_alloc(struct sc_attr** attr_out)
{
  struct sc_attr* attr = __sc_attr_alloc();
  *attr_out = attr;
  if( attr == NULL )
    return -ENOMEM;
  const char* default_attr_str = getenv("SC_ATTR");
  if( default_attr_str != NULL &&
      sc_attr_from_str(attr, default_attr_str) < 0 ) {
    fprintf(stderr, "%s: ERROR: bad SC_ATTR environment variable\n", __func__);
    return -EINVAL;
  }
  return 0;
}


void sc_attr_free(struct sc_attr* attr)
{
  __sc_attr_free_fields(attr);
  free(attr);
}


void sc_attr_reset(struct sc_attr* attr)
{
  __sc_attr_free_fields(attr);
  __sc_attr_reset(attr);
}


static void sc_attr_copy(struct sc_attr* to, const struct sc_attr* from)
{
  struct sc_attr_info* f;
  for( f = sc_attr_info; f < sc_attr_info + SC_ATTR_N; ++f )
    switch( f->type ) {
    case sc_attr_type_int: {
      memcpy(get_field(to, f), get_field((struct sc_attr*) from, f), f->size);
      break;
    }
    case sc_attr_type_str: {
      char* s = *(get_field_str((struct sc_attr*) from, f));
      char** p = get_field_str(to, f);
      free(*p);
      if( s == NULL )
        *p = NULL;
      else
        *p = strdup(s);
      break;
    }
    default:
      TEST(0);
    }
}


struct sc_attr* sc_attr_dup(const struct sc_attr* from)
{
  struct sc_attr* to = __sc_attr_alloc();
  if( to != NULL )
    sc_attr_copy(to, from);
  return to;
}


static struct sc_attr_info* sc_attr_info_find(const char* name)
{
  struct sc_attr_info* f;
  for( f = sc_attr_info; f < sc_attr_info + SC_ATTR_N; ++f )
    if( ! strcasecmp(name, f->name) )
      return f;
  return NULL;
}


int sc_attr_set_int(struct sc_attr* attr, const char* name, int64_t val)
{
  struct sc_attr_info* f;
  f = sc_attr_info_find(name);
  if( f != NULL ) {
    switch( f->type ) {
    case sc_attr_type_int:;
      SC_ATTR_TYPE_int* pi = get_field(attr, f);
      *pi = val;
      return 0;
    case sc_attr_type_str:;
      char** ps = get_field(attr, f);
      free(*ps);
      TEST( asprintf(ps, "%"PRId64, val) > 0 );
      return 0;
    default:
      TEST(0);
      break;
    }
  }
  fprintf(stderr, "%s: ERROR: no such attribute '%s'\n", __func__, name);
  return -ENOENT;
}


int sc_attr_set_str(struct sc_attr* attr, const char* name, const char* val)
{
  struct sc_attr_info* f;
  f = sc_attr_info_find(name);
  if( f != NULL ) {
    if( f->type != sc_attr_type_str ) {
      fprintf(stderr, "%s: ERROR: attribute '%s' has type %d\n",
              __func__, name, f->type);
      return -ENOMSG;
    }
    char** p = get_field(attr, f);
    free(*p);
    if( val != NULL )
      TEST(*p = strdup(val));
    else
      *p = NULL;
    return 0;
  }
  return -ENOENT;
}


static int parse_str(void* dest, const char* val)
{
  SC_ATTR_TYPE_str* out = dest;
  if( val[0] != '\0' )
    *out = strdup(val);
  else
    *out = NULL;
  return 0;
}


static int parse_int(void* dest, const char* val)
{
  SC_ATTR_TYPE_int* out = dest;
  char dummy;
  int64_t tmp;
  if( sscanf(val, "%"PRIi64"%c", &tmp, &dummy) != 1 )
    return -ENOMSG;
  *out = tmp;
  return 0;
}


static int parse_size(void* dest, const char* val)
{
  SC_ATTR_TYPE_int* out = dest;
  int64_t tmp;
  int rc = sc_parse_size_string(&tmp, val);
  if( rc == 0 )
    *out = tmp;
  return rc;
}


int sc_attr_set_from_str(struct sc_attr* attr, const char* name,
                         const char* val)
{
  struct sc_attr_info* f;
  if( (f = sc_attr_info_find(name)) == NULL ) {
    fprintf(stderr, "%s: ERROR: no such attribute '%s'\n", __func__, name);
    return -ENOENT;
  }
  switch( f->type ) {
  case sc_attr_type_int: {
    int64_t tmp;
    int rc = f->parser(&tmp, val);
    if( rc < 0 ) {
      fprintf(stderr, "%s: ERROR: could not parse value from '%s=%s'\n",
              __func__, name, val);
      return rc;
    }
    return sc_attr_set_int(attr, name, tmp);
  }
  case sc_attr_type_str: {
    char** pf = get_field_str(attr, f);
    free(*pf);
    int rc = f->parser(pf, val);
    if( rc < 0 )
      return rc;
    else
      return 0;
  }
  default:
    TEST(0);
    return 0;
  }
}


int sc_attr_set_from_fmt(struct sc_attr* attr,
                         const char* name, const char* fmt, ...)
{
  va_list va;
  va_start(va, fmt);
  char* val;
  int rc = vasprintf(&val, fmt, va);
  va_end(va);
  if( rc < 0 )
    return -ENOMEM;
  rc = sc_attr_set_from_str(attr, name, val);
  free(val);
  return rc;
}


static int __sc_attr_from_str(struct sc_attr* attr, char* str)
{
  char *next, *val;
  while( *str != '\0' ) {
    if( (next = strchr(str, ';')) != NULL ) {
      *next = '\0';
      ++next;
    }
    if( (val = strchr(str, '=')) == NULL ) {
      fprintf(stderr, "%s: missing '=' in '%s'\n", __func__, str);
      return -1;
    }
    *(val++) = '\0';
    int rc = sc_attr_set_from_str(attr, str, val);
    if( rc < 0 )
      return rc;
    if( (str = next) == NULL )
      break;
  }
  return 0;
}


static int sc_attr_from_str(struct sc_attr* attr, const char* str)
{
  char* s = strdup(str);
  int rc = __sc_attr_from_str(attr, s);
  free(s);
  return rc;
}

/**********************************************************************
 * Built-in attribute documentation.
 */

static const char* sc_attr_default_sc_attr_type_str(const char* val)
{
  return val ? val : strdup("");
}


static const char* sc_attr_default_sc_attr_type_int(SC_ATTR_TYPE_int val)
{
  char* s;
  TEST(asprintf(&s, "%"PRId64, val) > 0);
  return s;
}


static void sc_attr_init_default_doc(void)
{
  if( sc_attr_info[0].default_doc != NULL )
    return;
  int i = 0;

#define FNAME(_type) sc_attr_default_## _type
#define DEFAULT_FUNC(_type) FNAME(_type)
# define SC_ATTR(_type, _name, _status, _def_val, _def_doc, _objects, _doc) \
  sc_attr_info[i++].default_doc =                                       \
    _def_doc ? _def_doc : DEFAULT_FUNC( SC_ATTR_TYPE_STORAGE_##_type )(_def_val);
# include <sc_internal/attr_tmpl.h>
# undef SC_ATTR
  TEST(i == SC_ATTR_N);
}


int sc_attr_doc(const char* attr_name,
                const char*** docs_out, int* docs_len_out)
{
  if( attr_name == NULL || ! strcmp(attr_name, "") ) {
    TEST(*docs_out = malloc(SC_ATTR_N * sizeof(const char*)));
    int i;
    for( i = 0; i < SC_ATTR_N; ++i )
      (*docs_out)[i] = sc_attr_info[i].name;
    *docs_len_out = SC_ATTR_N;
    return 0;
  }

  struct sc_attr_info* f = sc_attr_info_find(attr_name);
  if( f == NULL )
    return -1;
  sc_attr_init_default_doc();
  const char* docs[] = {
    f->name,
    f->type_str,
    f->status,
    f->default_doc,
    f->objects,
    f->doc ? f->doc : ""
  };
  *docs_len_out = sizeof(docs) / sizeof(docs[0]);
  *docs_out = malloc(sizeof(docs));
  memcpy(*docs_out, docs, sizeof(docs));
  return 0;
}


struct sc_object* sc_attr_to_object(const struct sc_attr* attr)
{
  if( attr == NULL )
    return NULL;
  return (struct sc_object*) &(attr->attr_obj.obj_public);
}


const struct sc_attr* sc_attr_from_object(struct sc_object* obj)
{
  if( obj == NULL || obj->obj_type != SC_OBJ_C_ATTR )
    return NULL;
  return SC_CONTAINER(struct sc_attr, attr_obj.obj_public, obj);
}
