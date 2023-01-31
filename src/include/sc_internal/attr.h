/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#ifndef __SC_ATTR_H__
#define __SC_ATTR_H__


#define SC_ATTR_TYPE_int   int64_t
#define SC_ATTR_TYPE_size  SC_ATTR_TYPE_int
#define SC_ATTR_TYPE_str   char*


struct sc_attr {
  /* Object header so we can convert to/from sc_object. */
  struct sc_object_impl  attr_obj;
  /* Attribute fields. */
# define SC_ATTR(type, name, status, default_val, default_doc, objects, doc) \
    SC_ATTR_TYPE_##type name;
# include <sc_internal/attr_tmpl.h>
# undef SC_ATTR
};


#define SC_ATTR_GET_INT_DEFAULT(attr, name, default_val)        \
  (((attr)->name >= 0) ? (attr)->name : (default_val))

#define SC_ATTR_GET_INT_ALT(attr, name, alt_name)       \
  SC_ATTR_GET_INT_DEFAULT(attr, name, (attr)->alt_name)


#endif  /* __SC_ATTR_H__ */
