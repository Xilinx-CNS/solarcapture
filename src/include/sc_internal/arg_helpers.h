/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#ifndef SC_ARG_HELPERS_H
#define SC_ARG_HELPERS_H

#include <limits.h>
#include <inttypes.h>
#include <errno.h>

#define SC_N_ARGS(args)  (sizeof(args) / sizeof(args[0]))
#define MISSING_ARG_STRING "%s: ERROR: missing required argument '%s'\n"

static inline int sc_node_init_get_arg_str_req(const char** val,
                                               struct sc_node* node,
                                               const char* name)
{
  int rc;
  if( (rc = sc_node_init_get_arg_str(val, node, name, NULL)) > 0 )
    return sc_node_set_error(node, EINVAL, MISSING_ARG_STRING,
                             node->nd_type->nt_name, name);
  else
    return rc; /* success or failed to retrieve arg */
}


static inline int sc_node_init_get_arg_bool(bool* val, struct sc_node* node,
                                            const char* name, bool dflt)
{
  int rc, tmp;
  if( (rc = sc_node_init_get_arg_int(&tmp, node, name, 0)) == 0 )
    *val = !!tmp;
  else if( rc > 0 )
    *val = dflt;
  return rc;
}


/* Get integer argument.  p_val can be a pointer to any integer type.
 * Return 0 on good, -1 if bad or out-of-range and 1 if not supplied.
 */
#define sc_iarg(p_val, node, name, val_def)                                  \
  ({                                                                         \
    int64_t __val64;                                                         \
    int __rc = sc_node_init_get_arg_int64(&__val64, (node), (name),          \
                                          (val_def));                        \
    *(p_val) = (typeof(*(p_val))) __val64;                                   \
    if( *(p_val) != __val64 || *(p_val) > INT64_MAX )                        \
      __rc = sc_node_set_error((node), EINVAL, "%s: ERROR: arg '%s' out of " \
                               "range\n", (node)->nd_type->nt_name, (name)); \
    __rc;                                                                    \
  })


/* Get required integer argument.  p_val can be a pointer to any integer
 * type.  Return 0 on good, -1 if missing or bad.
 */
#define sc_iarg_req(p_val, node, name)                                       \
  ({                                                                         \
    int __rc = sc_iarg((p_val), (node), (name), 0);                          \
    if( __rc > 0 )                                                           \
      __rc = sc_node_set_error(node, EINVAL, MISSING_ARG_STRING,             \
                               (node)->nd_type->nt_name,                     \
                               (name));                                      \
    __rc;                                                                    \
  })


/* Get integer argument and range check.  p_val can be a pointer to any
 * integer type.  Return 0 on good, -1 if not an integer or out-of-range
 * and 1 if arg was not provided.  The default value is not range checked.
 */
#define sc_iarg_range(p_val, node, name, val_def, val_min, val_max)           \
  ({                                                                          \
    int __rc = sc_iarg((p_val), (node), (name), (val_def));                   \
    if( __rc == 0 && (*(p_val) < (val_min) || *(p_val) > (val_max)) )         \
      __rc = sc_node_set_error((node), EINVAL, "%s: ERROR: arg '%s' out of "  \
                               "range (min=%"PRId64" max=%"PRId64")\n",       \
                               (node)->nd_type->nt_name, (name),              \
                               (int64_t) (val_min), (int64_t) (val_max));     \
    __rc;                                                                     \
  })


/* Get required integer argument and range check.  p_val can be a pointer
 * to any integer type.  Returns 0 on good, -1 if arg is missing, bad or
 * out-of-range.
 */
#define sc_iarg_req_range(p_val, node, name, val_min, val_max)               \
  ({                                                                         \
    int __rc = sc_iarg_range((p_val), (node), (name),                        \
                             (val_min), (val_min), (val_max));               \
    if( __rc > 0 )                                                           \
      __rc = sc_node_set_error(node, EINVAL, MISSING_ARG_STRING,             \
                               (node)->nd_type->nt_name,                     \
                               (name));                                      \
    __rc;                                                                    \
  })


/* For convenience */
#define sc_sarg     sc_node_init_get_arg_str
#define sc_sarg_req sc_node_init_get_arg_str_req
#define sc_barg     sc_node_init_get_arg_bool


static inline int sc_get_arg_obj(struct sc_object** obj_out,
                                 struct sc_node* node, const char* name,
                                 enum sc_object_type obj_type, bool required)
{
  *obj_out = NULL;
  int rc = sc_node_init_get_arg_obj(obj_out, node, name, obj_type);
  if( rc > 0 && required ) {
    sc_node_set_error(node, EINVAL, "%s: ERROR: required arg "
                      "'%s' missing\n", (node)->nd_type->nt_name, name);
    return -1;
  }
  return rc;
}


static inline int sc_get_arg_pool(struct sc_pool** pool_out,
                                  struct sc_node* node, const char* name,
                                  bool required)
{
  struct sc_object* obj;
  int rc = sc_get_arg_obj(&obj, node, name, SC_OBJ_POOL, required);
  *pool_out = (rc == 0) ? sc_pool_from_object(obj) : NULL;
  return rc;
}


static inline int sc_get_arg_node(struct sc_node** node_out,
                                  struct sc_node* node, const char* name,
                                  bool required)
{
  struct sc_object* obj;
  int rc = sc_get_arg_obj(&obj, node, name, SC_OBJ_NODE, required);
  *node_out = (rc == 0) ? sc_node_from_object(obj) : NULL;
  return rc;
}


#endif /* SC_ARG_HELPERS_H */
