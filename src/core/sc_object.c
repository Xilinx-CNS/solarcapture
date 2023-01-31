/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#include "internal.h"


enum sc_object_type sc_object_type(struct sc_object* obj)
{
  return obj->obj_type;
}


int sc_pkt_predicate_alloc(struct sc_pkt_predicate** pred_out,
                           int private_bytes)
{
  assert(private_bytes >= 0);
  int bytes = sizeof(struct sc_pkt_predicate_impl);
  struct sc_pkt_predicate_impl* ppi = calloc(1, bytes + private_bytes);
  sc_object_impl_init(&ppi->pred_obj, SC_OBJ_PKT_PREDICATE);
  if( private_bytes )
    ppi->pred_public.pred_private = ppi + 1;
  *pred_out = &(ppi->pred_public);
  return 0;
}


struct sc_object* sc_pkt_predicate_to_object(struct sc_pkt_predicate* pred)
{
  if( pred == NULL )
    return NULL;
  struct sc_pkt_predicate_impl* ppi;
  ppi = SC_PKT_PREDICATE_IMPL_FROM_PKT_PREDICATE(pred);
  return &(ppi->pred_obj.obj_public);
}


struct sc_pkt_predicate* sc_pkt_predicate_from_object(struct sc_object* obj)
{
  if( obj == NULL || obj->obj_type != SC_OBJ_PKT_PREDICATE )
    return NULL;
  struct sc_pkt_predicate_impl* ppi;
  ppi = SC_CONTAINER(struct sc_pkt_predicate_impl, pred_obj.obj_public, obj);
  return &(ppi->pred_public);
}


/**********************************************************************
 * sc_opaque
 */

struct sc_opaque_object_impl {
  struct sc_object_impl  op_obj;
  void*                  op_ptr;
};


#define SC_OPAQUE_OBJECT_IMPL_FROM_OBJECT(obj)                          \
  SC_CONTAINER(struct sc_opaque_object_impl, op_obj.obj_public, (obj))


int sc_opaque_alloc(struct sc_object** obj_out, void* opaque)
{
  struct sc_opaque_object_impl* ooi;
  ooi = calloc(1, sizeof(struct sc_opaque_object_impl));
  sc_object_impl_init(&ooi->op_obj, SC_OBJ_OPAQUE);
  ooi->op_ptr = opaque;
  *obj_out = &ooi->op_obj.obj_public;
  return 0;
}


void sc_opaque_free(struct sc_object* obj)
{
  struct sc_opaque_object_impl* ooi;
  ooi = SC_OPAQUE_OBJECT_IMPL_FROM_OBJECT(obj);
  SC_TEST(ooi->op_obj.obj_public.obj_type == SC_OBJ_OPAQUE);
  free(ooi);
}


void sc_opaque_set_ptr(struct sc_object* obj, void* opaque)
{
  struct sc_opaque_object_impl* ooi;
  ooi = SC_OPAQUE_OBJECT_IMPL_FROM_OBJECT(obj);
  SC_TEST(ooi->op_obj.obj_public.obj_type == SC_OBJ_OPAQUE);
  ooi->op_ptr = opaque;
}


void* sc_opaque_get_ptr(const struct sc_object* obj)
{
  struct sc_opaque_object_impl* ooi;
  ooi = SC_OPAQUE_OBJECT_IMPL_FROM_OBJECT(obj);
  SC_TEST(ooi->op_obj.obj_public.obj_type == SC_OBJ_OPAQUE);
  return ooi->op_ptr;
}
