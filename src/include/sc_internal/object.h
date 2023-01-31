/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#ifndef __SC_OBJECT_H__
#define __SC_OBJECT_H__


struct sc_object {
  enum sc_object_type obj_type;
};


struct sc_object_impl {
  struct sc_object   obj_public;
};


#define SC_OBJECT_IMPL_FROM_OBJECT(obj)                         \
  SC_CONTAINER(struct sc_object_impl, obj_public, (obj))


static inline void sc_object_impl_init(struct sc_object_impl* oi,
                                       enum sc_object_type type)
{
  oi->obj_public.obj_type = type;
}


struct sc_pkt_predicate_impl {
  struct sc_pkt_predicate  pred_public;
  struct sc_object_impl    pred_obj;
};


#define SC_PKT_PREDICATE_IMPL_FROM_PKT_PREDICATE(pp)            \
  SC_CONTAINER(struct sc_pkt_predicate_impl, pred_public, (pp))


#endif  /* __SC_OBJECT_H__ */
