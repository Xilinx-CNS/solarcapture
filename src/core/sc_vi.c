/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#include "internal.h"
#include <sc_internal/ef_vi.h>
#include <sc_internal/stream.h>
#include <sc_internal/builtin_nodes.h>


#define SC_TRY_MSG(tg, exp, ...)                        \
  do {                                                  \
    int __rc = (exp);                                   \
    if( __rc < 0 )                                      \
      return sc_set_err((tg), -__rc, __VA_ARGS__);      \
  } while( 0 )


static int ef_vi_group_add_fn(void* v_vi_group, ef_filter_spec* spec)
{
  struct sc_ef_vi_group* vi_group = v_vi_group;
  return ef_vi_set_filter_add(&vi_group->ef_vi_set, vi_group->dh, spec, NULL);
}


static int ef_vi_group_add_stream(struct sc_vi_group* vi_group,
                                  struct sc_stream* s,
                                  enum sc_capture_mode capture_mode,
                                  int promiscuous)
{
  assert(vi_group->svg_type == sc_vi_group_type_ef_vi);
  struct sc_ef_vi_group* sevg = SC_CONTAINER(struct sc_ef_vi_group, sc_vi_group,
                                             vi_group);
  return sc_stream_add(s, sevg, capture_mode, promiscuous, sevg->capture_point,
                       ef_vi_group_add_fn);
}


static int sc_vi_group_alloc__ef_vi(struct sc_vi_group** sc_vi_group,
                                    const struct sc_attr* attr,
                                    struct sc_session* tg,
                                    const char* layer_2_interface, int n_vis)
{
  struct sc_netif* netif;
  const char* fcs_interface;

  int rc = sc_netif_get(&netif, attr, tg, layer_2_interface);
  if( rc < 0 )
    return rc;

  struct sc_ef_vi_group* vi_group = calloc(1, sizeof(*vi_group));
  TEST(vi_group);
  rc = sc_get_capture_mode(tg, attr, &vi_group->sc_vi_group.svg_capture_mode);
  if( rc < 0 ) {
    free(vi_group);
    return rc;
  }
  vi_group->sc_vi_group.svg_promiscuous = attr->promiscuous;
  SC_TRY_MSG(tg, sc_get_capture_point(tg, attr->capture_point,
                                      &vi_group->capture_point),
             "ERROR: capture_point=%s not supported\n", attr->capture_point);

  fcs_interface = ef_pd_interface_name(&netif->pd);
  rc = sc_get_interface_strip_fcs(tg, fcs_interface,
                                  &vi_group->sc_vi_group.svg_strip_fcs);
  if( rc < 0 ) {
    free(vi_group);
    return rc;
  }
  if( attr->strip_fcs >= 0 ) {
    if( vi_group->sc_vi_group.svg_strip_fcs != attr->strip_fcs ) {
      free(vi_group);
      return sc_set_err(tg, EINVAL, "ERROR: %s: Set strip_fcs=%"PRId64", but interface"
                        " %s set to %d\n", __func__,
                        attr->strip_fcs, fcs_interface,
                        vi_group->sc_vi_group.svg_strip_fcs);
    }
  }

  vi_group->sc_vi_group.svg_tg            = tg;
  vi_group->sc_vi_group.svg_type          = sc_vi_group_type_ef_vi;
  vi_group->sc_vi_group.svg_add_stream_fn = ef_vi_group_add_stream;

  vi_group->n_vis = n_vis;
  vi_group->netif = netif;
  SC_TRY_MSG(tg, ef_driver_open(&vi_group->dh),
             "ERROR: ef_vi driver() failed\n");
  SC_TRY_MSG(tg, ef_vi_set_alloc_from_pd(&vi_group->ef_vi_set, vi_group->dh,
                                      &netif->pd, netif->dh, n_vis),
          "ERROR: ef_vi_set_alloc_from_pd() for interface '%s' failed\n",
          layer_2_interface);
  vi_group->vi_group_id = tg->tg_vi_groups_n++;
  *sc_vi_group = &vi_group->sc_vi_group;
  sc_trace(tg, "%s: intf=%s n_vis=%d\n",
           __func__, layer_2_interface, n_vis);
  return 0;
}


int sc_vi_group_alloc(struct sc_vi_group** sc_vi_group,
                      const struct sc_attr* attr,
                      struct sc_session* tg,
                      const char* layer_2_interface, int n_vis)
{
  return sc_vi_group_alloc__ef_vi(sc_vi_group, attr, tg, layer_2_interface,
                                  n_vis);
}


struct sc_session*
   sc_vi_group_get_session(const struct sc_vi_group* vi_group)
{
  return vi_group->svg_tg;
}


static int sc_vi_set_recv_node__ef_vi(struct sc_vi* sc_vi,
                                      struct sc_node* node_in,
                                      const char* name_opt)
{
  struct sc_ef_vi* vi = sc_vi->vi_priv;
  return sc_ef_vi_set_recv_node(vi, node_in, name_opt, sc_vi->vi_attr);
}


int sc_vi_add_stream__ef_vi(struct sc_vi* sc_vi, struct sc_stream* s,
                            enum sc_capture_mode capture_mode,
                            int promiscuous)
{
  struct sc_ef_vi* vi = sc_vi->vi_priv;
  enum sc_capture_point capture_point;
  struct sc_session* tg = sc_vi->vi_thread->session;
  SC_TRY_MSG(tg, sc_get_capture_point(tg, sc_vi->capture_point, &capture_point),
             "ERROR: sc_get_capture_point() failed\n");

  return sc_ef_vi_add_stream(vi, s, capture_mode, promiscuous, capture_point);
}


static int
sc_vi_alloc_from_set(struct sc_ef_vi* vi,
                     int evq_capacity, int rxq_capacity,
                     int txq_capacity, enum ef_vi_flags flags,
                     void* data)
{
  struct sc_ef_vi_group* set = data;
  return ef_vi_alloc_from_set(&vi->vi, vi->dh, &set->ef_vi_set, set->dh,
                              set->index, evq_capacity, rxq_capacity,
                              txq_capacity, NULL, 0, flags);
}


static int sc_vi_alloc_from_group__ef_vi(struct sc_vi** vi_out,
                                         const struct sc_attr* attr,
                                         struct sc_thread* thread,
                                         struct sc_vi_group* sc_vi_group)
{
  struct sc_ef_vi_group* sevg = SC_CONTAINER(struct sc_ef_vi_group, sc_vi_group,
                                             sc_vi_group);
  unsigned sc_ef_vi_flags = 0;
  struct sc_session* tg = thread->session;
  TRY(sc_thread_affinity_save_and_set(thread));
  TEST(sevg->index < sevg->n_vis);

  struct sc_ef_vi* vi = sc_thread_calloc(thread, sizeof(*vi));
  TEST(vi != NULL);
  vi->id = tg->tg_vis_n;
  if( attr->name == NULL )
    TEST(asprintf(&vi->name, "%s-%d", sevg->netif->name, vi->id) > 0);
  else
    vi->name = strdup(attr->name);

  SC_TRY_MSG(tg, ef_driver_open(&vi->dh), "ERROR: ef_driver_open() failed\n");

  unsigned ef_vi_flags =  EF_VI_TX_IP_CSUM_DIS | EF_VI_TX_TCPUDP_CSUM_DIS;

  int rc = sc_ef_vi_alloc_feats(tg, vi, sevg->netif, attr, ef_vi_flags,
                                sc_vi_alloc_from_set, sevg, &sc_ef_vi_flags);
  if( rc != 0 )
    goto out;

  ++sevg->index;

  struct sc_attr* vi_attr = sc_attr_dup(attr);
  sc_ef_vi_set_attr(vi_attr, sc_ef_vi_flags, vi);

  SC_TRY(__sc_ef_vi_init(thread, vi_attr, vi, sevg->netif, sc_ef_vi_flags));

  sc_attr_free(vi_attr);
  struct sc_vi* sc_vi = sc_thread_calloc(thread, sizeof(*sc_vi));
  TEST(sc_vi != NULL);
  sc_vi->vi_thread = thread;
  sc_vi->vi_interface = vi->netif->interface;
  sc_vi->vi_set_recv_node_fn = sc_vi_set_recv_node__ef_vi;
  sc_vi->vi_add_stream_fn = sc_vi_add_stream__ef_vi;
  sc_vi->vi_mode = ( vi->packed_stream_mode ) ?
    SC_VI_MODE_PACKED_STREAM : SC_VI_MODE_NORMAL;
  sc_vi->vi_priv = vi;
  vi->stats->vi_group_id = sevg->vi_group_id;

  rc = sc_get_capture_mode(thread->session, attr, &sc_vi->capture_mode);
  if( rc < 0 ) {
    free(vi->name);
    sc_thread_mfree(thread, vi);
    sc_thread_mfree(thread, sc_vi);
    goto out;
  }

  *vi_out = sc_vi;

  sc_trace(tg, "%s: name=%s thread=%s intf=%s/%s vi_id=%d\n", __func__,
           vi->name, thread->name, sevg->netif->name,
           sevg->netif->interface->if_name, ef_vi_instance(&vi->vi));
 out:
  SC_TRY(sc_thread_affinity_restore(thread));
  return rc;
}


int sc_vi_alloc_from_group(struct sc_vi** vi_out, const struct sc_attr* attr,
                           struct sc_thread* thread, struct sc_vi_group* svg)
{
  int rc;
  assert(svg->svg_type == sc_vi_group_type_ef_vi);
  rc = sc_vi_alloc_from_group__ef_vi(vi_out, attr, thread, svg);
  if( rc < 0 )
    return rc;
  (*vi_out)->vi_attr = sc_attr_dup(attr);
  return 0;
}


struct sc_thread* sc_vi_get_thread(const struct sc_vi* vi)
{
  return vi->vi_thread;
}


const char* sc_vi_get_interface_name(const struct sc_vi* vi)
{
  return vi->vi_interface->if_name;
}


int sc_vi_alloc__ef_vi(struct sc_vi** vi_out,
                              const struct sc_attr* attr,
                              struct sc_thread* thread,
                              const char* layer_2_interface)
{
  const char* cluster_name;
  struct sc_vi* sc_vi;
  struct sc_ef_vi* vi;
  struct sc_session* tg = thread->session;
  int rc;
  enum sc_capture_point point;
  const char* fcs_interface;

  TRY(sc_thread_affinity_save_and_set(thread));

  sc_vi = sc_thread_calloc(thread, sizeof(*sc_vi));
  TEST(sc_vi != NULL);
  sc_vi->vi_thread = thread;
  sc_vi->vi_set_recv_node_fn = sc_vi_set_recv_node__ef_vi;
  sc_vi->vi_add_stream_fn = sc_vi_add_stream__ef_vi;


  rc = sc_get_capture_mode(tg, attr, &sc_vi->capture_mode);
  if( rc < 0 )
    goto free_sc_vi;

  sc_vi->promiscuous = attr->promiscuous;

  rc = sc_get_capture_point(tg, attr->capture_point, &point);
  if( rc < 0 )
    goto free_sc_vi;

  rc = sc_get_vi_mode(tg, attr, &sc_vi->vi_mode);
  if( rc < 0 )
    goto free_sc_vi;

  TEST(sc_vi->capture_interface = strdup(layer_2_interface));
  if( attr->capture_point != NULL )
    TEST(sc_vi->capture_point = strdup(attr->capture_point));

  if( attr->cluster != NULL )
    cluster_name = attr->cluster;
  else
    cluster_name = layer_2_interface;

  unsigned vi_flags = 0;

  rc = sc_ef_vi_alloc(&vi, attr, thread, cluster_name, vi_flags);

  if( rc != 0 ) {
    if( attr->cluster != NULL && tg->tg_err_errno != EINVAL )
      rc = sc_set_err(tg, ENODEV, "ERROR: %s: Failed to join cluster '%s'\n",
                      __func__, attr->cluster);
    goto free_strs;
  }

  if( vi->packed_stream_mode )
    sc_vi->vi_mode = SC_VI_MODE_PACKED_STREAM;
  else
    sc_vi->vi_mode = SC_VI_MODE_NORMAL;

  if( ! sc_netif_is_cluster(vi->netif) && attr->cluster != NULL ) {
    rc = sc_set_err(tg, ENODEV, "ERROR: %s: Failed to join cluster '%s'\n",
                    __func__, attr->cluster);
    goto free_sc_ef_vi;
  }

  fcs_interface = ef_pd_interface_name(&vi->netif->pd);
  rc = sc_get_interface_strip_fcs(tg, fcs_interface, &sc_vi->strip_fcs);
  if( rc < 0 )
    goto free_sc_ef_vi;
  if( attr->strip_fcs >= 0 ) {
    if( sc_vi->strip_fcs != attr->strip_fcs ) {
      rc = sc_set_err(tg, EINVAL, "ERROR: %s: Set strip_fcs=%"PRId64", but interface "
                      "%s set to %d\n", __func__, attr->strip_fcs,
                      fcs_interface, sc_vi->strip_fcs);
      goto free_sc_ef_vi;
    }
  }

  sc_vi->vi_priv = vi;
  sc_vi->vi_interface = vi->netif->interface;
  *vi_out = sc_vi;

  TRY(sc_thread_affinity_restore(thread));

  return 0;

 free_sc_ef_vi:
  TEST(vi->id == --tg->tg_vis_n);
  sc_ef_vi_free(tg, vi);
 free_strs:
  free(sc_vi->capture_interface);
  free(sc_vi->capture_point);
 free_sc_vi:
  TRY(sc_thread_affinity_restore(thread));
  sc_thread_mfree(thread, sc_vi);
  return rc;
}


/* ?? todo: should we have a corresponding sc_vi_free? */
int sc_vi_alloc(struct sc_vi** vi_out, const struct sc_attr* attr,
                struct sc_thread* thread, const char* layer_2_interface)
{
  int rc;
  struct sc_vi* sc_vi = NULL;
  if( sc_vi == NULL )
    if( (rc = sc_vi_alloc__ef_vi(&sc_vi, attr, thread, layer_2_interface))
        != 0 )
      return rc;
  sc_vi->vi_attr = sc_attr_dup(attr);
  *vi_out = sc_vi;
  return 0;
}


static int sc_vi_add_batcher(struct sc_vi* vi, int max_pkts,
                             struct sc_node** to_node,
                             const char** name_opt)
{
  /* Add a sc_batch_limiter node between the VI and [to_node]. */
  struct sc_node* batcher;
  struct sc_attr* attr;
  TRY(sc_attr_alloc(&attr));
  struct sc_arg args[] = { SC_ARG_INT("max_packets", max_pkts) };
  TRY(sc_node_alloc(&batcher, attr, vi->vi_thread,
                    &sc_batch_limiter_sc_node_factory,
                    args, sizeof(args) / sizeof(args[0])));
  sc_attr_free(attr);
  int rc = sc_node_add_link(batcher, "", *to_node, *name_opt);
  if( rc < 0 )
    return sc_node_fwd_error(batcher, rc);
  *to_node = batcher;
  *name_opt = NULL;
  return 0;
}


int sc_vi_set_recv_node(struct sc_vi* vi, struct sc_node* recv_node,
                        const char* name_opt)
{
  int rc;

  int max_pkts =
    SC_ATTR_GET_INT_ALT(vi->vi_attr, vi_recv_max_pkts, batch_max_pkts);
  if( max_pkts > 0 )
    if( (rc = sc_vi_add_batcher(vi, max_pkts, &recv_node, &name_opt)) < 0 )
      return rc;

  return vi->vi_set_recv_node_fn(vi, recv_node, name_opt);
}


int sc_vi_add_stream(struct sc_vi* vi, struct sc_stream* s)
{
  enum sc_capture_mode capture_mode = SC_CAPTURE_MODE_UNSPECIFIED;
  int promiscuous = 1;

  if ( s->capture_mode != SC_CAPTURE_MODE_UNSPECIFIED ) {
    capture_mode = s->capture_mode;
  }
  else if ( vi->capture_mode != SC_CAPTURE_MODE_UNSPECIFIED ) {
    capture_mode = vi->capture_mode;
  }

  if( s->promiscuous != -1 ) {
    promiscuous = s->promiscuous;
  }
  else if ( vi->promiscuous != -1 ) {
    promiscuous = vi->promiscuous;
  }

  return vi->vi_add_stream_fn(vi, s, capture_mode, promiscuous);
}


int sc_vi_group_add_stream(struct sc_vi_group* vi_group, struct sc_stream* s)
{
  enum sc_capture_mode capture_mode = SC_CAPTURE_MODE_UNSPECIFIED;
  int promiscuous = 1;

  if ( s->capture_mode != SC_CAPTURE_MODE_UNSPECIFIED ) {
    capture_mode = s->capture_mode;
  }
  else {
    capture_mode = vi_group->svg_capture_mode;
  }

  if ( s->promiscuous != -1 ) {
    promiscuous = s->promiscuous;
  }
  else if ( vi_group->svg_promiscuous != -1 ) {
    promiscuous = vi_group->svg_promiscuous;
  }

  return vi_group->svg_add_stream_fn(vi_group, s, capture_mode, promiscuous);
}


int sc_vi_is_ef_vi(struct sc_vi* vi)
{
  return vi->vi_set_recv_node_fn == sc_vi_set_recv_node__ef_vi;
}
