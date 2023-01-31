/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \node{sc_tap}
 *
 * \brief Forward input to output, and a copy of input to the 'tap' output with
 * optional filtering.
 *
 * \nodedetails
 *  Forward input to output and a copy of input to the 'tap' output.  If a
 *  BPF or predicate filter is specified, only packets matching the filter are
 *  duplicated to the 'tap' output.
 *
 *  The node can be placed in one of two modes:
 *   - default:
 *     - Input packets are always forwarded to "" immediately.
 *     - If buffers are available, they are copied to "tap" immediately, otherwise
 *     they never go to tap.
 *   - Reliable:
 *     - If buffers are available, all packets are forwarded to "" and "tap"
 *     immediately.
 *     - If not, they are delayed until buffers are available and then forwarded
 *     to "" and "tap" at that point.
 *
 *  Note: In reliable mode this node can potentially create a backlog large enough
 *  to provoke drops in an upstream node or VI.
 *
 * \nodeargs
 * Argument    | Optional? | Default | Type           | Description
 * ----------- | --------- | ------- | -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
 * snap        | Yes       | 0       | ::SC_PARAM_INT | Copy at most n bytes of the duplicated frames, set to 0 to disable.
 * reliable    | Yes       | 0       | ::SC_PARAM_INT | Set to 1/0 to enable/disable reliable mode.
 * bpf         | Yes       | NULL    | ::SC_PARAM_STR | Filter to select packets to duplicate in BPF format.
 * predicate   | Yes       | NULL    | ::SC_PARAM_OBJ | Predicate object to select packets to duplicate.
 *
 * Note: At most one of bpf and predicate may be specified.
 *
 * \namedinputlinks
 * None
 *
 * \outputlinks
 * Link   | Description
 * ------ | -----------------------------------
 *  ""    | All packets are sent down this link.
 *  "tap" | The copy of the input.
 *
 * \cond NODOC
 */
#include <sc_internal.h>
#include <sc_internal/builtin_nodes.h>
#include <solar_capture/nodes/subnode_helper.h>

#include <errno.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>


#define TRY(x)                                                  \
  do {                                                          \
    int __rc = (x);                                             \
    if( __rc < 0 ) {                                            \
      fprintf(stderr, "ERROR: TRY(%s) failed\n", #x);           \
      fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__); \
      fprintf(stderr, "ERROR: rc=%d errno=%d (%s)\n",           \
              __rc, errno, strerror(errno));                    \
      abort();                                                  \
    }                                                           \
  } while( 0 )


struct sc_tap_state {
  const struct sc_node_link* next_hop;
  struct sc_callback*        pool_cb;
  struct sc_pkt_predicate*   predicate;
  struct sc_subnode_helper*  snh;
  int                        snap;
  int                        reliable;
  bool                       end_of_input;

  struct sc_packet_list      backlog;
};


static void sc_tap_drain(struct sc_tap_state* st)
{
  struct sc_packet_list pl;
  struct sc_packet* copy;
  struct sc_packet* pkt;

  assert(!sc_packet_list_is_empty(&st->backlog));

  __sc_packet_list_init(&pl);
  do {
    pkt = st->backlog.head;
    if( st->predicate == NULL ||
        st->predicate->pred_test_fn(st->predicate, pkt) ) {
      copy = sc_pool_duplicate_packet(st->snh->sh_pool, pkt, st->snap);
      if( copy != NULL ) {
        sc_forward2(st->snh->sh_links[0], copy);
      }
      else {  /* Run out of packet buffers for copies. */
        if( ! sc_packet_list_is_empty(&pl) )
          __sc_forward_list2(st->next_hop, &pl);
        if( st->reliable ) {
          sc_pool_on_threshold(st->snh->sh_pool, st->pool_cb, pkt->frags_n + 1);
        }
        else {
          /* No point wasting CPU time invoking the predicate on any
           * remaining packets in the backlog.
           */
          __sc_forward_list2(st->next_hop, &(st->backlog));
          __sc_packet_list_init(&(st->backlog));
        }
        return;
      }
    }
    __sc_packet_list_pop_head(&st->backlog);
    __sc_packet_list_append(&pl, pkt);
  } while( ! sc_packet_list_is_empty(&st->backlog) );

  st->backlog.tail = &st->backlog.head;
  assert(!sc_packet_list_is_empty(&pl));
  __sc_forward_list2(st->next_hop, &pl);
  if( st->end_of_input ) {
    sc_node_link_end_of_stream2(st->next_hop);
    sc_node_link_end_of_stream2(st->snh->sh_links[0]);
  }
}


static void sc_tap_buffers_available(struct sc_callback* cb, void* event_info)
{
  struct sc_tap_state* st = cb->cb_private;
  sc_tap_drain(st);
}


static void sc_tap_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct sc_tap_state* st = node->nd_private;
  sc_packet_list_append_list(&st->backlog, pl);
  if( ! sc_callback_is_active(st->pool_cb) )
    sc_tap_drain(st);
}


static void sc_tap_end_of_stream(struct sc_node* node)
{
  struct sc_tap_state* st = node->nd_private;
  st->end_of_input = true;
  if( sc_packet_list_is_empty(&st->backlog) ) {
    sc_node_link_end_of_stream2(st->next_hop);
    sc_node_link_end_of_stream2(st->snh->sh_links[0]);
  }
}


static int sc_tap_prep(struct sc_node* node,
                       const struct sc_node_link*const* links, int n_links)
{
  struct sc_tap_state* st = node->nd_private;
  st->next_hop = sc_node_prep_get_link_or_free(node, "");
  return sc_node_prep_check_links(node);
}


static int sc_tap_add_link(struct sc_node* from_node, const char* link_name,
                           struct sc_node* to_node, const char* to_name_opt)
{
  struct sc_tap_state* st = from_node->nd_private;
  if( ! strcmp(link_name, "tap") )
    return sc_node_add_link(st->snh->sh_node, "", to_node, to_name_opt);
  else
    return sc_node_add_link(from_node, link_name, to_node, to_name_opt);
}


static int try_get_bpf(struct sc_node* node, struct sc_tap_state* st)
{
  const char* filter_str;
  if( sc_node_init_get_arg_str(&filter_str, node, "bpf", NULL) < 0 )
    return -1;
  if( filter_str != NULL ) {
    struct sc_thread* t = sc_node_get_thread(node);
    struct sc_session* scs = sc_thread_get_session(t);
    int rc = sc_bpf_predicate_alloc(&st->predicate, scs, filter_str);
    if( rc < 0 ) {
      sc_node_fwd_error(node, rc);
      return -1;
    }
  }
  return 0;
}


static int sc_tap_init(struct sc_node* node, const struct sc_attr* attr,
                       const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_pkts_fn = sc_tap_pkts;
    nt->nt_end_of_stream_fn = sc_tap_end_of_stream;
    nt->nt_prep_fn = sc_tap_prep;
    nt->nt_add_link_fn = sc_tap_add_link;
  }
  node->nd_type = nt;

  struct sc_thread* thread = sc_node_get_thread(node);

  struct sc_tap_state* st;
  st = sc_thread_calloc(thread, sizeof(*st));
  node->nd_private = st;

  if( sc_node_init_get_arg_int(&st->snap, node, "snap", 0) < 0 )
    goto error;
  if( st->snap == 0 )
    st->snap = INT_MAX;
  if( sc_node_init_get_arg_int(&st->reliable, node, "reliable", 0) < 0 )
    goto error;

  struct sc_object* obj;
  int rc = sc_node_init_get_arg_obj(&obj, node, "predicate",
                                    SC_OBJ_PKT_PREDICATE);
  if( rc < 0 )
    goto error;
  if( rc == 0 )
    st->predicate = sc_pkt_predicate_from_object(obj);
  if( st->predicate == NULL && try_get_bpf(node, st) < 0 )
    goto error;

  SC_TEST(sc_callback_alloc(&st->pool_cb, attr, thread) == 0);
  st->pool_cb->cb_private = st;
  st->pool_cb->cb_handler_fn = sc_tap_buffers_available;
  __sc_packet_list_init(&st->backlog);

  struct sc_attr* attr2 = sc_attr_dup(attr);
  TRY(sc_attr_set_int(attr2, "private_pool", 1));
  TRY(sc_attr_set_from_fmt(attr2, "name", "%s.tap_sh", node->nd_name));
  struct sc_node* snh_node;
  struct sc_arg args[] = {
    SC_ARG_INT("with_pool", 1),
    SC_ARG_INT("with_free_link", 2), /* free link only if no other link */
  };
  SC_TRY( sc_node_alloc_named(&snh_node, attr2, thread, "sc_subnode_helper",
                              NULL, args, sizeof(args) / sizeof(args[0])) );
  sc_attr_free(attr2);
  struct sc_subnode_helper* snh = sc_subnode_helper_from_node(snh_node);
  st->snh = snh;
  snh->sh_private = st;
  return 0;

 error:
  sc_thread_mfree(thread, st);
  return -1;
}


const struct sc_node_factory sc_tap_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_tap",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_tap_init,
};

/** \endcond NODOC */
