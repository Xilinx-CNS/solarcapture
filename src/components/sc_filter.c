/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \node{sc_filter}
 *
 * \brief Node to filter packets, directing all matched packets to one
 * output, and all other packets to another output.
 *
 * \nodedetails
 * This node directs all matched packets to one output and all other packets
 * to another output. The filter can be provided via a BPF string, or via a
 * ::sc_pkt_predicate object.
 *
 * \internal
 * TODO: We should consider extending this to be a more general
 * demultiplexer.  ie. Support >2 outgoing hops.  Use integer return value
 * from predicate function to select.  (Or perhaps that should just be a
 * separate node type).
 * \endinternal
 *
 * \nodeargs
 * Argument   | Optional? | Default | Type           | Description
 * ---------- | --------- | ------- | -------------- | --------------------------------------------------------------------------------------------------------------------------------
 * bpf        | Yes       | NULL    | ::SC_PARAM_STR | Filter string in Berkeley Packet Filter format.
 * predicate  | Yes       | NULL    | ::SC_PARAM_OBJ | An ::SC_OBJ_PKT_PREDICATE to use as a filter.
 *
 * Note: Exactly one of bpf and predicate must be set.
 *
 * \namedinputlinks
 * None
 *
 * \outputlinks
 * Link           | Description
 * -------------- | -----------------------------------
 *  ""            | Packets matched by the filter.
 *  "not_matched" | Packets not matched by the filter.
 *
 * \nodestatscopy{sc_filter}
 *
 * \cond NODOC
 */

#include <sc_internal.h>
#include <sc_internal/builtin_nodes.h>

#include <errno.h>

#define SC_TYPE_TEMPLATE <sc_filter_types_tmpl.h>
#define SC_DECLARE_TYPES sc_filter_stats_declare
#include <solar_capture/declare_types.h>


struct sc_filter_state {
  const struct sc_node_link* next_hop;
  const struct sc_node_link* next_hop_not_matched;
  struct sc_pkt_predicate*   predicate;
  struct sc_filter_stats*    stats;
};


static void sc_filter_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct sc_filter_state* st = node->nd_private;
  struct sc_packet_list pl_nm;
  struct sc_packet** p_prev_next;
  struct sc_packet* pkt;

  sc_packet_list_init(&pl_nm);
  p_prev_next = &pl->head;

  while( (pkt = *p_prev_next) != NULL )
    if( st->predicate->pred_test_fn(st->predicate, pkt) ) {
      p_prev_next = &pkt->next;
    }
    else {
      *p_prev_next = pkt->next;
      pl->num_frags -= pkt->frags_n;
      --(pl->num_pkts);
      __sc_packet_list_append(&pl_nm, pkt);
    }

  if( ! sc_packet_list_is_empty(pl) ) {
    pl->tail = p_prev_next;
    __sc_forward_list(node, st->next_hop, pl);
  }
  if( ! sc_packet_list_is_empty(&pl_nm) ) {
    st->stats->pkts_rejected += pl_nm.num_pkts;
    __sc_forward_list(node, st->next_hop_not_matched, &pl_nm);
  }
}


static void sc_filter_end_of_stream(struct sc_node* node)
{
  struct sc_filter_state* st = node->nd_private;
  sc_node_link_end_of_stream(node, st->next_hop);
  sc_node_link_end_of_stream(node, st->next_hop_not_matched);
}


static int sc_filter_prep(struct sc_node* node,
                          const struct sc_node_link*const* links, int n_links)
{
  struct sc_filter_state* st = node->nd_private;
  st->next_hop = sc_node_prep_get_link_or_free(node, "");
  st->next_hop_not_matched = sc_node_prep_get_link_or_free(node,
                                                           "not_matched");
  return sc_node_prep_check_links(node);
}


static int try_get_bpf(struct sc_node* node, struct sc_filter_state* st)
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


static int sc_filter_init(struct sc_node* node, const struct sc_attr* attr,
                          const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_pkts_fn = sc_filter_pkts;
    nt->nt_prep_fn = sc_filter_prep;
    nt->nt_end_of_stream_fn = sc_filter_end_of_stream;
  }
  sc_filter_stats_declare(sc_thread_get_session(sc_node_get_thread(node)));
  node->nd_type = nt;

  struct sc_filter_state* st;
  st = sc_thread_calloc(sc_node_get_thread(node), sizeof(*st));
  node->nd_private = st;

  struct sc_object* obj;
  int rc;
  rc = sc_node_init_get_arg_obj(&obj, node, "predicate", SC_OBJ_PKT_PREDICATE);
  if( rc == 0 ) {
    st->predicate = sc_pkt_predicate_from_object(obj);
  }
  else if( rc < 0 ) {
    goto error;
  }
  else {
    if( try_get_bpf(node, st) < 0 )
      goto error;
  }
  if( st->predicate == NULL ) {
    sc_node_set_error(node, EINVAL,
                      "sc_filter: ERROR: no filter condition specified\n");
    goto error;
  }
  sc_node_export_state(node, "sc_filter_stats", sizeof(struct sc_filter_stats),
                       &st->stats);
  return 0;

 error:
  sc_thread_mfree(sc_node_get_thread(node), st);
  return -1;
}


const struct sc_node_factory sc_filter_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_filter",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_filter_init,
};

/** \endcond NODOC */
