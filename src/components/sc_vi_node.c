/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \node{sc_vi_node}
 *
 * \brief A node which passes packets to and/or from a network interface.
 *
 * \nodedetails
 * This node passes packets to and/or from a network interface.
 *
 * Packets arriving at this node are passed to the indicated network
 * interface.  Packets received from the network interface are passed to
 * this node's output link.
 *
 * This node creates an \noderef{sc_vi_node} if an output link is added,
 * and creates an \noderef{sc_injector} if an incoming link is added.
 *
 * The 'streams' argument is used to indicate which packets from the
 * interface should be captured on the receive path.  This is analogous to
 * calling sc_vi_add_stream().
 *
 * If the interface name looks like "tap:name" then an \noderef{sc_tuntap}
 * node is instantiated.
 *
 * \nodeargs
 * Argument    | Optional? | Default | Type           | Description
 * ----------- | --------- | ------- | -------------- | ----------------------------------------------------------
 * interface   | No        |         | ::SC_PARAM_STR | Name of the network interface.
 * streams     | Yes       | "all"   | ::SC_PARAM_STR | ';' separated list of streams to be captured on receive.
 *
 * \cond NODOC
 */
#include <sc_internal.h>
#include <sc_internal/builtin_nodes.h>

#include <stdio.h>
#include <errno.h>
#include <string.h>


struct vi_node {
  char*           interface;
  char*           streams;
  struct sc_attr* attr;
  struct sc_vi*   vi;
  struct sc_node* injector;
};


static bool sc_vi_node_add_stream(struct sc_node* node,
                                  const struct sc_attr* attr,
                                  const char* stream)
{
  struct sc_thread* thread = sc_node_get_thread(node);
  struct vi_node* st = node->nd_private;
  struct sc_stream* strm;
  SC_TRY( sc_stream_alloc(&strm, attr, sc_thread_get_session(thread)) );
  int rc = sc_stream_set_str(strm, stream);
  if( rc == 0 )
    rc = sc_vi_add_stream(st->vi, strm);
  SC_TRY( sc_stream_free(strm) );
  if( rc < 0 ) {
    sc_node_fwd_error(node, rc);
    return false;
  }
  return true;
}


static int sc_vi_node_add_link(struct sc_node* from_node, const char* link_name,
                               struct sc_node* to_node, const char* to_name_opt)
{
  struct vi_node* st = from_node->nd_private;
  if( st->vi != NULL )
    return sc_node_set_error(from_node, EINVAL, "%s: ERROR: sc_vi_node can "
                             "only support a single output link\n", __func__);

  int rc = sc_vi_alloc(&(st->vi), st->attr, sc_node_get_thread(from_node),
                       st->interface);
  if( rc < 0 )
    return sc_node_fwd_error(from_node, rc);

  if( st->streams != NULL ) {
    size_t len = strlen(st->streams);
    char streams_tmp[len + 1];
    strcpy(streams_tmp, st->streams);
    char *iter = NULL;
    const char* stream = strtok_r(streams_tmp, ";", &iter);
    while( stream != NULL ) {
      if( ! sc_vi_node_add_stream(from_node, st->attr, stream) )
        return -1;
      stream = strtok_r(NULL, ";", &iter);
    }
  }
  else {
    if( ! sc_vi_node_add_stream(from_node, st->attr, "all") )
      return -1;
  }
  return sc_vi_set_recv_node(st->vi, to_node, to_name_opt);
}


static struct sc_node* sc_vi_node_select_subnode(struct sc_node* node,
                                                 const char* name_opt,
                                                 char** new_name_out)
{
  struct vi_node* st = node->nd_private;
  if( st->injector == NULL ) {
    struct sc_arg args[] = {
      SC_ARG_STR("interface", st->interface),
    };
    int rc = sc_node_alloc_named(&(st->injector), st->attr,
                                 sc_node_get_thread(node), "sc_injector", NULL,
                                 args, sizeof(args) / sizeof(args[0]));
    if( rc < 0 ) {
      sc_node_fwd_error(node, rc);
      return NULL;
    }
  }
  return st->injector;
}


static int delegate_to_tap(struct sc_node* node, const struct sc_attr* attr,
                           const char* interface)
{
  int up;
  if( sc_node_init_get_arg_int(&up, node, "up", 1) < 0 )
    return -1;
  struct sc_arg args[] = {
    SC_ARG_STR("interface", interface),
    SC_ARG_INT("up",        up),
  };
  int n_args = sizeof(args) / sizeof(args[0]);
  return sc_node_init_delegate(node, attr, &sc_tuntap_sc_node_factory,
                               args, n_args);
}


static int sc_vi_node_init(struct sc_node* node, const struct sc_attr* attr,
                           const struct sc_node_factory* factory)
{
  struct sc_thread* thread = sc_node_get_thread(node);

  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_add_link_fn = sc_vi_node_add_link;
    nt->nt_select_subnode_fn = sc_vi_node_select_subnode;
  }
  node->nd_type = nt;

  const char* interface;
  if( sc_node_init_get_arg_str(&interface, node, "interface", NULL) < 0 )
    return -1;
  if( interface == NULL )
    return sc_node_set_error(node, EINVAL, "%s: ERROR: required arg "
                             "'interface' missing\n", __func__);

  if( sc_match_prefix(interface, "tap:", &interface) )
    return delegate_to_tap(node, attr, interface);

  const char* streams;
  if( sc_node_init_get_arg_str(&streams, node, "streams", NULL) < 0 )
    return -1;

  struct vi_node* st;
  st = sc_thread_calloc(thread, sizeof(*st));
  node->nd_private = st;
  SC_TEST( st->attr = sc_attr_dup(attr) );
  /* st->injector = NULL; */
  /* st->vi = NULL; */
  SC_TEST( st->interface = strdup(interface) );
  /* st->streams = NULL; */
  if( streams )
    SC_TEST( st->streams = strdup(streams) );
  return 0;
}


const struct sc_node_factory sc_vi_node_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_vi_node",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_vi_node_init,
};

/** \endcond NODOC */
