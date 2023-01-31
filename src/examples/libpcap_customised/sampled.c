/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/*
 * This file contains an example implementation of a custom SolarCapture
 * node.  This node captures packets from a network interface, samples the
 * captured packets and forwards the sample packets to its output.
 *
 * The "sampled" node doesn't participate in the data path.  It
 * instantiates a couple of built-in SolarCapture nodes which do the real
 * work.
 *
 * See the "extensions_api" samples for the basics of how SolarCapture
 * nodes are implemented.
 */

#define SC_API_VER 5
#include <solar_capture.h>

#include <errno.h>
#include <stdio.h>


#define TRY(x)                                                          \
  do {                                                                  \
    int __rc = (x);                                                     \
    if( __rc < 0 ) {                                                    \
      fprintf(stderr, "ERROR: %s: TRY(%s) failed\n", __func__, #x);     \
      fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__);         \
      fprintf(stderr, "ERROR: rc=%d errno=%d (%s)\n",                   \
              __rc, errno, strerror(errno));                            \
      abort();                                                          \
    }                                                                   \
  } while( 0 )


/* Private state for our custom node. */
struct sampled_node {
  struct sc_node*  filter;
};


/* Private state for our predicate object. */
struct sampled_pred {
  unsigned  rand_r_seed;
  unsigned  threshold;    /* controls the fraction of packets sampled */
};


/* This function is invoked once for each packet received by the sc_filter
 * node.  If it returns 1, then the packet is sampled.
 */
static int sampled_pred_fn(struct sc_pkt_predicate* pred, struct sc_packet* pkt)
{
  struct sampled_pred* sp = pred->pred_private;
  return (unsigned) rand_r(&(sp->rand_r_seed)) < sp->threshold;
}


/* The nt_add_link_fn() is called when the application adds an outgoing
 * link to this node using sc_node_add_link().
 */
static int sampled_add_link(struct sc_node* from_node, const char* link_name,
                            struct sc_node* to_node, const char* to_name_opt)
{
  struct sampled_node* sn = from_node->nd_private;
  if( ! strcmp(link_name, "") )
    return sc_node_add_link(sn->filter, "", to_node, to_name_opt);
  else
    return sc_node_set_error(from_node, EINVAL, "sampled: ERROR: bad outgoing "
			     "link '%s' (expected "")\n", link_name);
}


static int sampled_init(struct sc_node* node, const struct sc_attr* attr,
                        const struct sc_node_factory* factory)
{
  /* We need a node type just so we can return errors. */
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_add_link_fn = sampled_add_link;
  }
  node->nd_type = nt;

  double fraction;
  const char *interface, *streams, *source;
  int seed;
  if( sc_node_init_get_arg_dbl(&fraction, node, "fraction", -1.0)   < 0 ||
      sc_node_init_get_arg_str(&interface, node, "interface", NULL) < 0 ||
      sc_node_init_get_arg_int(&seed, node, "seed", 0)              < 0 ||
      sc_node_init_get_arg_str(&streams, node, "streams", NULL)     < 0 ||
      sc_node_init_get_arg_str(&source, node, "source", NULL)       < 0  )
    return -1;

  if( fraction < 0.0 || fraction > 1.0 )
    return sc_node_set_error(node, EINVAL, "sampled: ERROR: bad arg "
			     "fraction=%f\n", fraction);
  if( (interface == NULL) == (source == NULL) )
    return sc_node_set_error(node, EINVAL, "sampled: ERROR: expected one of "
                             "'interface' or 'source' arg\n");

  struct sc_thread* thread = sc_node_get_thread(node);

  /* The libpcap bindings set unpack_packed_stream=0 because they know how
   * to handle the packed-stream format.  However, the sc_filter node does
   * not, so we must ensure we give it "normal" packets.
   */
  struct sc_attr* attr2 = sc_attr_dup(attr);
  TRY( sc_attr_set_int(attr2, "unpack_packed_stream", 1) );

  /* Create a packet source.  If "interface" is set, we create an
   * sc_vi_node which captures packets from an interface.
   */
  struct sc_node* source_node;
  if( interface != NULL ) {
    struct sc_arg args[] = {
      SC_ARG_STR("interface", interface),
      SC_ARG_STR("streams", streams),
    };
    int n_args = sizeof(args) / sizeof(args[0]);
    int rc = sc_node_alloc_named(&source_node, attr2, thread, "sc_vi_node",
                                 NULL, args, n_args);
    if( rc < 0 )
      sc_node_fwd_error(node, rc);
  }
  else {
    /* Create a node according to the specification in "source".  See
     * sc_node_alloc_from_str() for the details.  For example these have
     * the same effect:
     *
     *   source=sc:sc_vi_node:interface=eth4
     *
     *   interface=eth4
     */
    int rc = sc_node_alloc_from_str(&source_node, attr2, thread, source);
    if( rc < 0 )
      sc_node_fwd_error(node, rc);
  }

  struct sampled_node* sn = sc_thread_calloc(thread, sizeof(*sn));
  node->nd_private = sn;

  /* Create a predicate object which will be used to select the sample
   * packets.
   */
  struct sc_pkt_predicate* pred;
  TRY( sc_pkt_predicate_alloc(&pred, sizeof(struct sampled_pred)) );
  pred->pred_test_fn = sampled_pred_fn;
  struct sampled_pred* sp = pred->pred_private;
  sp->rand_r_seed = seed;
  sp->threshold = RAND_MAX * fraction;

  /* Instantiate a filter node that will use our predicate. */
  struct sc_arg args[] = {
    SC_ARG_OBJ("predicate", sc_pkt_predicate_to_object(pred)),
  };
  int n_args = sizeof(args) / sizeof(args[0]);
  TRY( sc_node_alloc_named(&(sn->filter), attr, thread, "sc_filter",
                           NULL, args, n_args) );

  /* Link the packet source to the filter. */
  TRY( sc_node_add_link(source_node, "", sn->filter, NULL) );
  return 0;
}


const struct sc_node_factory sampled_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sampled",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sampled_init,
};
