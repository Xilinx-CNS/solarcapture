/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \addtogroup scnode SolarCapture Nodes
 * @{
 * \struct sct_eos_indicator
 * \brief ::sct_eos_indicator Test node for determining if the end of stream has been reached.
 * The node will output 'EOS' to the passed fd, when the node receives end of stream.
 * All incoming packets are forwarded unchanged
 *
 *
 * \nodeargs
 * Arguments           | Optional? | Default   | Type         | Description
 * ------------------- | --------- | --------- | ------------ | ----------------------------------------
 * fd                  | No        |           | SC_PARAM_INT | The file descriptor to write to when receiving end of stream
 *
 *
 *
 * \cond NODOC
 */

#include <sc_internal.h>
#include <inttypes.h>
#include <errno.h>

#include <unistd.h>

struct sct_eos_indicator
{
  const struct sc_node_link* next_hop;
  int32_t                    fd;
};


/* Forward all packets unchanged */
static void sct_eos_indicator_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct sct_eos_indicator* eos = node->nd_private;
  sc_forward_list(node, eos->next_hop, pl);
}


/* Write e to the fd each time eos is received */
static void sct_eos_indicator_end_of_stream(struct sc_node* node)
{
  struct sct_eos_indicator* eos = node->nd_private;
  char end_of_stream_str[] = "EOS";
  write(eos->fd, end_of_stream_str, sizeof(end_of_stream_str));
  sc_node_link_end_of_stream(node, eos->next_hop);
}


static int sct_eos_indicator_prep(struct sc_node* node,
                                 const struct sc_node_link*const* links,
                                 int n_links)
{
  struct sct_eos_indicator* eos = node->nd_private;
  eos->next_hop = (void*) sc_node_prep_get_link_or_free(node, "");
  return sc_node_prep_check_links(node);
}


static int sct_eos_indicator_init(struct sc_node* node, const struct sc_attr* attr,
                                 const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_prep_fn = sct_eos_indicator_prep;
    nt->nt_pkts_fn = sct_eos_indicator_pkts;
    nt->nt_end_of_stream_fn = sct_eos_indicator_end_of_stream;
  }
  node->nd_type = nt;

  /* Create private data structure */
  struct sc_thread* thread = sc_node_get_thread(node);
  struct sct_eos_indicator* eos = sc_thread_calloc(thread, sizeof(*eos));
  node->nd_private = eos;

  /* Get node arguments */
  int rc = 0;
  if( (rc = sc_node_init_get_arg_int(&eos->fd, node, "fd", -1)) < 0 )
    return rc;

  if( eos->fd == -1 )
    return sc_node_set_error(node, EINVAL,
      "ERROR: %s: missing fd argument\n", __func__);

  return 0;
}


const struct sc_node_factory sct_eos_indicator_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sct_eos_indicator",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sct_eos_indicator_init,
};
/** \endcond */
