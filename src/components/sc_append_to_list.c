/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \node{sc_append_to_list}
 *
 * \brief Append incoming packets to an ::sc_packet_list.
 *
 * \nodedetails

 * This node provides a simple way to get packet buffers out of the
 * SolarCapture node graph, and is typically used with an unmanaged thread.
 * It is often used when writing code to adapt the SolarCapture API to
 * another API, or embed SolarCapture in an application.
 *
 * After allocating an instance of this node, the application must
 * initialise sc_append_to_list::append_to so that it points to an
 * initialised ::sc_packet_list.  Here is an example:
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * sc_node_alloc_named(&node, attr, thread, "sc_append_to_list", NULL, NULL, 0);
 * struct sc_append_to_list* atl = node->nd_private;
 * struct sc_packet_list my_packet_list;
 * sc_packet_list_init(&my_packet_list);
 * atl->append_to = &my_packet_list;
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * Packet buffers delivered in this way should eventually be returned to
 * SolarCapture by forwarding them through one of this node's output links,
 * or through its free_link:
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * sc_forward_list2(atl->free_link, &my_packet_list);
 * sc_packet_list_init(&my_packet_list);
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * \cond NODOC
 */

#include <sc_internal.h>
#include <sc_internal/builtin_nodes.h>
#include <solar_capture/nodes/append_to_list.h>


static void sc_append_to_list_pkts(struct sc_node* node,
                                   struct sc_packet_list* pl)
{
  struct sc_append_to_list* st = node->nd_private;
  sc_packet_list_append_list(st->append_to, pl);
}


static int sc_append_to_list_prep(struct sc_node* node,
                                  const struct sc_node_link* const* links,
                                  int n_links)
{
  struct sc_append_to_list* st = node->nd_private;
  st->free_link = sc_node_prep_get_link_or_free(node, NULL);
  st->links = sc_thread_calloc(sc_node_get_thread(node),
                               n_links * sizeof(st->links[0]));
  st->n_links = n_links;
  SC_TEST(st->links != NULL);
  int i;
  for( i = 0; i < n_links; ++i )
    st->links[i] = links[i];
  return 0;
}


static int sc_append_to_list_init(struct sc_node* node,
                                  const struct sc_attr* attr,
                                  const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_prep_fn = sc_append_to_list_prep;
    nt->nt_pkts_fn = sc_append_to_list_pkts;
  }
  node->nd_type = nt;

  int init_list;
  if( sc_node_init_get_arg_int(&init_list, node, "init_list", 0) < 0 )
    return -1;

  struct sc_thread* thread = sc_node_get_thread(node);
  struct sc_append_to_list* st;
  st = sc_thread_calloc(thread, sizeof(*st));
  node->nd_private = st;

  if( init_list ) {
    st->append_to = sc_thread_calloc(thread, sizeof(*st->append_to));
    sc_packet_list_init(st->append_to);
  }

  return 0;
}


const struct sc_node_factory sc_append_to_list_sc_node_factory = {
  .nf_node_api_ver = SC_API_VER,
  .nf_name = "sc_append_to_list",
  .nf_source_file = __FILE__,
  .nf_init_fn = sc_append_to_list_init,
};

/** \endcond NODOC */
