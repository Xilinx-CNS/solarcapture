/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \file
 * \brief Private state of \noderef{sc_append_to_list} node.
 */

#ifndef __SOLAR_CAPTURE_NODES_APPEND_TO_LIST_H__
#define __SOLAR_CAPTURE_NODES_APPEND_TO_LIST_H__

/**
 * \struct sc_append_to_list
 *
 * \brief Private state of \noderef{sc_append_to_list} node.
 *
 * See the \noderef{sc_append_to_list} node for details of how this is
 * used.
 */
struct sc_append_to_list {
  /** After 'prep' points to a link that can be used to free packets. */
  const struct sc_node_link*  free_link;
  /** After 'prep' points to the node's output links. */
  const struct sc_node_link** links;
  /** After 'prep' gives the number of output links. */
  int                         n_links;
  /** Application must point this at an initialised packet list. */
  struct sc_packet_list*      append_to;
};


#endif  /* __SOLAR_CAPTURE_NODES_APPEND_TO_LIST_H__ */
