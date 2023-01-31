/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \file
 * \brief \noderef{sc_subnode_helper} node interface.
 */
 
#ifndef __SOLAR_CAPTURE_NODES_SUBNODE_HELPER_H__
#define __SOLAR_CAPTURE_NODES_SUBNODE_HELPER_H__
#if SC_API_VER >= 4

struct sc_subnode_helper;

/**
 * \relates sc_subnode_helper
 * \brief Signature of sh_handle_backlog_fn
 *
 * \param sh   The sc_subnode_helper instance.
 *
 * The backlog handler is responsible for forwarding packets in the backlog
 * to one of the outgoing links.  It is invoked when any of the following
 * events occurs:
 *
 * 1. The backlog transitions from empty to non-empty and sh_pool (if set)
 *    has at least sh_pool_threshold buffers available.
 *
 * 2. The backlog is non-empty and the pool fill level increases above
 *    sh_pool_threshold.
 *
 * 3. Periodically every sh_backlog_poll_ns (if non-zero) while the backlog
 *    is non-empty.
 *
 * 4. After sc_subnode_helper_request_callback() is called.
 *
 * The handler is called repeatedly until either the backlog is empty or
 * the length of the backlog remains unmodified across the callback.  Note
 * that when the backlog handler is invoked due to timeout or
 * request_callback(), the pool threshold is not considered.
 */
typedef void (sc_sh_handle_backlog_fn)(struct sc_subnode_helper* sh);


/**
 * \relates sc_subnode_helper
 * \brief Signature of sh_handle_end_of_stream_fn
 *
 * \param sh   The sc_subnode_helper instance.
 *
 * The end-of-stream handler is invoked when the following conditions are
 * all true:
 *
 * 1. The node has received the end-of-stream signal.
 *
 * 2. The backlog is empty.
 *
 * 3. sh_pool (if set) has at least sh_pool_threshold buffers available.
 *
 * If this handler is set, it is responsible for propagating end-of-stream
 * to the outgoing links.  If no handler is provided, end-of-stream is
 * automatically propagated to all outputs once the backlog is empty.
 */
typedef void (sc_sh_handle_end_of_stream_fn)(struct sc_subnode_helper* sh);


/**
 * \struct sc_subnode_helper
 * \brief \noderef{sc_subnode_helper} node private state.
 */
struct sc_subnode_helper {
  void*                          sh_private;                 /**< Private state for the user */
  struct sc_node*                sh_node;                    /**< The node */
  const struct sc_node_link*     sh_free_link;               /**< A node link for freeing packets (if requested) */
  const struct sc_node_link**    sh_links;                   /**< Outgoing links */
  struct sc_packet_list          sh_backlog;                 /**< Unprocessed incoming packets */
  uint64_t                       sh_poll_backlog_ns;         /**< Interval at which to poll backlog handler when backlog is not empty */
  sc_sh_handle_backlog_fn*       sh_handle_backlog_fn;       /**< Handler invoked to process the backlog */
  struct sc_pool*                sh_pool;                    /**< A packet pool (if requested) */
  sc_sh_handle_end_of_stream_fn* sh_handle_end_of_stream_fn; /**< Handler invoked when end of stream has been signalled and the backlog is empty */
  int                            sh_pool_threshold;          /**< Number of buffers that must be available in the pool before calling the backlog handler */
  int                            sh_n_links;                 /**< Number of outgoing links */
};


/**
 * \relates sc_subnode_helper
 * \brief Get *sc_subnode_helper from sc_node*
 *
 * \param node   Node of type sc_subnode_helper.
 *
 * \return The sc_subnode_helper from the node
 */
static inline struct sc_subnode_helper*
  sc_subnode_helper_from_node(struct sc_node* node)
{
  return (struct sc_subnode_helper*) node->nd_private;
}


/**
 * \relates sc_subnode_helper
 * \brief Request that sc_subnode_helper calls its backlog handler at a
 * safe time.
 *
 * \param sh     An sc_subnode_helper instance
 */
extern void sc_subnode_helper_request_callback(struct sc_subnode_helper* sh);


#endif
#endif  /* __SOLAR_CAPTURE_NODES_SUBNODE_HELPER_H__ */
