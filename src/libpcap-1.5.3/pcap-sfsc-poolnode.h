/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/* The pool node exists purely to provide a means to aquire an sc_pool.
 *
 * It will allocate an sc_pool, which can then be accessed via the node state
 * once the node has been prepped (after sc_session_go).
 */
extern const struct sc_node_factory sfsc_pool_node_sc_node_factory;

struct sfsc_pool_node_state {
	struct sc_node* node;
	struct sc_pool* pool;
	const struct sc_node_link* next_hop;
};
