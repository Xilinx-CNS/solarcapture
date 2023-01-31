/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#include <stdlib.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <assert.h>
#include <errno.h>

#define SC_API_VER SC_API_VER_MAX

#include <solar_capture.h>
#include <stdio.h>

#include "pcap-sfsc-poolnode.h"


#define TEST(x)                                                         \
  do {                                                                  \
    if( ! (x) ) {                                                       \
      fprintf(stderr, "ERROR: %s: TEST(%s) failed\n", __func__, #x);    \
      fprintf(stderr, "ERROR: at %s:%d\n", __FILE__, __LINE__);         \
      abort();                                                          \
    }                                                                   \
  } while( 0 )


static int sfsc_pool_node_prep(struct sc_node* node,
			    const struct sc_node_link* const* links,
			    int n_links)
{
	struct sfsc_pool_node_state* st = node->nd_private;
	const struct sc_node_link* next_hop = sc_node_prep_get_link(node, "");
	struct sc_attr* attr;

	TEST(sc_attr_alloc(&attr) == 0);
	TEST(sc_attr_set_int(attr, "private_pool", 1) == 0);
	TEST(sc_attr_set_int(attr, "n_bufs_tx", 500) == 0);
	TEST(sc_node_prep_get_pool(&st->pool, attr, node, &next_hop, 1)
	     == 0);
	st->next_hop = next_hop;
	sc_attr_free(attr);
	return sc_node_prep_check_links(node);
}


static int sfsc_pool_node_init(struct sc_node* node, const struct sc_attr* attr,
			    const struct sc_node_factory* factory)
{
	static struct sc_node_type* nt;
	if( nt == NULL ) {
		sc_node_type_alloc(&nt, NULL, factory);
		nt->nt_prep_fn = sfsc_pool_node_prep;
	}
	node->nd_type = nt;

	struct sfsc_pool_node_state* st;
	st = sc_thread_calloc(sc_node_get_thread(node), sizeof(*st));
	node->nd_private = st;
	st->node = node;

	return 0;
}


const struct sc_node_factory sfsc_pool_node_sc_node_factory = {
	.nf_node_api_ver = SC_API_VER,
	.nf_name = "sfsc_pool",
	.nf_source_file = __FILE__,
	.nf_init_fn = sfsc_pool_node_init,
};
