/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#ifndef __SOLAR_CAPTURE_NODES_EOS_FWD_H__
#define __SOLAR_CAPTURE_NODES_EOS_FWD_H__


/* Register link with sc_eos_fwd node. When the node receives an end_of_stream,
 * it is forwarded on all registered links.
 */
void sc_eos_fwd_register_link(struct sc_node* eos_fwd_node,
                              const struct sc_node_link* eos_link);

#endif  /* __SOLAR_CAPTURE_NODES_EOS_FWD_H__ */
