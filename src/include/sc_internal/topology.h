/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#ifndef __SC_TOPOLOGY_H__
#define __SC_TOPOLOGY_H__


extern int sc_topology_check(struct sc_session* tg);

extern uint64_t sc_topology_find_sender_netifs(struct sc_node_impl*);

extern void sc_topology_dump(struct sc_session*);


#endif  /* __SC_TOPOLOGY_H__ */
