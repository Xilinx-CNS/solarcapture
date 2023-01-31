/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/*
 * File contains interface of simple memory ring buffer.
 */
#ifndef __PKT_RING_H__
#define __PKT_RING_H__


struct pkt_ring;

extern int pkt_ring_alloc(struct pkt_ring** ring_out, unsigned long size);

extern int pkt_ring_put(struct pkt_ring* ring, const void* payload, int len);

extern int pkt_ring_get(struct pkt_ring* ring, void** payload, int* len_out);


#endif  /* __PKT_RING_H__ */
