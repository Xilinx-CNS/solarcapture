/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/*
 * cpacket_offsets.h
 *
 *  Created on: 22 May 2015
 *      Author: ld
 */

/** \cond NODOC */

#ifndef NODES_CPACKET_OFFSETS_H_
#define NODES_CPACKET_OFFSETS_H_

#include <netinet/in.h>
#include <stdint.h>
#include <stdbool.h>


struct cpacket_time {
  uint32_t s;
  uint32_t ns;
} __attribute__ ((packed));

typedef uint32_t fcs_t;


struct cpacket_data {
  struct cpacket_time time;
  uint8_t version;
  uint16_t device_id;
  uint8_t port;
} __attribute__ ((packed));


struct cpacket_footer {
  fcs_t old_fcs;
  struct cpacket_data data;
} __attribute__ ((packed));


struct cpacket_footer_with_fcs {
  fcs_t old_fcs;
  struct cpacket_data data;
  fcs_t new_fcs;
} __attribute__ ((packed));


inline static size_t cpacket_footer_length(bool has_fcs) {
  return has_fcs ? sizeof(struct cpacket_footer_with_fcs)
      : sizeof(struct cpacket_footer);
}


#endif /* NODES_CPACKET_OFFSETS_H_ */

/** \endcond NODOC */
