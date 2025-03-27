/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/*
 * sc_arista7280_ts.h
 *
 *  Created on: 04 Apr 2019
 *      Author: marsik
 */

/** \cond NODOC */
#ifndef __SC_ARISTA7280_TS_H__
#define __SC_ARISTA7280_TS_H__

#define SC_NS_IN_S 1000000000ULL
#define SC_MS_IN_S 1000ULL
#define SC_NS_IN_MS 1000000ULL

#define ARISTA7280_ETHERTYPE 0xD28B
#define ARISTA7280_PROTOCOL_SUBTYPE 0x0001
/* R2 series protocol versions */
#define ARISTA7280_PROTOCOL_VERSION_64BIT_TAI 0x0010
#define ARISTA7280_PROTOCOL_VERSION_64BIT_UTC 0x0110
#define ARISTA7280_PROTOCOL_VERSION_48BIT_TAI 0x0020
#define ARISTA7280_PROTOCOL_VERSION_48BIT_UTC 0x0120
/* R3 series protocol versions */
#define ARISTA7280_PROTOCOL_VERSION_64BIT_TAI_R3 0x0011
#define ARISTA7280_PROTOCOL_VERSION_64BIT_UTC_R3 0x0111
#define ARISTA7280_PROTOCOL_VERSION_48BIT_TAI_R3 0x0021
#define ARISTA7280_PROTOCOL_VERSION_48BIT_UTC_R3 0x0121

#ifndef ETHERTYPE_LLDP
# define ETHERTYPE_LLDP   0x88CC
#endif

/* Length of the two mac addresses at the start of any packet */
#define MAC_ADDRESSES_SIZE 12

typedef enum {
  GOOD_PACKET,
  NO_TIMESTAMP,
} ts_class ;


static const void* p_or(const void* a, const void* b)
{
  return a ? a : b;
}


static inline void pkt_ts_from_ns(struct sc_packet* pkt, uint64_t ts)
{
  pkt->ts_sec = ts / SC_NS_IN_S;
  pkt->ts_nsec = ts % SC_NS_IN_S;
}


static inline void ps_pkt_ts_from_ns(struct sc_packed_packet* ps_pkt,
                                     uint64_t ts)
{
  ps_pkt->ps_ts_sec = ts / SC_NS_IN_S;
  ps_pkt->ps_ts_nsec = ts % SC_NS_IN_S;
}


/* Compares first 3 bytes pointed to by args.  Returns 0 if they're the
 * same else non-zero.
 */
static inline int cmp_oui(const void* oui_a, const void* oui_b)
{
  const uint8_t* a = oui_a;
  const uint8_t* b = oui_b;

  return (a[0] - b[0]) | (a[1] - b[1]) | (a[2] - b[2]);
}


/* Parses string into a oui */
static inline int parse_oui(uint8_t* oui, const char* s)
{
  unsigned u[3];
  char c;
  int i;

  if( sscanf(s, "%x:%x:%x%c", &u[0], &u[1], &u[2], &c) != 3 )
    return -1;
  for( i = 0; i < 3; ++i ) {
    if( u[i] > 255 )
      return -1;
    oui[i] = u[i];
  }
  return 0;
}


static inline int parse_mac(uint8_t* mac, const char* s)
{
  unsigned u[6];
  int i;
  char c;
  if( sscanf(s, "%x:%x:%x:%x:%x:%x%c",
             &u[0], &u[1], &u[2], &u[3], &u[4], &u[5], &c) != 6 )
    return -1;
  for( i = 0; i < 6; ++i ) {
    if( u[i] > 255 )
      return -1;
    mac[i] = u[i];
  }
  return 0;
}


static int get_bool(bool* v, struct sc_node* node,
                    const char* k, int default_v)
{
  int temp = 0;

  if( sc_node_init_get_arg_int(&temp, node, k, default_v) < 0 ||
      temp < 0 || temp > 1 )
    return sc_node_set_error(node, EINVAL, "sc_arista7280: ERROR: "
                             "bad value for arg '%s'; expected 0 or 1\n", k);
  *v = (bool)temp;
  return 0;
}

#endif  /* __SC_ARISTA7280_TS_H__ */
/** \endcond NODOC */
