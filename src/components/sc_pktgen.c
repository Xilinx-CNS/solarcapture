/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/** \cond NODOC */
/*
 * NOTE: We do not want customers to use this node at this point.
 *       If you add any Doxygen documentation, mark it as \internal.
 */

#include <sc_internal.h>
#include <sc_internal/builtin_nodes.h>

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <arpa/inet.h>


static void* sc_alloc(struct sc_node* node, size_t bytes)
{
  return sc_thread_calloc(sc_node_get_thread(node), bytes);
}


static void sc_free(struct sc_node* node, void* ptr)
{
  return sc_thread_mfree(sc_node_get_thread(node), ptr);
}


static int sc_strtoul(const char* str, uint32_t* res_out)
{
  char* end;
  if( *str == '0' && *(str + 1) == 'x' ) {
    str += 2;
    *res_out = strtoul(str, &end, 16);
  }
  else
    *res_out = strtoul(str, &end, 10);
  if( end == str || *end != '\0' )
    return 1;
  return 0;
}


enum sc_hdr_field_type {
  FIELD_INT,
  FIELD_LEN,
  FIELD_IP,
  FIELD_MAC,
  FIELD_PROTO,
};


struct sc_hdr_field;
struct sc_hdr_field_desc;


typedef void (sc_hdr_field_gen_fn)(struct sc_hdr_field* field, void* target,
                                   uint32_t pkt_len);
typedef int (sc_hdr_field_parser_fn)(const char* value, void* target);


struct sc_hdr_field_desc {
  const char* name;
  uint8_t size;
  enum sc_hdr_field_type type;
  const char* default_value;
  sc_hdr_field_parser_fn* parser_fn;
};


struct sc_hdr_field {
  const struct sc_hdr_field_desc* desc;
  void* private_data;
  uint8_t hdr_offset; /* bytes from SOP to start of current header */
  sc_hdr_field_gen_fn* gen_fn;
};


struct sc_range_data {
  uint32_t min;
  uint32_t max;
  uint32_t next;
};


enum sc_value_type {
  VALUE_UNPARSABLE,
  VALUE_FIXED,
  VALUE_RANGE,
  VALUE_RANDOM_RANGE,
};


static int parse_ip_net(const char* s, uint32_t* ip, uint8_t* prefix_len)
{
  int rc, success = 0;
  char* dup = strdup(s);
  char* plen = strchr(dup, '/');
  uint32_t tmp;

  if( plen == NULL )
    goto out;

  *plen++ = '\0';
  rc = sc_strtoul(plen, &tmp);
  if( rc != 0 || tmp > 32 )
    goto out;
  *prefix_len = tmp;
  success = inet_pton(AF_INET, dup, ip);

 out:
  free(dup);
  return success ? 0 : 1;
}


static int parse_range(const char* s, sc_hdr_field_parser_fn parser,
                       uint32_t* min, uint32_t* max)
{
  int rc = 1;
  char* min_ptr = strdup(s);
  char* max_ptr = strchr(min_ptr, '-');

  if( max_ptr == NULL )
    goto out;

  *max_ptr++ = '\0';
  /* We call the underlying parser to validate the value, but we can't return
   * its result as we don't know its output type and we need to return a
   * uint32_t */
  if( (rc = parser(min_ptr, min)) != 0     ||
      (rc = sc_strtoul(min_ptr, min)) != 0 ||
      (rc = parser(max_ptr, max)) != 0     ||
      (rc = sc_strtoul(max_ptr, max)) != 0 )
    goto out;
 out:
  free(min_ptr);
  return rc;
}


static enum sc_value_type parse_value(struct sc_node* node,
                                      const struct sc_hdr_field_desc* desc,
                                      const char* buf, void** target)
{
  enum sc_value_type range_type = VALUE_RANGE;
  if( buf[0] == 'r' ) {
    ++buf;
    range_type = VALUE_RANDOM_RANGE;
  }
  if( strchr(buf, '-') != NULL ) { /* e.g. "128-255" */
    if( desc->type != FIELD_INT && desc->type != FIELD_LEN )
      return VALUE_UNPARSABLE;
    struct sc_range_data* rdata = sc_alloc(node, sizeof(struct sc_range_data));
    if( parse_range(buf, desc->parser_fn, &rdata->min, &rdata->max) == 0 && \
        rdata->min <= rdata->max && rdata->max < ( 1ULL << (desc->size * 8)) ) {
      rdata->next = rdata->min;
      *target = rdata;
      return range_type;
    }
    sc_free(node, rdata);
    return VALUE_UNPARSABLE;
  }

  else if( strchr(buf, '/') != NULL ) { /* e.g. "192.168.0.0/24" */
    if( desc->type != FIELD_IP )
      return VALUE_UNPARSABLE;
    struct sc_range_data* ipdata = sc_alloc(node, sizeof(struct sc_range_data));
    uint8_t tmp;
    if( parse_ip_net(buf, &ipdata->min, &tmp) == 0 ) {
      ipdata->min = ntohl(ipdata->min);
      ipdata->max = ipdata->min | ((1 << (32 - tmp)) - 1);
      ipdata->next = ipdata->min;
      *target = ipdata;
      return range_type;
    }
    sc_free(node, ipdata);
    return VALUE_UNPARSABLE;
  }

  else { /* single value */
    *target = sc_alloc(node, desc->size);
    if( desc->parser_fn(buf, *target) == 0 )
      return VALUE_FIXED;
    sc_free(node, *target);
    return VALUE_UNPARSABLE;
  }
}


static void gen_size(struct sc_hdr_field* field, void* target,
                     uint32_t pkt_len)
{
  *((uint16_t*) target) = htons(pkt_len - field->hdr_offset);
}


static void gen_range32(struct sc_hdr_field* field, void* target,
                        uint32_t pkt_len)
{
  struct sc_range_data* rdata = field->private_data;
  *(uint32_t*) target = htonl(rdata->next++);
  if( rdata->next > rdata->max || rdata->next == 0 )
    rdata->next = rdata->min;
}


static void gen_range16(struct sc_hdr_field* field, void* target,
                        uint32_t pkt_len)
{
  struct sc_range_data* rdata = field->private_data;
  *(uint16_t*) target = htons(rdata->next++);
  if( rdata->next > rdata->max || rdata->next == 0 )
    rdata->next = rdata->min;
}


static void gen_range8(struct sc_hdr_field* field, void* target,
                       uint32_t pkt_len)
{
  struct sc_range_data* rdata = field->private_data;
  *(uint8_t*) target = rdata->next++;
  if( rdata->next > rdata->max || rdata->next == 0 )
    rdata->next = rdata->min;
}


static void gen_random_range8(struct sc_hdr_field* field, void* target,
                              uint32_t pkt_len)
{
  struct sc_range_data* rdata = field->private_data;
  uint8_t tmp = rdata->min + rand() % (rdata->max - rdata->min + 1);
  *(uint8_t*) target = tmp;
}


static void gen_random_range16(struct sc_hdr_field* field, void* target,
                               uint32_t pkt_len)
{
  struct sc_range_data* rdata = field->private_data;
  uint16_t tmp = rdata->min + rand() % (rdata->max - rdata->min + 1);
  *(uint16_t*) target = htons(tmp);
}


static void gen_random_range32(struct sc_hdr_field* field, void* target,
                               uint32_t pkt_len)
{
  struct sc_range_data* rdata = field->private_data;
  uint32_t tmp = rdata->min + rand() % (rdata->max - rdata->min + 1);
  *(uint32_t*) target = htonl(tmp);
}


static int bad_field(struct sc_node* node, const char* key, const char* value)
{
  return sc_node_set_error(node, EINVAL,
                           "pktgen: ERROR: Unparsable %s ('%s')\n",
                           key, value);
}


static int init_field(struct sc_node* node,
                      const struct sc_hdr_field_desc* desc,
                      struct sc_hdr_field* field,
                      uint8_t hdr_offset)
{
  const char* buf;
  field->desc = desc;
  field->hdr_offset = hdr_offset;

  if( sc_node_init_get_arg_str(&buf, node, desc->name, NULL) < 0 )
    return -1;

  if( buf == NULL )
    buf = desc->default_value;
  enum sc_value_type vtype = parse_value(node, desc, buf, &field->private_data);
  if( vtype == VALUE_UNPARSABLE )
    goto unparsable;
  else if( vtype == VALUE_FIXED && desc->type == FIELD_LEN &&  \
      *((uint16_t*) field->private_data) == 0 )

    field->gen_fn = gen_size; /* Autogen size fields based on packet size */
  else if( vtype == VALUE_RANGE ) {
    switch( desc->size ) {
    case 1:
      field->gen_fn = gen_range8;
      break;
    case 2:
      field->gen_fn = gen_range16;
      break;
    case 4:
      field->gen_fn = gen_range32;
      break;
    default:
      goto unparsable;
    }
  }
  else if( vtype == VALUE_RANDOM_RANGE ) {
    switch( desc->size ) {
    case 1:
      field->gen_fn = gen_random_range8;
      break;
    case 2:
      field->gen_fn = gen_random_range16;
      break;
    case 4:
      field->gen_fn = gen_random_range32;
      break;
    default:
      goto unparsable;
    }
  }
  else
    field->gen_fn = NULL; /* memcpy private_data directly into packet */

  return vtype;
 unparsable:
  bad_field(node, desc->name, buf);
  return VALUE_UNPARSABLE;
}


static int parse_mac(const char* s, void* target)
{
  unsigned tmp[6];
  uint8_t* mac = target;
  int i;
  if( sscanf(s, "%x:%x:%x:%x:%x:%x",
             &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5]) != 6 )
    return -1;
  for( i = 0; i < 6; ++i )
    mac[i] = tmp[i];
  return 0;
}


static int parse_uint32(const char* s, void* target)
{
  uint32_t tmp;
  int rc = sc_strtoul(s, &tmp);
  if( rc != 0 )
    return 1;
  *(uint32_t*) target = htonl(tmp);
  return 0;
}


static int parse_uint16(const char* s, void* target)
{
  uint32_t tmp;
  int rc = sc_strtoul(s, &tmp);
  if( rc != 0 || tmp >= (1 << 16) )
    return 1;
  *(uint16_t*) target = htons(tmp);
  return 0;
}


static int parse_vlan(const char* s, void* target)
{
  int rc = parse_uint16(s, target);
  if( rc == 0 && ntohs(*(uint16_t*) target) >= (1 << 12) )
    rc = 1;
  return rc;
}


static int parse_uint8(const char* s, void* target)
{
  uint32_t tmp;
  int rc = sc_strtoul(s, &tmp);
  if( rc != 0 || tmp >= (1 << 8) )
    return 1;
  *(uint8_t*) target = tmp;
  return 0;
}


static int parse_proto(const char* s, void* target)
{
  if( !strcmp(s, "udp") )
    *(uint8_t*) target = IPPROTO_UDP;
  else if( !strcmp(s, "tcp") )
    *(uint8_t*) target = IPPROTO_TCP;
  else
    return parse_uint8(s, target);
  return 0;
}


static int parse_ip4(const char* s, void* target)
{
  uint32_t* ip = target;
  if( inet_pton(AF_INET, s, ip) != 1 )
    return 1;
  return 0;
}


static struct sc_hdr_field_desc sc_pkt_size = \
  { "size", 2, FIELD_INT, "60", parse_uint16 };


#define MAX_HEADERS 3
#define STATIC_HDR_SIZE 66 /* worst case (eth/vlan/ip/tcp/seqnum) */
#define NULL_FIELD {NULL, 0, 0, NULL, NULL}
#define SC_HDR_FIELD(name, size, type, dflt, parser) \
  { name, size, type, dflt, parser },

static struct sc_hdr_field_desc sc_eth_fields[] = {
#include "sc_pktgen_eth_hdr.h"
  NULL_FIELD,
};


static struct sc_hdr_field_desc sc_eth_vlan_fields[] = {
#include "sc_pktgen_eth_vlan_hdr.h"
  NULL_FIELD,
};


static struct sc_hdr_field_desc sc_ip4_fields[] = {
#include "sc_pktgen_ip4_hdr.h"
  NULL_FIELD,
};


static struct sc_hdr_field_desc sc_udp_fields[] = {
#include "sc_pktgen_udp_hdr.h"
  NULL_FIELD,
};


static struct sc_hdr_field_desc sc_tcp_fields[] = {
#include "sc_pktgen_tcp_hdr.h"
  NULL_FIELD,
};

#undef SC_HDR_FIELD



struct pktgen {
  struct sc_node*            node;
  struct sc_node*            tsa_node;
  const struct sc_node_link* next_hop;

  uint64_t                   pkt_seq;

  struct sc_hdr_field        pkt_size;
  bool                       has_vlan;
  uint8_t                    l4proto;
  uint64_t                   ns_per_pkt;
  void*                      packet_header;

  struct sc_packet*          current_packet;
  uint16_t                   bytes_rem;

  struct sc_hdr_field*       hdr_fields;
};


static int get_l4proto(struct sc_node* node, uint8_t* target)
{
  const char* tmp;
  if( sc_node_init_get_arg_str(&tmp, node, "protocol", "udp") < 0 )
    return -1;
  if( parse_proto(tmp, target) != 0 )
    return bad_field(node, "protocol", tmp);
  return 0;
}


static int get_has_vlan(struct sc_node* node, bool* target)
{
  const char* tmp;
  if( sc_node_init_get_arg_str(&tmp, node, "vlan_id", NULL) < 0 )
    return -1;
  *target = (tmp == NULL) ? false : true;
  return 0;
}


static int get_uint64(struct sc_node* node, const char* key, uint64_t* target)
{
  const char* tmp;
  char* end;
  if( sc_node_init_get_arg_str(&tmp, node, key, "0") < 0 )
    return -1;
  *target = strtoull(tmp, &end, 10);
  if( end == tmp || *end != '\0' )
    return bad_field(node, key, tmp);
  return 0;
}


static inline uint64_t hton64(uint64_t n)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
  uint32_t lo = n & 0xFFFFFFFF;
  uint32_t hi = n >> 32;
  return (( (uint64_t) htonl(lo)) << 32) | htonl(hi);
#else
  return n;
#endif
}


static void pktgen_pkts(struct sc_node* node, struct sc_packet_list* pl)
{
  struct pktgen* gen = node->nd_private;
  struct sc_packet* pkt = pl->head;
  struct sc_packet* next_pkt;
  struct iovec* iov;

  struct sc_packet_list outl;
  __sc_packet_list_init(&outl);

  while( pkt != NULL ) {
    next_pkt = pkt->next;
    if( gen->current_packet == NULL ) {
      uint16_t pkt_len;
      if( gen->pkt_size.gen_fn == NULL )
        pkt_len = *(uint16_t*) gen->pkt_size.private_data;
      else
        gen->pkt_size.gen_fn(&gen->pkt_size, &pkt_len, 0);
      pkt_len = ntohs(pkt_len);
      pkt->frame_len = pkt_len;
      if( pkt_len <= pkt->iov[0].iov_len ) {
        pkt->iov[0].iov_len = pkt_len;
        __sc_packet_list_append(&outl, pkt);
      }
      else {
        gen->current_packet = pkt;
        gen->bytes_rem = pkt_len - pkt->iov[0].iov_len;
      }

      uint8_t* ptr = gen->packet_header;

      int i = -1;
#define SC_HDR_FIELD(name, size, type, dflt, parser)                  \
      if( gen->hdr_fields[++i].gen_fn != NULL )                       \
        gen->hdr_fields[i].gen_fn(&gen->hdr_fields[i], ptr, pkt_len); \
      ptr += size;

      if( gen->has_vlan ) {
#include "sc_pktgen_eth_vlan_hdr.h"
      }
      else {
#include "sc_pktgen_eth_hdr.h"
      }
#include "sc_pktgen_ip4_hdr.h"
      if( gen->l4proto == IPPROTO_UDP ) {
#include "sc_pktgen_udp_hdr.h"
      }
      else if ( gen->l4proto == IPPROTO_TCP ) {
#include "sc_pktgen_tcp_hdr.h"
      }
#undef SC_HDR_FIELD

      *( (uint64_t*) ptr ) = hton64(gen->pkt_seq++);
      memcpy(pkt->iov[0].iov_base, gen->packet_header, STATIC_HDR_SIZE);
    }
    else {
      *(gen->current_packet->frags_tail) = pkt;
      gen->current_packet->frags_tail = &pkt->next;
      pkt->next = NULL;
      ++(gen->current_packet->frags_n);
      iov = gen->current_packet->iov + (gen->current_packet->iovlen)++;
      iov->iov_base = pkt->iov[0].iov_base;
      if( pkt->iov[0].iov_len >= gen->bytes_rem ) {
        iov->iov_len = gen->bytes_rem;
        __sc_packet_list_append(&outl, gen->current_packet);
        gen->current_packet = NULL;
      }
      else
        gen->bytes_rem -= (iov->iov_len = pkt->iov[0].iov_len);
    }
    pkt = next_pkt;
  }
  if( outl.num_pkts > 0 ) {
    sc_packet_list_finalise(&outl);
    sc_forward_list(gen->node, gen->next_hop, &outl);
  }
}


static void pktgen_end_of_stream(struct sc_node* node)
{
  struct pktgen* gen = node->nd_private;
  sc_node_link_end_of_stream(node, gen->next_hop);
}


static int pktgen_prep(struct sc_node* node,
                          const struct sc_node_link*const* links,
                          int n_links)
{
  struct pktgen* gen = node->nd_private;
  gen->next_hop = sc_node_prep_get_link_or_free(node, "");
  return sc_node_prep_check_links(node);
}


static int alloc_hdr_fields(struct sc_node* node)
{
  struct pktgen* gen = node->nd_private;
  struct sc_hdr_field* fields;
  int i, j;

  struct sc_hdr_field_desc* headers[MAX_HEADERS] = {
    gen->has_vlan ? sc_eth_vlan_fields : sc_eth_fields,
    sc_ip4_fields,
    (gen->l4proto == IPPROTO_UDP) ? sc_udp_fields : sc_tcp_fields,
  };

  int n_fields = 0;
  for( i = 0; i < MAX_HEADERS; ++i ) {
    j = 0;
    while( headers[i][j++].name != NULL )
      n_fields++;
  }

  fields = sc_alloc(node, sizeof(struct sc_hdr_field) * n_fields);

  uint8_t field_i=0, field_offset=0, hdr_offset=0;
  for( i = 0; i < MAX_HEADERS; ++i ) {
    j = 0;
    while( headers[i][j].name != NULL ) {
      if( init_field(node, &headers[i][j], &fields[field_i++],
                     hdr_offset) == VALUE_UNPARSABLE )
        goto err;
      field_offset += headers[i][j++].size;
    }
    hdr_offset = field_offset;
  }

  gen->hdr_fields = fields;

  gen->packet_header = sc_alloc(node, STATIC_HDR_SIZE);
  uint8_t* ptr = gen->packet_header;
  i = -1;
#define SC_HDR_FIELD(name, size, type, dflt, parser)    \
  if( gen->hdr_fields[++i].gen_fn == NULL )             \
    memcpy(ptr, gen->hdr_fields[i].private_data, size); \
  ptr += size;

  if( gen->has_vlan ) {
#include "sc_pktgen_eth_vlan_hdr.h"
  }
  else {
#include "sc_pktgen_eth_hdr.h"
  }
#include "sc_pktgen_ip4_hdr.h"
  if( gen->l4proto == IPPROTO_UDP ) {
#include "sc_pktgen_udp_hdr.h"
  }
  else if( gen->l4proto == IPPROTO_TCP ) {
#include "sc_pktgen_tcp_hdr.h"
  }
#undef SC_HDR_FIELD

  return 0;

 err:
  sc_free(node, fields);
  return 1;
}


/*
 * If we have a ts_adjust node, redirect all outgoing links to there,
 * with the exception of the link from this node to the sc_ts_adjust
 */
static int pktgen_add_link(struct sc_node* from_node,
                           const char* link_name,
                           struct sc_node* to_node,
                           const char* to_name_opt)
{
  struct pktgen* gen = from_node->nd_private;
  if( gen->tsa_node != NULL && to_node != gen->tsa_node)
    from_node = gen->tsa_node;
  return sc_node_add_link(from_node, link_name, to_node, to_name_opt);
}


/*
 * Allow users to provide our sc_ts_adjust node with a "controller" link
 * as they can with an independant sc_ts_adjust.
 */
struct sc_node* pktgen_select_subnode(struct sc_node* node,
                                      const char* name_opt,
                                      char** new_name_out)
{
  struct pktgen* gen = node->nd_private;
  if( name_opt != NULL && ! strcmp(name_opt, "controller") &&
      gen->tsa_node != NULL )
    node = gen->tsa_node;
  return node;
}


static int pktgen_setup_ts_adjust(struct pktgen* gen,
                                  const struct sc_attr* attr)
{
  const char* pps, *bw;
  if( sc_node_init_get_arg_str(&pps, gen->node, "pps", NULL) < 0 ||
      sc_node_init_get_arg_str(&bw, gen->node, "bw", NULL) < 0 )
    return -1;

  if( pps != NULL && bw != NULL )
    return sc_node_set_error(gen->node, EINVAL, "pps and bw are mutually "
                             "exclusive\n");
  else if( pps == NULL && bw == NULL )
    return 0; /* No rate requested, do not instantiate sc_ts_adjust */

  struct sc_arg tsa_args[] = {
    SC_ARG_INT("start_now", 1),
    SC_ARG_STR(pps ? "pps" : "bw", pps ? pps : bw),
  };

  int rc = sc_node_alloc(&gen->tsa_node, attr, sc_node_get_thread(gen->node),
                         &sc_ts_adjust_sc_node_factory, tsa_args,
                         sizeof(tsa_args) / sizeof(tsa_args[0]));
  if( rc != 0 )
    return rc;

  return sc_node_add_link(gen->node, "", gen->tsa_node, "");
}


static int pktgen_init(struct sc_node* node, const struct sc_attr* attr,
                       const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_prep_fn = pktgen_prep;
    nt->nt_pkts_fn = pktgen_pkts;
    nt->nt_add_link_fn = pktgen_add_link;
    nt->nt_select_subnode_fn = pktgen_select_subnode;
    nt->nt_end_of_stream_fn = pktgen_end_of_stream;
  }
  node->nd_type = nt;

  struct pktgen* gen;
  gen = sc_alloc(node, sizeof(*gen));
  node->nd_private = gen;
  gen->node = node;
  gen->current_packet = NULL;

  if( init_field(node, &sc_pkt_size, &gen->pkt_size, 0) == VALUE_UNPARSABLE ||
      get_l4proto(node, &gen->l4proto) != 0 ||
      get_has_vlan(node, &gen->has_vlan) != 0 ||
      get_uint64(node, "seq", &gen->pkt_seq) != 0 ||
      alloc_hdr_fields(node) != 0 ||
      pktgen_setup_ts_adjust(gen, attr) != 0 )
    return -1;

  return 0;
}

const struct sc_node_factory sc_pktgen_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_pktgen",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = pktgen_init,
};
/** \endcond NODOC */
