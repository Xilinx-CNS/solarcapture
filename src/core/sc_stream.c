/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#include "internal.h"
#include <sc_internal/ef_vi.h>
#include <sc_internal/stream.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <net/ethernet.h>


#define BAD_STREAM(stream, err, ...)                                    \
  sc_set_err((stream)->st_tg, (err), "ERROR: bad stream: " __VA_ARGS__)

#define BAD_STREAM_KEY(stream, key, value)                      \
  BAD_STREAM((stream), EINVAL, "%s=\"%s\"\n", (key), (value))


static int my_getaddrinfo(const char* host, const char* port,
                          struct addrinfo** ai_out)
{
  struct addrinfo hints;
  hints.ai_flags = 0;
  hints.ai_family = AF_INET;
  hints.ai_socktype = 0;
  hints.ai_protocol = 0;
  hints.ai_addrlen = 0;
  hints.ai_addr = NULL;
  hints.ai_canonname = NULL;
  hints.ai_next = NULL;
  return getaddrinfo(host, port, &hints, ai_out);
}


static int parse_ip4(const char* host, const char* port,
                     uint32_t* ip_out, uint16_t* port_out)
{
  int rc;
  struct addrinfo* ai;
  if( (rc = my_getaddrinfo(host, port, &ai)) )
      return rc;
  const struct sockaddr_in* sin = (void*) ai->ai_addr;
  *ip_out = sin->sin_addr.s_addr;
  *port_out = sin->sin_port;
  freeaddrinfo(ai);
  return 0;
}

static int parse_ip4_host(const char* host, uint32_t* ip_out)
{
  int rc;
  struct addrinfo* ai;
  if( (rc = my_getaddrinfo(host, "0", &ai)) )
      return rc;
  const struct sockaddr_in* sin = (void*) ai->ai_addr;
  *ip_out = sin->sin_addr.s_addr;
  freeaddrinfo(ai);
  return 0;
}

static int parse_ip4_port(const char* port, uint16_t* port_out)
{
  int rc;
  if( strlen(port) == 0 )
    return EAI_NONAME;
  struct addrinfo* ai;
  if( (rc = my_getaddrinfo("0", port, &ai)) )
      return rc;
  const struct sockaddr_in* sin = (void*) ai->ai_addr;
  *port_out = sin->sin_port;
  freeaddrinfo(ai);
  return 0;
}

static int parse_mac(const char* mac, uint8_t* mac_out)
{
  int i;
  unsigned u[6];
  char dummy;

  if( sscanf(mac, "%x:%x:%x:%x:%x:%x%c",
             &u[0], &u[1], &u[2], &u[3], &u[4], &u[5], &dummy) != 6 )
    return -1;

  for( i = 0; i < 6; i++ ) {
    if( u[i] > UINT8_MAX )
      return - 1;
    mac_out[i] = u[i];
  }

  return 0;
}


/* Convert string to integer and generate suitable error message if it
 * fails.
 */
static int strm_convert_i(int* res_out, struct sc_stream* stream,
                          const char* val, const char* val_type,
                          const char* expected, int min, int max)
{
  int rc = sc_strtoi_range(res_out, val, 0, min, max);
  if( rc < 0 )
    rc = BAD_STREAM(stream, -rc, "%s=%s; expected %s\n",
                    val_type, val, expected);
  return rc;
}


static int set_eth_type(struct sc_stream* stream, const char* value)
{
  int eth_type;
  if( ! strcasecmp(value, "ip") ) {
    eth_type = ETHERTYPE_IP;
  }
  else if( ! strcasecmp(value, "arp") ) {
    eth_type = ETHERTYPE_ARP;
  }
  else {
    int rc = strm_convert_i(&eth_type, stream, value, "eth_type",
                            "'ip' or 0-0xffff", 0, 0xffff);
    if( rc < 0 )
      return rc;
  }
  return sc_stream_eth_type(stream, eth_type);
}


static int set_protocol(struct sc_stream* stream, const char* value)
{
  int protocol;
  if( !strcmp(value, "udp") ) {
    protocol = IPPROTO_UDP;
  }
  else if( !strcmp(value, "tcp") ) {
    protocol = IPPROTO_TCP;
  }
  else {
    int rc = strm_convert_i(&protocol, stream, value, "ip_protocol",
                            "'tcp', 'udp' or 0-255", 0, 255);
    if( rc < 0 )
      return rc;
  }
  return sc_stream_ip_protocol(stream, protocol);
}


static int set_vlan_id(struct sc_stream* stream, const char* value)
{
  int vlan_id;
  int rc = strm_convert_i(&vlan_id, stream, value, "vid", "0-0xfff", 0, 0xfff);
  if( rc < 0 )
    return rc;
  return sc_stream_eth_vlan_id(stream, vlan_id);
}


/* eth abbreviated syntax is:
 * eth:[vid=<vlan>,]<local-mac>
 */
static int set_eth_abbrev(struct sc_stream* stream, char* stream_str,
                          const char* orig_stream_str)
{
  int rc = -1;
  uint8_t mac[6];
  char* token;
  char* next_token;

  next_token = stream_str;
  token = strsep(&next_token, ":"); /* token = eth */
  if( !next_token || strcmp(token, "eth") )
    goto fail_set_error;

  /* There could be an optional vlan id here */
  token = strsep(&next_token, "="); /* token = vid */
  if( next_token ) {
    if( strcmp(token, "vid") )
      goto fail_set_error;

    token = strsep(&next_token, ","); /* token = vlan */
    if( next_token == NULL )
      goto fail_set_error;
    rc = set_vlan_id(stream, token);
    if( rc < 0 )
      return rc;
  }
  else {
    next_token = token;
  }

  /* Determine mac address (rest of string) */
  if( (rc = parse_mac(next_token, mac)) < 0 )
    goto fail_set_error;
  return sc_stream_eth_dhost(stream, mac);

 fail_set_error:
  return BAD_STREAM(stream, EINVAL, "%s\n", orig_stream_str);
}


/* ip abbreviated syntax is:
 * {udp,tcp}:[vid=<vlan>,]<local-host>:<local-port>
 * {udp,tcp}:[vid=<vlan>,]<local-host>:<local-port>,<remote-host>:<remote-port>
 */
static int set_ip_abbrev(struct sc_stream* stream, char* stream_str,
                         const char* orig_stream_str)
{
  int rc = -1;
  char* token;
  char* next_token;

  next_token = stream_str;
  token = strsep(&next_token, ":"); /* token = {udp,tcp} */
  if( !next_token )
    goto fail_set_error;

  /* Determine protocol */
  if( !strcmp(token, "udp") )
    rc = sc_stream_ip_protocol(stream, IPPROTO_UDP);
  else if( !strcmp(token, "tcp") )
    rc = sc_stream_ip_protocol(stream, IPPROTO_TCP);
  else
    goto fail_set_error;

  /* There could be an optional vlan id here */
  token = strsep(&next_token, "="); /* token = vid */
  if( next_token ) {
    if( strcmp(token, "vid") )
      goto fail_set_error;

    token = strsep(&next_token, ","); /* token = vlan */
    if( (rc = set_vlan_id(stream, token)) < 0 )
      return rc;
  }
  else {
    next_token = token;
  }

  /* Determine local host and port */
  token = strsep(&next_token, ":"); /* token = local-host */
  if( !next_token )
    goto fail_set_error;
  if( (rc = sc_stream_ip_dest_host(stream, token)) < 0 )
    return rc;

  token = strsep(&next_token, ","); /* token = local-port */
  if( (rc = sc_stream_ip_dest_port(stream, token)) < 0 )
    return rc;

  if( next_token ) {
    /* Determine optional remote host and port */
    token = strsep(&next_token, ":"); /* token = [remote-host] */
    if( next_token == NULL )
      goto fail_set_error;
    if( (rc = sc_stream_ip_source_host(stream, token)) < 0 )
      return rc;

    token = next_token; /* token = remote-port */
    if( (rc = sc_stream_ip_source_port(stream, token)) < 0 )
      return rc;
  }

  return rc;

 fail_set_error:
  return BAD_STREAM(stream, EINVAL, "%s\n", orig_stream_str);
}


static int set_general(struct sc_stream* stream, char* stream_str,
                       const char* orig_stream_str)
{
  int rc = 0;
  uint8_t mac[6];
  char* key;
  char* value;
  char* key_value;

  /* General format is series of key=value pairs, separated by ",". */
  while( stream_str && (rc == 0) ) {

    /* Split key and value */
    key_value = strsep(&stream_str, ",");
    if( strchr(key_value, '=') ) {
      key = strsep(&key_value, "=");
      value = key_value;
    }
    else {
      key = key_value;
      if( !strcmp(key, "ip") )
        rc = set_eth_type(stream, key);
      else if( !strcmp(key, "tcp") || !strcmp(key, "udp") )
        rc = set_protocol(stream, key);
      else
        return BAD_STREAM(stream, EINVAL, "Invalid key \"%s\"\n", key);
      continue;
    }

    if( !strcmp(key, "dmac") ) {
      if( parse_mac(value, mac) < 0 )
        return BAD_STREAM_KEY(stream, key, value);
      rc = sc_stream_eth_dhost(stream, mac);
    }
    else if( !strcmp(key, "smac") ) {
      if( parse_mac(value, mac) < 0 )
        return BAD_STREAM_KEY(stream, key, value);
      rc = sc_stream_eth_shost(stream, mac);
    }
    else if( !strcmp(key, "vid") ) {
      rc = set_vlan_id(stream, value);
    }
    else if( !strcmp(key, "eth_type") ) {
      rc = set_eth_type(stream, value);
    }
    else if( !strcmp(key, "shost") ) {
      rc = sc_stream_ip_source_host(stream, value);
    }
    else if( !strcmp(key, "dhost") ) {
      rc = sc_stream_ip_dest_host(stream, value);
    }
    else if( !strcmp(key, "ip_protocol") ) {
      rc = set_protocol(stream, value);
    }
    else if( !strcmp(key, "sport") ) {
      rc = sc_stream_ip_source_port(stream, value);
    }
    else if( !strcmp(key, "dport") ) {
      rc = sc_stream_ip_dest_port(stream, value);
    }
    else {
      rc = BAD_STREAM(stream, EINVAL, "Invalid key \"%s\"\n", key);
    }
  }

  return rc;
}


int sc_stream_alloc(struct sc_stream** stream_out, const struct sc_attr* attr,
                    struct sc_session* tg)
{
  struct sc_stream* s = calloc(1, sizeof(*s));
  TEST(s);
  s->st_tg = tg;

  int rc = sc_get_capture_mode(tg, attr, &s->capture_mode);
  if( rc < 0 )
    goto fail;
  s->promiscuous = attr->promiscuous;
  s->vid_optional = attr->vid_optional;

  *stream_out = s;
  return 0;

 fail:
  free(s);
  return rc;
}


int sc_stream_free(struct sc_stream* s)
{
  free(s);
  return 0;
}


int sc_stream_reset(struct sc_stream* s)
{
  s->fields = 0;
  return 0;
}


int sc_stream_set_str(struct sc_stream* stream, const char* str)
{
  int rc;
  char* stream_str = strdup(str);

  if( !stream_str )
    return sc_set_err(stream->st_tg, ENOMEM,
                      "%s: ERROR: out of memory\n", __func__);

  sc_stream_reset(stream);
  sc_trace(stream->st_tg, "%s: setting stream %s\n", __func__, str);

  if( !strcmp(stream_str, "all") )
    rc = sc_stream_all(stream);
  else if( !strcmp(stream_str, "mismatch") )
    rc = sc_stream_mismatch(stream);
  else if( !strncmp(stream_str, "eth:", 4) )
    rc = set_eth_abbrev(stream, stream_str, str);
  else if( !strncmp(stream_str, "udp:", 4) ||
           !strncmp(stream_str, "tcp:", 4) )
    rc = set_ip_abbrev(stream, stream_str, str);
  else
    rc = set_general(stream, stream_str, str);

  free(stream_str);
  return rc;
}


int sc_stream_all(struct sc_stream* s)
{
  s->fields |= SC_SF_ALL;
  return 0;
}


int sc_stream_mismatch(struct sc_stream* s)
{
  s->fields |= SC_SF_MISMATCH;
  return 0;
}


int sc_stream_ip_dest_hostport(struct sc_stream* s, int protocol,
                               const char* dhost, const char* dport)
{
  int rc;
  s->ip4_protocol = protocol;
  rc = parse_ip4(dhost, dport, &s->ip4_dest_addr, &s->ip4_dest_port);
  if( rc )
    return sc_set_err(s->st_tg, ENOENT,
                      "%s: ERROR: Lookup of '%s:%s' failed (%d %s)\n",
                      __func__, dhost, dport, rc, gai_strerror(rc));
  s->fields |=
    SC_SF_IP4_PROTOCOL |
    SC_SF_IP4_DEST_ADDR |
    SC_SF_IP4_DEST_PORT;
  sc_stream_eth_type(s, ETHERTYPE_IP);
  return 0;
}


int sc_stream_ip_source_hostport(struct sc_stream* s,
                                 const char* shost, const char* sport)
{
  int rc;
  rc = parse_ip4(shost, sport, &s->ip4_source_addr, &s->ip4_source_port);
  if( rc )
    return sc_set_err(s->st_tg, ENOENT,
                      "%s: ERROR: Lookup of '%s:%s' failed (%d %s)\n",
                      __func__, shost, sport, rc, gai_strerror(rc));
  s->fields |=
    SC_SF_IP4_SOURCE_ADDR |
    SC_SF_IP4_SOURCE_PORT;
  sc_stream_eth_type(s, ETHERTYPE_IP);
  return 0;
}


int sc_stream_eth_dhost(struct sc_stream* s, const uint8_t* mac_addr)
{
  memcpy(s->eth_dhost, mac_addr, 6);
  s->fields |= SC_SF_ETH_DHOST;
  return 0;
}

int sc_stream_eth_shost(struct sc_stream* s, const uint8_t* mac_addr)
{
  memcpy(s->eth_shost, mac_addr, 6);
  s->fields |= SC_SF_ETH_SHOST;
  return 0;
}

int sc_stream_eth_vlan_id(struct sc_stream* s, int vlan_id)
{
  if( vlan_id < 0 || vlan_id > 0xFFF )
    return BAD_STREAM(s, ERANGE, "vid=%d out of range\n", vlan_id);
  s->eth_vlan_id = vlan_id;
  s->fields |= SC_SF_ETH_VLAN_ID;
  return 0;
}

int sc_stream_eth_type(struct sc_stream* s, uint16_t eth_type)
{
  s->eth_type = htons(eth_type);
  s->fields |= SC_SF_ETH_TYPE;
  return 0;
}

int sc_stream_ip_dest_host(struct sc_stream* s, const char* dhost)
{
  int rc;
  rc = parse_ip4_host(dhost, &s->ip4_dest_addr);
  if( rc )
    return sc_set_err(s->st_tg, ENOENT,
                      "%s: ERROR: Lookup of '%s' failed (%d %s)\n",
                      __func__, dhost, rc, gai_strerror(rc));
  s->fields |= SC_SF_IP4_DEST_ADDR;
  sc_stream_eth_type(s, ETHERTYPE_IP);
  return 0;
}

int sc_stream_ip_dest_port(struct sc_stream* s, const char* dport)
{
  int rc;
  rc = parse_ip4_port(dport, &s->ip4_dest_port);
  if( rc )
    return sc_set_err(s->st_tg, ENOENT,
                      "%s: ERROR: Lookup of '%s' failed (%d %s)\n",
                      __func__, dport, rc, gai_strerror(rc));
  s->fields |= SC_SF_IP4_DEST_PORT;
  sc_stream_eth_type(s, ETHERTYPE_IP);
  return 0;
}

int sc_stream_ip_source_host(struct sc_stream* s, const char* shost)
{
  int rc;
  rc = parse_ip4_host(shost, &s->ip4_source_addr);
  if( rc )
    return sc_set_err(s->st_tg, ENOENT,
                      "%s: ERROR: Lookup of '%s' failed (%d %s)\n",
                      __func__, shost, rc, gai_strerror(rc));
  s->fields |= SC_SF_IP4_SOURCE_ADDR;
  sc_stream_eth_type(s, ETHERTYPE_IP);
  return 0;
}

int sc_stream_ip_source_port(struct sc_stream* s, const char* sport)
{
  int rc;
  rc = parse_ip4_port(sport, &s->ip4_source_port);
  if( rc )
    return sc_set_err(s->st_tg, ENOENT,
                      "%s: ERROR: Lookup of '%s' failed (%d %s)\n",
                      __func__, sport, rc, gai_strerror(rc));
  s->fields |= SC_SF_IP4_SOURCE_PORT;
  sc_stream_eth_type(s, ETHERTYPE_IP);
  return 0;
}

int sc_stream_ip_protocol(struct sc_stream* s, int protocol)
{
  if( protocol < 0 || protocol > UINT8_MAX )
    return BAD_STREAM(s, ERANGE, "ip_protocol=%d out of range\n", protocol);
  s->ip4_protocol = protocol;
  s->fields |= SC_SF_IP4_PROTOCOL;
  sc_stream_eth_type(s, ETHERTYPE_IP);
  return 0;
}


int __sc_stream_extract_mcast_group(struct sc_stream* stream,
                                    uint32_t* mcast_group)
{
  uint32_t addr = ntohl(stream->ip4_dest_addr);
  if( ! (stream->fields & SC_SF_IP4_DEST_ADDR) ||
      ! (stream->fields & SC_SF_IP4_PROTOCOL)  ||
      stream->ip4_protocol != IPPROTO_UDP      ||
      (addr & 0xF0000000) != 0xE0000000 )
    return 1;

  *mcast_group = addr;
  return 0;
}


int __sc_stream_extract_vlan_id(struct sc_stream* stream,
                                uint16_t* vlan_id)
{
  if( ! (stream->fields & SC_SF_ETH_VLAN_ID) )
    return 1;
  *vlan_id = stream->eth_vlan_id;
  return 0;
}


#define GOTO_ADD_FN_FAILED(strm_type)                                   \
  do { add_fn_stream_type = strm_type; goto add_fn_failed; } while( 0 )


int sc_stream_add(struct sc_stream* s, void* vi_or_set,
                  enum sc_capture_mode mode, int promiscuous,
                  enum sc_capture_point capture_point,
                  int (*add_fn)(void* vi_or_set, ef_filter_spec*))
{
  const char* add_fn_stream_type;
  int rc;
  ef_filter_spec spec;
  ef_filter_spec_init(&spec, EF_FILTER_FLAG_NONE);

  if( mode == SC_CAPTURE_MODE_SNIFF ) {
    if( s->fields & ~SC_SF_ALL )
      return sc_set_err(s->st_tg, EOPNOTSUPP, "%s: ERROR: unsupported stream "
                        "with capture_mode=sniff (fields=%x)\n", __func__,
                        s->fields);

    switch( capture_point ) {
    case SC_CAPTURE_POINT_EGRESS:
      TRY(ef_filter_spec_set_tx_port_sniff(&spec));
      break;
    case SC_CAPTURE_POINT_INGRESS:
    case SC_CAPTURE_POINT_UNSPECIFIED:
      /* If capture point is unspecified this is implicit ingress */
      TRY(ef_filter_spec_set_port_sniff(&spec, promiscuous));
      break;
    default:
      /* We should not have translated the attribute to anything other than
       * the above values.
       */
      SC_TEST( 0 );
    }

    if( (rc = add_fn(vi_or_set, &spec)) < 0 )
      GOTO_ADD_FN_FAILED("sniff");
  }
  else {
    if( capture_point != SC_CAPTURE_POINT_INGRESS &&
        capture_point != SC_CAPTURE_POINT_UNSPECIFIED )
      return sc_set_err(s->st_tg, EOPNOTSUPP, "%s: ERROR: capture_point=egress "
                        "not supported with capture_mode=steal\n", __func__);

    switch( s->fields ) {
    case SC_SF_ALL:
      TRY(ef_filter_spec_set_unicast_all(&spec));
      if( (rc = add_fn(vi_or_set, &spec)) < 0 )
        GOTO_ADD_FN_FAILED("unicast_all");
      ef_filter_spec_init(&spec, EF_FILTER_FLAG_NONE);
      TRY(ef_filter_spec_set_multicast_all(&spec));
      if( (rc = add_fn(vi_or_set, &spec)) < 0 )
        GOTO_ADD_FN_FAILED("multicast_all");
      break;
    case SC_SF_MISMATCH:
      TRY(ef_filter_spec_set_unicast_mismatch(&spec));
      if( (rc = add_fn(vi_or_set, &spec)) < 0 )
        GOTO_ADD_FN_FAILED("unicast_mismatch");
      ef_filter_spec_init(&spec, EF_FILTER_FLAG_NONE);
      TRY(ef_filter_spec_set_multicast_mismatch(&spec));
      if( (rc = add_fn(vi_or_set, &spec)) < 0 )
        GOTO_ADD_FN_FAILED("multicast_mismatch");
      break;
    case SC_SF_ETH_DHOST:
      TRY(ef_filter_spec_set_eth_local(&spec, EF_FILTER_VLAN_ID_ANY,
                                       s->eth_dhost));
      if( (rc = add_fn(vi_or_set, &spec)) < 0 )
        GOTO_ADD_FN_FAILED("eth_dhost");
      break;
    case SC_SF_ETH_DHOST | SC_SF_ETH_VLAN_ID:
      TRY(ef_filter_spec_set_eth_local(&spec, s->eth_vlan_id, s->eth_dhost));
      if( (rc = add_fn(vi_or_set, &spec)) < 0 )
        GOTO_ADD_FN_FAILED("eth_dhost_vlan");
      break;
    case SC_SF_ETH_TYPE | SC_SF_IP4_PROTOCOL | SC_SF_IP4_DEST_ADDR |
         SC_SF_IP4_DEST_PORT:
      TRY(ef_filter_spec_set_ip4_local(&spec, s->ip4_protocol,
                                       s->ip4_dest_addr, s->ip4_dest_port));
      if( (rc = add_fn(vi_or_set, &spec)) < 0 )
        GOTO_ADD_FN_FAILED("ip4_local");
      break;
    case SC_SF_ETH_TYPE | SC_SF_IP4_PROTOCOL | SC_SF_IP4_DEST_ADDR |
         SC_SF_IP4_DEST_PORT | SC_SF_IP4_SOURCE_ADDR | SC_SF_IP4_SOURCE_PORT:
      TRY(ef_filter_spec_set_ip4_full(&spec, s->ip4_protocol,
                                      s->ip4_dest_addr, s->ip4_dest_port,
                                      s->ip4_source_addr, s->ip4_source_port));
      if( (rc = add_fn(vi_or_set, &spec)) < 0 )
        GOTO_ADD_FN_FAILED("ip4_full");
      break;
    case SC_SF_ETH_TYPE | SC_SF_ETH_VLAN_ID | SC_SF_IP4_PROTOCOL |
         SC_SF_IP4_DEST_ADDR | SC_SF_IP4_DEST_PORT:
      TRY(ef_filter_spec_set_ip4_local(&spec, s->ip4_protocol,
                                       s->ip4_dest_addr, s->ip4_dest_port));
      TRY(ef_filter_spec_set_vlan(&spec, s->eth_vlan_id));
      rc = add_fn(vi_or_set, &spec);
      if( rc < 0 && s->vid_optional ) {
        sc_trace(s->st_tg, "%s: retrying ip4_local stream without vid\n",
                 __func__);
        ef_filter_spec_init(&spec, EF_FILTER_FLAG_NONE);
        TRY(ef_filter_spec_set_ip4_local(&spec, s->ip4_protocol,
                                         s->ip4_dest_addr, s->ip4_dest_port));
        rc = add_fn(vi_or_set, &spec);
      }
      if( rc < 0 )
        GOTO_ADD_FN_FAILED("ip4_local_vlan");
      break;
    case SC_SF_ETH_TYPE | SC_SF_ETH_VLAN_ID | SC_SF_IP4_PROTOCOL |
         SC_SF_IP4_DEST_ADDR | SC_SF_IP4_DEST_PORT | SC_SF_IP4_SOURCE_ADDR |
         SC_SF_IP4_SOURCE_PORT:
      TRY(ef_filter_spec_set_ip4_full(&spec, s->ip4_protocol,
                                      s->ip4_dest_addr, s->ip4_dest_port,
                                      s->ip4_source_addr, s->ip4_source_port));
      TRY(ef_filter_spec_set_vlan(&spec, s->eth_vlan_id));
      rc = add_fn(vi_or_set, &spec);
      if( rc < 0 && s->vid_optional) {
        sc_trace(s->st_tg, "%s: retrying ip4_full stream without vid\n",
                 __func__);
        ef_filter_spec_init(&spec, EF_FILTER_FLAG_NONE);
        TRY(ef_filter_spec_set_ip4_full(&spec, s->ip4_protocol,
                                        s->ip4_dest_addr, s->ip4_dest_port,
                                        s->ip4_source_addr, s->ip4_source_port));
        rc = add_fn(vi_or_set, &spec);
      }
      if( rc < 0 )
        GOTO_ADD_FN_FAILED("ip4_full_vlan");
      break;

    case SC_SF_ETH_TYPE:
      TRY(ef_filter_spec_set_eth_type(&spec, s->eth_type));
      if( (rc = add_fn(vi_or_set, &spec)) < 0 )
        GOTO_ADD_FN_FAILED("eth_type");
      break;
    case SC_SF_ETH_TYPE | SC_SF_ETH_VLAN_ID:
      TRY(ef_filter_spec_set_eth_type(&spec, s->eth_type));
      TRY(ef_filter_spec_set_vlan(&spec, s->eth_vlan_id));
      if( (rc = add_fn(vi_or_set, &spec)) < 0 )
        GOTO_ADD_FN_FAILED("eth_type_vlan");
      break;
    case SC_SF_ETH_TYPE | SC_SF_ETH_DHOST:
      TRY(ef_filter_spec_set_eth_type(&spec, s->eth_type));
      TRY(ef_filter_spec_set_eth_local(&spec, EF_FILTER_VLAN_ID_ANY,
                                       s->eth_dhost));
      if( (rc = add_fn(vi_or_set, &spec)) < 0 )
        GOTO_ADD_FN_FAILED("eth_type_dhost");
      break;

    case SC_SF_ETH_TYPE | SC_SF_IP4_PROTOCOL:
      TRY(ef_filter_spec_set_ip_proto(&spec, s->ip4_protocol));
      if( (rc = add_fn(vi_or_set, &spec)) < 0 )
        GOTO_ADD_FN_FAILED("ip4_protocol");
      break;
    case SC_SF_ETH_TYPE | SC_SF_IP4_PROTOCOL | SC_SF_ETH_VLAN_ID:
      TRY(ef_filter_spec_set_ip_proto(&spec, s->ip4_protocol));
      TRY(ef_filter_spec_set_vlan(&spec, s->eth_vlan_id));
      if( (rc = add_fn(vi_or_set, &spec)) < 0 )
        GOTO_ADD_FN_FAILED("ip4_protocol_vlan");
      break;
    case SC_SF_ETH_TYPE | SC_SF_IP4_PROTOCOL | SC_SF_ETH_DHOST:
      TRY(ef_filter_spec_set_ip_proto(&spec, s->ip4_protocol));
      TRY(ef_filter_spec_set_eth_local(&spec, EF_FILTER_VLAN_ID_ANY,
                                       s->eth_dhost));
      if( (rc = add_fn(vi_or_set, &spec)) < 0 )
        GOTO_ADD_FN_FAILED("eth_dhost_ip4_protocol");
      break;

    case SC_SF_ETH_VLAN_ID:
      TRY(ef_filter_spec_set_unicast_mismatch(&spec));
      TRY(ef_filter_spec_set_vlan(&spec, s->eth_vlan_id));
      if( (rc = add_fn(vi_or_set, &spec)) < 0 )
        GOTO_ADD_FN_FAILED("unicast_mismatch_vlan");
      ef_filter_spec_init(&spec, EF_FILTER_FLAG_NONE);
      TRY(ef_filter_spec_set_multicast_mismatch(&spec));
      TRY(ef_filter_spec_set_vlan(&spec, s->eth_vlan_id));
      if( (rc = add_fn(vi_or_set, &spec)) < 0 )
        GOTO_ADD_FN_FAILED("multicast_mismatch_vlan");
      break;

    default:
      return sc_set_err(s->st_tg, EINVAL, "%s: ERROR: unsupported combination "
                        "of fields (%x)\n", __func__, s->fields);
    }
  }

  return 0;


 add_fn_failed:
  return sc_set_err(s->st_tg, -rc, "%s: ERROR: unable to add stream type "
                    "'%s' (%s)\n", __func__, add_fn_stream_type, strerror(-rc));
}
