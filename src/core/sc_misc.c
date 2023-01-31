/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#include "internal.h"

#include <limits.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>


int sc_affinity_set(int affinity)
{
  cpu_set_t cpus;
  CPU_ZERO(&cpus);
  CPU_SET(affinity, &cpus);
  return sched_setaffinity(0, sizeof(cpus), &cpus);
}


int sc_affinity_save_and_set(struct sc_session* scs, int affinity)
{
  int rc = 0;
  struct sc_saved_affinity* sv_affinity =
    malloc(sizeof(struct sc_saved_affinity));
  SC_TEST(sv_affinity);
  TRY(sched_getaffinity(0, sizeof(sv_affinity->ssa_affinity),
                        &sv_affinity->ssa_affinity));
  sc_dlist_push_head(&scs->tg_affinity_stack, &sv_affinity->ssa_session_link);

  if( affinity >= 0 )
    if( (rc = sc_affinity_set(affinity)) < 0 )
      return sc_set_err(scs, errno, "ERROR: %s: Failed to set affinity=%d\n",
                        __func__, affinity);

  return rc;
}


int sc_affinity_restore(struct sc_session* scs)
{
  if( sc_dlist_is_empty(&scs->tg_affinity_stack) )
    return -1;

  struct sc_saved_affinity* sv_affinity =
    SC_CONTAINER(struct sc_saved_affinity, ssa_session_link,
                 sc_dlist_pop_head(&scs->tg_affinity_stack));

  TRY(sched_setaffinity(0, sizeof(sv_affinity->ssa_affinity),
                        &sv_affinity->ssa_affinity));

  free(sv_affinity);
  return 0;
}


int sc_thread_affinity_save_and_set(struct sc_thread* t)
{
  return sc_affinity_save_and_set(t->session, t->affinity);
}


int sc_thread_affinity_restore(struct sc_thread* t)
{
  return sc_affinity_restore(t->session);
}


int sc_join_mcast_group(struct sc_session* tg,
                        const char* intf, const char* group)
{
  sc_trace(tg, "%s: intf=%s group=%s\n", __func__, intf, group);

  static int sock = -1;
  if( sock < 0 )
    TG_TRY_MSG(tg, sock = socket(AF_INET, SOCK_DGRAM, 0),
               "%s: Failed to create socket\n", __func__);

  struct ip_mreqn mreq = {
    .imr_address.s_addr = htonl(INADDR_ANY),
    .imr_ifindex = if_nametoindex(intf),
    .imr_multiaddr.s_addr = inet_addr(group),
  };

  if( mreq.imr_ifindex == 0 )
    return sc_set_err(tg, EINVAL,
                      "ERROR: %s: if_nametoindex(%s) failed\n", __func__, intf);

  int rc = setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
  if( rc < 0 && errno != EADDRINUSE ) {
    /* EADDRINUSE just means we've joined the same group twice on the same
     * interface.
     */
    char* error = (errno == ENOBUFS ?
                   "hit kernel igmp_max_memberships limit" : strerror(errno));
    return sc_set_err(tg, errno, "ERROR: %s: Failed to join multicast "
                      "group '%s' on %s (%s)\n", __func__, group, intf, error);
  }
  return 0;
}


int sc_get_capture_mode(struct sc_session *tg, const struct sc_attr *attr,
                        enum sc_capture_mode *mode)
{
  if( attr->capture_mode != NULL ) {
    if ( !strcmp(attr->capture_mode, "sniff") )
      *mode = SC_CAPTURE_MODE_SNIFF;
    else if ( !strcmp(attr->capture_mode, "steal") )
      *mode = SC_CAPTURE_MODE_STEAL;
    else {
      return sc_set_err(tg, EINVAL,
                        "%s: ERROR: Invalid capture_mode %s\n",
                        __func__, attr->capture_mode);
    }
  }
  else {
    *mode = SC_CAPTURE_MODE_UNSPECIFIED;
  }

  return 0;
}


int sc_get_vi_mode(struct sc_session *tg, const struct sc_attr *attr,
                   enum sc_vi_mode *mode)
{
  if( attr->vi_mode != NULL ) {
    if ( !strcmp(attr->vi_mode, "auto") )
      *mode = SC_VI_MODE_AUTO;
    else if ( !strcmp(attr->vi_mode, "packed_stream") )
      *mode = SC_VI_MODE_PACKED_STREAM;
    else if ( !strcmp(attr->vi_mode, "normal") )
      *mode = SC_VI_MODE_NORMAL;
    else {
      return sc_set_err(tg, EINVAL,
                        "%s: ERROR: Invalid vi_mode %s\n",
                        __func__, attr->vi_mode);
    }
  }
  else {
    *mode = SC_VI_MODE_AUTO;
  }

  return 0;
}


int sc_get_capture_point(struct sc_session* tg, const char* attr,
                         enum sc_capture_point* capture_point)
{
  if( attr != NULL ) {
    if( !strcmp(attr, "ingress") )
      *capture_point = SC_CAPTURE_POINT_INGRESS;
    else if( !strcmp(attr, "egress") )
      *capture_point = SC_CAPTURE_POINT_EGRESS;
    else
      return sc_set_err(tg, EINVAL,
                        "%s: ERROR: Invalid capture_point %s\n",
                        __func__, attr);
  }
  else {
    *capture_point = SC_CAPTURE_POINT_UNSPECIFIED;
  }

  return 0;
}


int sc_get_interface_strip_fcs(struct sc_session* tg, const char* interface,
                               int* strip_fcs)
{
  int rc;
  int forward_fcs;
  FILE* file;
  char* filename;

  SC_TEST(asprintf(&filename,
                   "/sys/class/net/%s/device/forward_fcs", interface) > 0);
  file = fopen(filename, "r");

  if( file ) {
    rc = fscanf(file, "%d", &forward_fcs);
    SC_TEST(rc == 1);
    *strip_fcs = forward_fcs ? 0 : 1;
    rc = 0;
  }
  else {
    /* Older drivers that do not support the forward_fcs interface will not
     * create the file, so treat ENOENT as meaning that the fcs will be
     * stripped.
     */
    if( errno == ENOENT ) {
      *strip_fcs = 1;
      rc = 0;
    }
    else {
      rc = sc_set_err(tg, errno, "%s: ERROR: Failed to read "
                      "/sys/class/net/%s/device/forward_fcs\n",
                      __func__, interface);
    }
  }

  free(filename);
  if( file )
    fclose(file);

  return rc;
}


void sc_realloc(void* pp_area_in, size_t new_size)
{
  void** pp_area = pp_area_in;
  *pp_area = realloc(*pp_area, new_size);
  SC_TEST(*pp_area != NULL);
}


bool sc_match_prefix(const char* str, const char* prefix,
                     const char** suffix_out_opt)
{
  size_t prefix_len = strlen(prefix);
  if( strncmp(str, prefix, prefix_len) == 0 ) {
    if( suffix_out_opt != NULL )
      *suffix_out_opt = str + prefix_len;
    return true;
  }
  return false;
}


char* sc_strtok_r(char* str, char delim, char** saveptr)
{
  if( str == NULL && (str = *saveptr) == NULL )
    return NULL;
  /* Skip empty tokens. */
  while( *str && *str == delim )
    ++str;
  if( ! *str ) {
    *saveptr = NULL;
    return NULL;
  }
  char* tok = str;
  char* to = str;
  for( ; *str && *str != delim; ++str ) {
    if( str[0] == '\\' && str[1] )
      ++str;
    *to++ = *str;
  }
  if( *str )
    *saveptr = str + 1;
  else
    *saveptr = NULL;
  *to = '\0';
  return tok;
}


int sc_strtoi_range(int* res_out, const char* str, int base, int min, int max)
{
  char* end;
  errno = 0;
  long res = strtol(str, &end, base);
  if( errno )
    return -errno;
  if( end == str || *end != '\0' )
    return -EINVAL;
  if( res < (long) min || res > (long) max )
    return -ERANGE;
  *res_out = res;
  return 0;
}


bool sc_fd_is_readable(int fd)
{
  struct pollfd pfd;
  pfd.fd = fd;
  pfd.events = POLLIN;
  return poll(&pfd, 1, 0) == 1 && (pfd.revents & POLLIN);
}


int sc_parse_size_string(int64_t* parsed_val, const char* str)
{
  struct suffix {
    const char* str;
    int   scale;
  };
  struct suffix suffix_arr[] = {
    {"B", 1},
    {"kB", 1000},
    {"MB", 1000 * 1000},
    {"GB", 1000 * 1000 * 1000},
    {"KiB", 1024},
    {"MiB", 1024 * 1024},
    {"GiB", 1024 * 1024 * 1024},
  };

  char* end;
  *parsed_val = strtoull(str, &end, 0);
  if( end == str )
    return -ENOMSG;
  if( *end == '\0' )
    return 0;

  int i;
  for( i = 0; i < sizeof(suffix_arr) / sizeof(suffix_arr[0]); ++i )
    if( ! strcmp(end, suffix_arr[i].str) ) {
      *parsed_val *= suffix_arr[i].scale;
      return 0;
    }
  return -ENOMSG;
}
