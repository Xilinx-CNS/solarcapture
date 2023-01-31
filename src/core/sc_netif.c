/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#include "internal.h"
#include <sc_internal/ef_vi.h>

#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <fcntl.h>


int sc_netif_is_cluster(const struct sc_netif *const netif)
{
  return netif->pd.pd_cluster_name != NULL;
}


int sc_netif_alloc(struct sc_netif** netif_out,
                   unsigned pd_flags,
                   struct sc_session* tg,
                   const char* if_or_cluster_name,
                   bool no_cluster,
                   bool report_errors)
{
  int rc, i;
  struct sc_netif* netif = calloc(1, sizeof(*netif));

  netif->no_cluster = no_cluster;
  if( (rc = ef_driver_open(&netif->dh)) < 0 ) {
    if( report_errors )
      sc_set_err(tg, -rc, "ERROR: ef_driver_open() failed (rc=%d %s)\n",
                 rc, strerror(-rc));
    goto fail1;
  }

  if( pd_flags & EF_PD_RX_PACKED_STREAM )
    netif->is_packed_stream = true;

  if( no_cluster ) {
    i = if_nametoindex(if_or_cluster_name);
    if( i == 0 ) {
      rc = -1;
      if( report_errors )
        sc_set_err(tg, errno, "ERROR: if_nametoindex(%s) failed (errno=%d)",
                   if_or_cluster_name, errno);
      goto fail2;
    }
    rc = ef_pd_alloc(&netif->pd, netif->dh, i, pd_flags);
    if( rc < 0 )
      goto fail2;
  }
  else {
    rc = ef_pd_alloc_by_name(&netif->pd, netif->dh, if_or_cluster_name,
                             pd_flags);
    if( rc < 0 )
      goto fail2;
  }

  netif->name = strdup(if_or_cluster_name);
  sc_interface_get(&netif->interface, tg, ef_pd_interface_name(&netif->pd));
  *netif_out = netif;
  return 0;

 fail2:
  ef_driver_close(netif->dh);
 fail1:
  free(netif);
  return rc;
}


inline static int sc_netif_get_with_properties(struct sc_netif** netif_out,
                                               const struct sc_attr* attr,
                                               struct sc_session* tg,
                                               const char* if_or_cluster_name,
                                               bool no_cluster,
                                               bool packed_stream)
{
  struct sc_netif* netif;
  int i, rc;

  for( i = 0; i < tg->tg_netifs_n; ++i )
    if( ! strcmp(tg->tg_netifs[i]->name, if_or_cluster_name) &&
        tg->tg_netifs[i]->no_cluster == no_cluster &&
        tg->tg_netifs[i]->is_packed_stream == packed_stream ) {
      *netif_out = tg->tg_netifs[i];
      return 0;
    }

  unsigned pd_flags = attr->pd_flags;
  if( packed_stream )
    pd_flags |= EF_PD_RX_PACKED_STREAM;

  if( (rc = sc_netif_alloc(&netif, pd_flags, tg, if_or_cluster_name,
                           no_cluster, true)) < 0 )
    return rc;

  TEST(tg->tg_netifs_n < SC_MAX_NETIFS);
  netif->netif_id = tg->tg_netifs_n++;
  SC_REALLOC(&tg->tg_netifs, tg->tg_netifs_n);
  tg->tg_netifs[netif->netif_id] = netif;
  *netif_out = netif;
  return 0;
}


int sc_netif_get(struct sc_netif** netif_out, const struct sc_attr* attr,
                 struct sc_session* tg, const char* if_or_cluster_name)
{
  int rc;
  bool no_cluster = (attr->cluster != NULL && !strcmp(attr->cluster, "none"));
  /* cluster="none" is a special value indicating that we should allocate
   * this netif a unique PD rather than potentially using solar_clusterd.
   * When looking for an existing suitable netif we only consider those whose
   * no_cluster flag matches the requested.
   */

  enum sc_vi_mode vi_mode;
  rc = sc_get_vi_mode(tg, attr, &vi_mode);
  if( rc < 0 )
    return -1;

  int rx_batch_nanos = attr->rx_batch_nanos;
  if( rx_batch_nanos < 0 )
    rx_batch_nanos = attr->batch_timeout_nanos;
  bool want_packed_stream;

  switch( vi_mode ) {
  case SC_VI_MODE_AUTO:
    want_packed_stream = (rx_batch_nanos != 0);
    break;
  case SC_VI_MODE_PACKED_STREAM:
    want_packed_stream = true;
    break;
  default:
    want_packed_stream = false;
    break;
  }

  rc = sc_netif_get_with_properties(netif_out, attr, tg, if_or_cluster_name,
                                    no_cluster, want_packed_stream);
  if( rc < 0 && want_packed_stream && vi_mode == SC_VI_MODE_AUTO )
    rc = sc_netif_get_with_properties(netif_out, attr, tg, if_or_cluster_name,
                                      no_cluster, false);

  if( rc < 0 ) {
    if( rc == -ELIBACC || rc == -EBADRQC)
      sc_set_err(tg, -rc, "ERROR: PD alloc (name=%s flags=%"PRId64" cluster=%s) "
                 "failed (rc=%d).  The installed version of Onload may not be "
                 "compatible with this build of SolarCapture.  "
                 "See the SolarCapture user guide for compatible versions.",
                 if_or_cluster_name, attr->pd_flags, attr->cluster, rc);
    else if( rc == -ENODEV )
      sc_set_err(tg, -rc, "ERROR: Failed to allocate PD for interface '%s'\n",
                 if_or_cluster_name);
    else
      sc_set_err(tg, -rc, "ERROR: PD alloc(name=%s, flags=%"PRId64" cluster=%s) "
                 "failed (rc=%d)\n", if_or_cluster_name, attr->pd_flags,
                 attr->cluster, rc);
    return -1;
  }

  return 0;

}


int sc_netif_free(struct sc_session* tg, struct sc_netif* netif)
{
  int rc;

  /* TODO: What other sc_netif resources should we free here? */
  if( (rc = ef_pd_free(&netif->pd, netif->dh)) != 0 )
    sc_trace(tg, "%s: ef_pd_free() failed: %d\n", __func__, rc);
  if( (rc = ef_driver_close(netif->dh)) != 0 )
    sc_trace(tg, "%s: ef_driver_close() failed: %d\n", __func__, rc);
  return 0;
}


#if 0
/*
 * Idea for future: Provide interface to query useful info about an
 * interface.  Not used yet, and commented out due to bit-rot.
 */
struct sc_netif_info {
  uint8_t         mac[6];
  struct in_addr  ip4_addr;
  int             mtu;
};


int sc_netif_get_info(struct sc_netif* netif, struct sc_netif_info** ni_out)
{
  struct sc_session* tg = netif->session;
  struct ifreq ifr;
  int fd, rc;

  struct sc_netif_info* info = calloc(1, sizeof(*info));
  TEST(info != NULL);

  TG_TRY_MSG(tg, fd = socket(PF_INET, SOCK_DGRAM, 0),
             "%s: ERROR: Failed to create socket\n", __func__);
  TEST(strlen(netif->interface_name) < IFNAMSIZ);
  strcpy(ifr.ifr_name, netif->interface_name);
  if( ioctl(fd, SIOCGIFHWADDR, &ifr) < 0 ) {
    rc = sc_set_err(tg, errno, "%s: ERROR: could not get mac for %s\n",
                    __func__, netif->interface_name);
    goto error_out;
  }
  memcpy(info->mac, ifr.ifr_addr.sa_data, 6);
  if( ioctl(fd, SIOCGIFADDR, &ifr) < 0 ) {
    rc = sc_set_err(tg, errno, "%s: ERROR: could not get IP for %s\n",
                    __func__, netif->interface_name);
    goto error_out;
  }
  info->ip4_addr = ((struct sockaddr_in*) &ifr.ifr_addr)->sin_addr;
  if( ioctl(fd, SIOCGIFMTU, &ifr) < 0 ) {
    rc = sc_set_err(tg, errno, "%s: ERROR: could not get MTU for %s\n",
                    __func__, netif->interface_name);
    goto error_out;
  }
  info->mtu = ifr.ifr_mtu;
  close(fd);
  return 0;

 error_out:
  free(info);
  close(fd);
  return rc;
}

#endif


#define MEDFORD_NIC_VARIANT 66
