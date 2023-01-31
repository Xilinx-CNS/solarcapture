/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \node{sc_tuntap}
 *
 * \brief Pass packets between SolarCapture and the kernel stack via a
 *        tun/tap interface.
 *
 * \nodedetails
 * Packets sent to this node are forwarded to the kernel stack via the
 * tun/tap interface.  Packets sent to the tun/tap interface by the kernel
 * stack are delivered through the node's output link.
 *
 * You can also create an sc_tuntap node indirectly by creating an
 * \noderef{sc_vi_node} with an interface name such as "tap:tap0".
 *
 * \nodeargs
 * Argument    | Optional? | Default | Type           | Description
 * ----------- | --------- | ------- | -------------- | -------------------------------------------------------------------------------
 * interface   | No        |         | ::SC_PARAM_STR | Name for the tun/tap interface.
 * up          | Yes       | 1       | ::SC_PARAM_INT | Whether or not to bring the interface up.
 *
 * \cond NODOC
 */
#include <sc_internal.h>
#include <sc_internal/builtin_nodes.h>

#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>


struct tuntap {
  char*            interface;
  struct sc_attr*  attr;
  int              fd;
  struct sc_node*  reader;
  struct sc_node*  writer;
};


static int sc_tuntap_add_link(struct sc_node* from_node, const char* link_name,
                              struct sc_node* to_node, const char* to_name_opt)
{
  struct tuntap* st = from_node->nd_private;
  if( st->reader != NULL )
    return sc_node_set_error(from_node, EINVAL, "%s: ERROR: sc_vi_node can "
                             "only support a single output link\n", __func__);

  int fd = (st->writer) ? dup(st->fd) : st->fd;
  struct sc_arg r_args[] = {
    SC_ARG_INT("fd", fd),
    SC_ARG_INT("signal_eof", 1),
    SC_ARG_INT("close_on_eof", 1),
  };
  int rc = sc_node_alloc_named(&(st->reader), st->attr,
                               sc_node_get_thread(from_node),
                               "sc_fd_reader", NULL,
                               r_args, sizeof(r_args) / sizeof(r_args[0]));
  if( rc < 0 ) {
    if( fd != st->fd )
      close(fd);
    return sc_node_fwd_error(from_node, rc);
  }
  sc_node_add_info_str(st->reader, "sc_tuntap_interface", st->interface);
  return sc_node_add_link(st->reader, "", to_node, to_name_opt);
}


static struct sc_node* sc_tuntap_select_subnode(struct sc_node* node,
                                                const char* name_opt,
                                                char** new_name_out)
{
  struct tuntap* st = node->nd_private;
  if( st->writer == NULL ) {
    int fd = (st->reader) ? dup(st->fd) : st->fd;
    struct sc_arg w_args[] = {
      SC_ARG_INT("fd", fd),
      SC_ARG_INT("close_on_eos", 1),
    };
    int rc = sc_node_alloc_named(&(st->writer), st->attr,
                                 sc_node_get_thread(node), "sc_fd_writer", NULL,
                                 w_args, sizeof(w_args) / sizeof(w_args[0]));
    if( rc < 0 ) {
      if( fd != st->fd )
        close(fd);
      sc_node_fwd_error(node, rc);
      return NULL;
    }
    sc_node_add_info_str(st->writer, "sc_tuntap_interface", st->interface);
  }
  return st->writer;
}


static int sc_tuntap_init2(struct sc_node* node, const struct sc_attr* attr,
                           const struct sc_node_factory* factory,
                           const char* interface, bool up)
{
  struct sc_thread* thread = sc_node_get_thread(node);

  const char* tun_dev = "/dev/net/tun";
  int fd = open(tun_dev, O_RDWR);
  if( fd < 0 )
    return sc_node_set_error(node, errno, "%s: ERROR: could not open(%s)\n",
                             __func__, tun_dev);

  struct ifreq ifr;
  memset(&ifr, 0, sizeof(ifr));
  sc_fill_char_buf(ifr.ifr_name, IFNAMSIZ, interface);
  ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
  int rc = ioctl(fd, TUNSETIFF, &ifr);
  if( rc < 0 ) {
    close(fd);
    return sc_node_set_error(node, errno, "%s: ERROR: unable to open "
                             "interface '%s'\n", __func__, interface);
  }

  if( up ) {
    int sock;
    SC_TRY( sock = socket(AF_INET, SOCK_DGRAM, 0) );
    SC_TRY( ioctl(sock, SIOCGIFFLAGS, &ifr) );
    ifr.ifr_flags |= IFF_UP;
    SC_TRY( ioctl(sock, SIOCSIFFLAGS, &ifr) );
    SC_TRY( close(sock) );
  }

  struct tuntap* st;
  st = sc_thread_calloc(thread, sizeof(*st));
  node->nd_private = st;
  SC_TEST( st->interface = strdup(ifr.ifr_name) );
  SC_TEST( st->attr = sc_attr_dup(attr) );
  st->fd = fd;
  /* st->reader = NULL; */
  /* st->writer = NULL; */
  return 0;
}


static int sc_tuntap_init(struct sc_node* node, const struct sc_attr* attr,
                          const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL ) {
    sc_node_type_alloc(&nt, NULL, factory);
    nt->nt_add_link_fn = sc_tuntap_add_link;
    nt->nt_select_subnode_fn = sc_tuntap_select_subnode;
  }
  node->nd_type = nt;

  const char* interface;
  if( sc_node_init_get_arg_str(&interface, node, "interface", NULL) < 0 )
    return -1;
  if( interface == NULL )
    return sc_node_set_error(node, EINVAL, "sc_tuntap: ERROR: required arg "
                             "'interface' missing\n");

  int up;
  if( sc_node_init_get_arg_int(&up, node, "up", 1) < 0 )
    return -1;

  return sc_tuntap_init2(node, attr, factory, interface, up);
}


const struct sc_node_factory sc_tuntap_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_tuntap",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_tuntap_init,
};

/** \endcond NODOC */
