/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \node{sc_shm_export}
 *
 * \brief Export packets or messages to a shared memory channel.
 *
 * \nodedetails
 * This node is used in conjunction with \noderef{sc_shm_import} to form a
 * unidirectional shared memory channel between two SolarCapture sessions.
 * Packets delivered to sc_shm_export are forwarded over the channel to the
 * connected \noderef{sc_shm_import} instance.
 *
 * By default sc_shm_export creates a reliable channel.  If packets arrive
 * at this node before a consumer is connected, then they are buffered.
 *
 * See also \noderef{sc_shm_broadcast}, which supports multiple consumers.
 *
 * \nodeargs
 * Argument              | Optional? | Default | Type           | Description
 * --------------------- | --------- | ------- | -------------- | ----------------------------------------------------------
 * path                  | No        |         | ::SC_PARAM_STR | The path prefix that should be used for creating the \noderef{sc_shm_export} node listening socket and shared memory files
 * max_in_flight         | Yes       | 100%    | ::SC_PARAM_INT | Maximum amount of buffering that can be in flight at a time. Specified as a percentage of the incoming pool ('%' suffix), or in bytes ('B', 'KiB', 'MiB' or 'GiB' suffix).
 * \internal
 * fd                    | Yes       | (null)  | ::SC_PARAM_INT | Rather than creating a listening socket, instead use this already-connected FD
 * connect_sock          | Yes       |         | ::SC_PARAM_STR | Rather than creating a listening socket, instead connect to an already created socket
 * \endinternal
 *
 * \internal
 * NOTE: This mode has three modes of operation:
 *
 * 1. If the 'fd' input is specified, it should be a connected unix domain socket
 *    whose other side is an sc_shm_import node. This node will handshake with the
 *    import node over the socket. The 'path' arguments specifies the location in
 *    which to create the SHM files
 *
 * 2. If the 'fd' input and connect_sock is not specified, the node will open a listening socket
 *    and wait for a connection. The socket path is based on the 'path' input
 *    with a "_sock" suffix. The node does not not support multiple connected
 *    clients - while a client is connected, any further client connections will
 *    be closed immediately.
 *
 * 3. If connect_sock is specified, it should connect to a unix domain socket
 *    located at connect_sock whose other side is an \noderef{sc_shm_import} node. This
 *    node will handshake with the import node over the socket. The 'path'
 *    arguments specifies the location in which to create the SHM files.
 *
 * In both modes, the 'path' argument specifies the location in which to create
 * the SHM data and control buffers.
 * \endinternal
 *
 * \namedinputlinks
 * Packets arriving on an input link named "foo" are forwarded to an output
 * link named "foo" on the other side of the shared memory channel.  Note
 * that these named channels do not support high performance.
 *
 * \cond NODOC
 */

#include <sc_internal.h>
#include <sc_internal/builtin_nodes.h>

#include <errno.h>


static int sc_shm_export_init(struct sc_node* node, const struct sc_attr* attr,
                              const struct sc_node_factory* factory)
{
  static struct sc_node_type* nt;
  if( nt == NULL )
    sc_node_type_alloc(&nt, NULL, factory);
  node->nd_type = nt;

  int fd, exit_on_disconnect;
  const char* path;
  const char* connect_sock;
  const char* max_in_flight;

  if( sc_node_init_get_arg_str(&max_in_flight, node,
                               "max_in_flight", "100%")                   < 0 ||
      sc_node_init_get_arg_int(&fd, node, "fd", -1)                       < 0 ||
      sc_node_init_get_arg_int(&exit_on_disconnect, node,
                               "exit_on_disconnect", 0)                   < 0 ||
      sc_node_init_get_arg_str(&path, node, "path", NULL)                 < 0 ||
      sc_node_init_get_arg_str(&connect_sock, node, "connect_sock", NULL) < 0  )
    return -1;

  if( path == NULL )
    return sc_node_set_error(node, EINVAL, "sc_shm_export: ERROR: required arg "
                             "'path' missing\n");
  if( fd >= 0 && connect_sock != NULL )
    return sc_node_set_error(node, EINVAL, "sc_shm_export: ERROR: both fd and "
                             "connect_sock provided\n");

  struct sc_arg broadcast_args[] = {
    SC_ARG_STR("max_in_flight", max_in_flight),
    SC_ARG_INT("fd", fd),
    SC_ARG_INT("exit_on_disconnect", exit_on_disconnect),
    SC_ARG_STR("path", path),
    SC_ARG_STR("connect_sock", connect_sock),
    SC_ARG_INT("listen", fd < 0 && connect_sock == NULL),
    SC_ARG_INT("min_connected_reliable_channels", 1),
    SC_ARG_INT("reliable_mode", 1),
    SC_ARG_INT("max_channels", 1),
  };

  return sc_node_init_delegate(node, attr, &sc_shm_broadcast_sc_node_factory,
                             broadcast_args,
                             sizeof(broadcast_args)/sizeof(broadcast_args[0]));
}


const struct sc_node_factory sc_shm_export_sc_node_factory = {
  .nf_node_api_ver   = SC_API_VER,
  .nf_name           = "sc_shm_export",
  .nf_source_file    = __FILE__,
  .nf_init_fn        = sc_shm_export_init,
};

/** \endcond NODOC */
