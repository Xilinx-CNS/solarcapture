/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/**
 * \addtogroup scapi SolarCapture API
 * @{
 * \file
 * \brief sc_io: A special header for use in sc_packets to encode messages.
 */
#ifndef __SC_IO_H__
#define __SC_IO_H__
#include <stdint.h>

/* Packets on links (in or out) with this prefix contain only data
 * without a preceding sc_io_msg_hdr. Only supported when the
 * sc_io_demux node has a single connection. Such links do not receive
 * connection open/close notifications and cannot requiest close */
#define SC_IO_LINK_DATA_PREFIX "data:"

/**
 * Prefixes the input link name with SC_IO_LINK_DATA_PREFIX, indicating
 * indicates to sc_io_demux that packets on this link have no sc_io_msg_hdr.
 * Such links do not receive NEW_CONN/CLOSE notifications and cannot request
 * connection close.
 *
 * The caller should free the returned pointer once done with it.
 */
static inline char* sc_io_link_add_data_prefix(const char* link_name)
{
  int len = strlen(SC_IO_LINK_DATA_PREFIX) + strlen(link_name) + 1;
  char* new_name = calloc(len, sizeof(char));
  strcat(new_name, SC_IO_LINK_DATA_PREFIX);
  strcat(new_name, link_name);
  return new_name;
}


#define LINKMAX 16
/**
 * Types of messages that can be sent. Note not all messages can be sent to all
 * nodes
 */
enum sc_io_msg_type {
  SC_IO_MSG_NEW_CONN, /**< Create a new connection to send message over.
                        This only ever emitted from a node and should not be
                        passed into the node */
  SC_IO_MSG_CLOSE, /**< Close a current connection, this is both emitted and
                     consumed by the node */
  SC_IO_MSG_DATA, /**< A packet containing message data sent/received over a
                    connection */
};


struct sc_io_msg_hdr {
  int connection_id;             /**< A connection id for the connection to act upon */
  enum sc_io_msg_type msg_type; /**< The type of message to send to this connection */
};

#pragma pack(1)
struct socket_msg {
  uint32_t msg_length;
  char     link_name[LINKMAX];
  char     msg[];
};
#pragma pack()



#endif  /* __SC_IO_H__ */
/**
 * @}
 */
