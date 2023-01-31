/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#ifndef __SC_SHM_RINGBUF_H__
#define __SC_SHM_RINGBUF_H__


/* Doxbox: SF-113230-SW
 */

/* Types for shared memory channel.
 */
enum sc_shm_message_type {
  SSM_TYPE_STREAM_PACKET,
  SSM_TYPE_FREE_PACKET,
  SSM_TYPE_DROP_NOTIFICATION
};


enum sc_shm_packet_type {
  SSM_PKT_TYPE_NORMAL,
  SSM_PKT_TYPE_PACKED_STREAM
};

union sc_shm_message_data {
  struct {
    uintptr_t usm_buffer_offset;
    uint64_t  usm_buffer_len;
    uintptr_t usm_packet_id;
    uint64_t  usm_ts_sec;
    uint32_t  usm_ts_nsec;
    uint64_t  usm_drop_count;
    enum sc_shm_packet_type usm_packet_type;
  } usm_stream_packet;

  struct {
    uintptr_t usm_packet_id;
  } usm_free_packet;

  struct {
    uint64_t usm_drop_count;
  } usm_drop_notification;
};


struct sc_shm_message {
  enum  sc_shm_message_type ssm_message_type;
  union sc_shm_message_data ssm_message;
};


struct sc_shm_endpoint;


struct sc_shm_endpoints;


/* Types for socket channel.
 */
enum sc_shm_io_message_type {
  SSIO_TYPE_CONN_REQ,
  SSIO_TYPE_CONN_RESP,
  SSIO_TYPE_DISCONN_REQ,
  SSIO_TYPE_DISCONN_RESP,
  SSIO_TYPE_WAKE
};


#define SSIO_MAX_STR_LEN 256


struct sc_shm_io_message_data_req {
  int  ssio_request_reliable;
  int  ssio_count_drops;
};


struct sc_shm_io_message_data_resp {
  char ssio_buffer_shm_path[SSIO_MAX_STR_LEN];
  char ssio_ringbuf_shm_path[SSIO_MAX_STR_LEN];
  int  ssio_endpoint_id;
};


union sc_shm_io_message_data {
  struct sc_shm_io_message_data_req ssio_conn_req;
  struct sc_shm_io_message_data_resp ssio_conn_resp;
};


struct sc_shm_io_message {
  enum sc_shm_io_message_type  ssio_type;
  union sc_shm_io_message_data ssio_data;
};


/* Create a set of endpoints mapped to files based on the provided template.
 */
struct sc_shm_endpoints* sc_shm_endpoints_create(const char* fname_template,
                                                 int n_channels);


struct sc_shm_endpoint* sc_shm_endpoint_get(struct sc_shm_endpoints* se, int i);


void sc_shm_endpoint_reset(struct sc_shm_endpoints* se, int i);


int sc_shm_endpoint_activate(struct sc_shm_endpoints* se, int i);


uintptr_t
sc_pkt_shm_buffer_offset(struct sc_node* node, struct sc_packet* packet);


/* Retrieve location in filesystem for specified endpoint.
 */
const char* sc_shm_endpoint_get_path(struct sc_shm_endpoints* se, int i);


/* For the consumer to attach to an endpoint via the specified path.
 */
struct sc_shm_endpoint* sc_shm_endpoint_attach(const char* path);


/* For the consumer to disconnect from an endpoint.
 */
int sc_shm_endpoint_detach(struct sc_shm_endpoint* ep);


/* Set of functions for posting messages to and getting messages from shared
 * memory ringbuffers.
 */

int sc_shm_endpoint_msg_send(struct sc_shm_endpoint* ep,
                                    struct sc_shm_message*  m);


int sc_shm_endpoint_msg_get(struct sc_shm_endpoint* ep,
                                   struct sc_shm_message* m);

int sc_shm_endpoint_get_space(struct sc_shm_endpoint* ep);


void sc_shm_endpoint_notify_sleep(struct sc_shm_endpoint* ep);


uint64_t sc_shm_endpoint_get_remote_sleep_seq(struct sc_shm_endpoint* ep);


uint64_t sc_shm_endpoint_get_n_sent(struct sc_shm_endpoint* ep);


uint64_t sc_shm_endpoint_get_n_received(struct sc_shm_endpoint* ep);


#endif  /* __SC_SHM_RINGBUF_H__ */
