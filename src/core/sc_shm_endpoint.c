/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#include <sys/file.h>
#include <asm/mman.h>
#include <sys/mman.h>
#include <string.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sc_internal.h>
#include "internal.h"


#define RINGBUF_SIZE 64


enum sc_shm_entry_state {
  SSS_FREE,
  SSS_USED
};


struct sc_shm_ringbuf_entry {
  enum  sc_shm_entry_state  sre_state;
  uint8_t filler[SC_CACHE_LINE_SIZE - sizeof(enum sc_shm_entry_state)];
  struct sc_shm_message     sre_message;
}__attribute__ ((aligned (SC_CACHE_LINE_SIZE)));


struct sc_shm_ringbuf {
  /* sr_head, n_consumed and n_sleep are written by the consumer and read by
   * the producer.
   */
  unsigned  sr_head;
  uint64_t  sleep_seq;
  uint8_t filler1[SC_CACHE_LINE_SIZE - (sizeof(unsigned) + sizeof(uint64_t))];
  /* sr_tail is written by the producer and read by the consumer.
   */
  unsigned  sr_tail;
  uint8_t filler2[SC_CACHE_LINE_SIZE - sizeof(unsigned)];
  struct sc_shm_ringbuf_entry sr_entries[RINGBUF_SIZE];
} __attribute__ ((aligned (SC_CACHE_LINE_SIZE)));


struct sc_shm_endpoint_map {
  struct sc_shm_ringbuf sse_ringbuf_from_create_side;
  struct sc_shm_ringbuf sse_ringbuf_to_create_side;
};


struct sc_shm_endpoint {
  /* Whether currently connected */
  bool      sse_active;
  int       sse_fd;
  /* Size of mapping. This is page aligned so may be different from
   * sizeof(sc_shm_endpoint_map)
   */
  uint64_t  sse_size;
  uint64_t  sse_n_sent;
  uint64_t  sse_n_received;
  /* True at the creating end, false at the connecting end. */
  bool      sse_create_side;
  struct sc_shm_endpoint_map* sse_ep_map;
  char*                   sse_ep_path;
};


struct sc_shm_endpoints {
  int                      se_n_endpoints;
  struct sc_shm_endpoint** se_endpoints;
};


struct sc_shm_endpoint* sc_shm_endpoint_attach(const char* path)
{
  SC_TEST(path != NULL);
  struct stat sb;

  struct sc_shm_endpoint* ep = calloc(1, sizeof(struct sc_shm_endpoint));
  if( ep == NULL )
    goto out1;
  ep->sse_fd = open(path, O_RDWR);
  if( ep->sse_fd < 0)
    goto out2;

  fstat(ep->sse_fd, &sb);
  if( sb.st_size < sizeof(struct sc_shm_endpoint_map) ) {
    goto out3;
  }
  ep->sse_size = sb.st_size;
  ep->sse_ep_map = mmap(NULL, ep->sse_size, PROT_READ | PROT_WRITE,
                        MAP_SHARED, ep->sse_fd, 0);

  if( ep->sse_ep_map == MAP_FAILED ) {
    goto out3;
  }
  ep->sse_active = true;
  ep->sse_create_side = false;
  return ep;
 out3:
  close(ep->sse_fd);
 out2:
  free(ep);
 out1:
  return NULL;
}


int sc_shm_endpoint_detach(struct sc_shm_endpoint* ep)
{
  SC_TEST(ep != NULL );
  munmap(ep->sse_ep_map, ep->sse_size);
  close(ep->sse_fd);
  free(ep);
  return 0;
}


static void sc_shm_ringbuf_reset(struct sc_shm_ringbuf* rb)
{
  int i;
  rb->sr_head = 0;
  rb->sr_tail = 0;
  rb->sleep_seq = 0;
  for( i = 0; i < RINGBUF_SIZE ; i++ )
    rb->sr_entries[i].sre_state = SSS_FREE;
}


static int sc_shm_ringbuf_init(struct sc_shm_ringbuf* rb)
{
  sc_shm_ringbuf_reset(rb);
  return 0;
}


void sc_shm_endpoint_reset(struct sc_shm_endpoints* se, int i)
{
  SC_TEST(i < se->se_n_endpoints);
  struct sc_shm_endpoint* ep = se->se_endpoints[i];
  ep->sse_active = false;
  ep->sse_n_sent = 0;
  ep->sse_n_received = 0;
  sc_shm_ringbuf_reset(&ep->sse_ep_map->sse_ringbuf_from_create_side);
  sc_shm_ringbuf_reset(&ep->sse_ep_map->sse_ringbuf_to_create_side);
}


struct sc_shm_endpoint* sc_shm_endpoint_get(struct sc_shm_endpoints* se, int i)
{
  SC_TEST(i < se->se_n_endpoints);
  return se->se_endpoints[i];
}


int sc_shm_endpoint_activate(struct sc_shm_endpoints* se, int i)
{
  SC_TEST(i < se->se_n_endpoints);
  struct sc_shm_endpoint* ep = se->se_endpoints[i];
  if( ep->sse_active )
    return -EBUSY;

  ep->sse_active = true;
  return 0;
}


static inline int sc_shm_ringbuf_pop_head(struct sc_shm_ringbuf* rb,
                                          struct sc_shm_message* m)
{
  int rc;
  assert(rb);
  assert(m);
  sc_read_acquire();
  if( rb->sr_entries[rb->sr_head].sre_state != SSS_USED ) {
    rc =  -ENOMSG;
    goto out;
  }

  memcpy(m, &rb->sr_entries[rb->sr_head].sre_message, sizeof(*m));
  sc_write_release();
  rb->sr_entries[rb->sr_head].sre_state = SSS_FREE;
  rb->sr_head = (rb->sr_head + 1) % RINGBUF_SIZE;
  rc = 0;
 out:
  return rc;
}


static inline int sc_shm_ringbuf_push_tail(struct sc_shm_ringbuf* rb,
                                           struct sc_shm_message* m)
{
  int rc;
  assert(rb);
  assert(m);

  sc_read_acquire();
  if( rb->sr_entries[rb->sr_tail].sre_state != SSS_FREE ) {
    rc =  -ENOBUFS;
    goto out;
  }

  rc = 0;

  SC_TEST(rb->sr_entries[rb->sr_tail].sre_state == SSS_FREE);
  memcpy(&rb->sr_entries[rb->sr_tail].sre_message, m, sizeof(*m));
  sc_write_release();
  rb->sr_entries[rb->sr_tail].sre_state = SSS_USED;
  rb->sr_tail = (rb->sr_tail + 1) % RINGBUF_SIZE;
 out:
  return rc;
}


int
sc_shm_endpoint_msg_send(struct sc_shm_endpoint* ep,
                         struct sc_shm_message*  m)
{
  int rc;
  struct sc_shm_ringbuf* rb = ( ep->sse_create_side ) ?
    &ep->sse_ep_map->sse_ringbuf_from_create_side :
    &ep->sse_ep_map->sse_ringbuf_to_create_side;
  if( ep->sse_active ) {
    rc = sc_shm_ringbuf_push_tail(rb, m);
    if( rc == 0 )
      ++ep->sse_n_sent;
    return rc;
  }
  else {
    return -ENOTCONN;
  }
}


int
sc_shm_endpoint_msg_get(struct sc_shm_endpoint* ep,
                        struct sc_shm_message* m)
{
  int rc;
  struct sc_shm_ringbuf* rb = ( ep->sse_create_side ) ?
    &ep->sse_ep_map->sse_ringbuf_to_create_side :
    &ep->sse_ep_map->sse_ringbuf_from_create_side;
  if( ep->sse_active ) {
    rc = sc_shm_ringbuf_pop_head(rb, m);
    if( rc == 0 )
      ++ep->sse_n_received;
    return rc;
  }
  else {
    return -ENOTCONN;
  }
}


int sc_shm_ringbuf_get_space(struct sc_shm_ringbuf* rb)
{
  return (rb->sr_head + RINGBUF_SIZE - rb->sr_tail - 1) % RINGBUF_SIZE;
}


int sc_shm_endpoint_get_space(struct sc_shm_endpoint* ep)
{
  struct sc_shm_ringbuf* rb = ( ep->sse_create_side ) ?
    &ep->sse_ep_map->sse_ringbuf_from_create_side :
    &ep->sse_ep_map->sse_ringbuf_to_create_side;
  return sc_shm_ringbuf_get_space(rb);
}


uintptr_t
sc_pkt_shm_buffer_offset(struct sc_node* node, struct sc_packet* packet)
{
  struct sc_node_impl* ni = SC_NODE_IMPL_FROM_NODE(node);
  struct sc_session* tg = ni->ni_thread->session;
  struct sc_pkt* pkt = SC_PKT_FROM_PACKET(packet);
  struct sc_pkt_pool* buffer_pp = tg->tg_pkt_pools[pkt->sp_pkt_pool_id];
  while( buffer_pp->pp_linked_pool )
    buffer_pp = buffer_pp->pp_linked_pool;

  SC_TEST(packet->iovlen == 1);
  uintptr_t offset = (uintptr_t)packet->iov[0].iov_base - (uintptr_t)buffer_pp->pp_mmap_base;
  return offset;
}


static struct sc_shm_endpoint* sc_shm_endpoint_create(const char* endpoint_fname)
{
  struct sc_shm_endpoint* ep;
  ep = calloc(1, sizeof(struct sc_shm_endpoint));
  if( ep == NULL )
    goto out1;
  ep->sse_size = ALIGN_FWD(sizeof(struct sc_shm_endpoint_map), HUGE_PAGE_SZ);
  ep->sse_fd = open(endpoint_fname, O_CREAT | O_RDWR | O_TRUNC, 0660);
  if( ep->sse_fd < 0 )
    goto out2;
  if( ftruncate(ep->sse_fd, ep->sse_size) < 0 )
    goto out3;
  ep->sse_ep_path = strdup(endpoint_fname);
  if( ep->sse_ep_path == NULL )
    goto out3;
  ep->sse_ep_map = mmap(NULL, ep->sse_size,
                        PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                        ep->sse_fd, 0);
  if( ep->sse_ep_map == MAP_FAILED )
    goto out3;

  ep->sse_active = false;
  ep->sse_create_side = true;
  sc_shm_ringbuf_init(&ep->sse_ep_map->sse_ringbuf_from_create_side);
  sc_shm_ringbuf_init(&ep->sse_ep_map->sse_ringbuf_to_create_side);
  return ep;
 out3:
  close(ep->sse_fd);
 out2:
  free(ep);
 out1:
  return NULL;
}


static void sc_shm_endpoint_destroy(struct sc_shm_endpoint* ep)
{
  munmap(ep->sse_ep_map, ep->sse_size);
  close(ep->sse_fd);
  free(ep);
}


struct sc_shm_endpoints* sc_shm_endpoints_create(const char* fname_tmpl,
                                                 int n_endpoints)
{
  struct sc_shm_endpoints* se;
  int i;

  if( fname_tmpl == NULL )
    goto out1;

  se = calloc(1, sizeof(struct sc_shm_endpoints));
  if( se == NULL )
    goto out1;
  se->se_n_endpoints = n_endpoints;
  se->se_endpoints = calloc(n_endpoints, sizeof(struct sc_shm_endpoint*));
  if( se->se_endpoints == NULL )
    goto out2;

  char endpoint_fname[SSIO_MAX_STR_LEN];
  for( i = 0; i < se->se_n_endpoints; i++ ) {
    snprintf(endpoint_fname, SSIO_MAX_STR_LEN, "%s_%d", fname_tmpl, i);
    se->se_endpoints[i] = sc_shm_endpoint_create(endpoint_fname);
    if( se->se_endpoints[i] == NULL ) {
      int j;
      for( j = 0 ; j < i ; j++ )
        sc_shm_endpoint_destroy(se->se_endpoints[j]);
      goto out3;
    }
  }
  return se;
 out3:
  free(se->se_endpoints);
 out2:
  free(se);
 out1:
  return NULL;
}


const char* sc_shm_endpoint_get_path(struct sc_shm_endpoints* se, int i)
{
  SC_TEST(i < se->se_n_endpoints);
  return se->se_endpoints[i]->sse_ep_path;
}


void sc_shm_endpoint_notify_sleep(struct sc_shm_endpoint* ep)
{
  struct sc_shm_ringbuf* rb = ( ep->sse_create_side ) ?
    &ep->sse_ep_map->sse_ringbuf_to_create_side:
    &ep->sse_ep_map->sse_ringbuf_from_create_side;
  rb->sleep_seq = ep->sse_n_received;;
  sc_write_release();
}


uint64_t sc_shm_endpoint_get_remote_sleep_seq(struct sc_shm_endpoint* ep)
{
  struct sc_shm_ringbuf* rb = ( ep->sse_create_side ) ?
    &ep->sse_ep_map->sse_ringbuf_from_create_side:
    &ep->sse_ep_map->sse_ringbuf_to_create_side;
  return rb->sleep_seq;
}


uint64_t sc_shm_endpoint_get_n_sent(struct sc_shm_endpoint* ep)
{
  return ep->sse_n_sent;
}


uint64_t sc_shm_endpoint_get_n_received(struct sc_shm_endpoint* ep)
{
  return ep->sse_n_received;
}
