/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#ifndef __SC_PKT_H__
#define __SC_PKT_H__


/* Max number of interfaces we can handle in a single session. */
#define SC_MAX_NETIFS    8

/* Size of the iovec in an sc_packet.  6 is enough to represent a maximally
 * sized jumbo frame split over FALCON_RX_USR_BUF_SIZE sized buffers.
 */
#define SC_PKT_MAX_IOVS  6

/* The default size for packet buffers used for DMA.  This size is
 * efficient when using buffers for DMA receive, since we can fit the
 * sc_pkt and DMA area in.  This size includes the sc_pkt prefix.
 */
#define SC_DMA_PKT_BUF_SIZE    2048

/* The size of the payload area for packets of size SC_DMA_PKT_BUF_SIZE. */
#define SC_DMA_PKT_BUF_LEN     (SC_DMA_PKT_BUF_SIZE - PKT_DMA_OFF)


struct sc_pkt {
  /* Unfortunately we need to store the buffer length in sc_pkt because the
   * pool is optional in sc_packet_append_iovec_ptr().
   */
  uint32_t            sp_len;
  uint8_t             sp_pkt_pool_id;
  uint8_t             sp_is_inline;      /* currently only used for assert */
  uint16_t            sp_ref_count;
  struct sc_packet    sp_usr;
  union {
    struct {
      /* Used when passing a packet list through a mailbox. */
      struct sc_packet** tail;
      int                num_pkts;
      int                num_frags;
    }                 sp_mbox;
    struct {
      /* Used when a packet list is being transmitted. */
      struct sc_injector_node* injector;
    }                 sp_tx;
  };
  struct iovec        sp_iov_storage[SC_PKT_MAX_IOVS];
  /* DMA address of the start of the receive DMA buffer for each netif.
   * Indexed by netif_id.
   */
  uint64_t            sp_ef_addr[SC_MAX_NETIFS];
  /* Pointer to start of payload buffer.  (When sp_is_inline is true, this
   * is the same as ((uint8_t*) pkt + PKT_DMA_OFF)).
   */
  void*               sp_buf;
};


#define SC_PKT_FROM_PACKET(p)  SC_CONTAINER(struct sc_pkt, sp_usr, (p))

#define SC_PKT_NEXT(pkt)       SC_PKT_FROM_PACKET((pkt)->sp_usr.next)


static inline uint8_t* sc_pkt_get_buf(const struct sc_pkt* pkt)
{
  return pkt->sp_buf;
}


static inline uint8_t* sc_pkt_get_buf_end(struct sc_pkt* pkt)
{
  return sc_pkt_get_buf(pkt) + pkt->sp_len;
}


#endif  /* __SC_PKT_H__ */
