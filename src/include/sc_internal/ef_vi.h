/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#ifndef __SC_EF_VI_H__
#define __SC_EF_VI_H__

#include <etherfabric/vi.h>
#include <etherfabric/memreg.h>
#include <etherfabric/pd.h>
#include <etherfabric/packedstream.h>


enum sc_ef_vi_flags {
  vif_tx_csum_tcpudp          = 0x1,
  vif_tx_csum_ip              = 0x2,
  vif_has_stream              = 0x4,
  vif_active_discard          = 0x8,
  vif_rx_timestamps           = 0x10,
  vif_packed_stream           = 0x20,
  vif_rx_event_merge          = 0x40,
};


struct sc_packed_stream_vi {
  struct sc_pkt*              current_ps_pkt;
  struct sc_pkt_pool*         ref_pkt_pool;
  struct sc_callback*         flush_cb;
  struct sc_callback*         backlog_cb;
  struct sc_packet_list       backlog;
  int                         backlog_threshold;
  bool                        unpack;
  ef_packed_stream_params     ps_params;
  uint8_t                     ps_flags_mask;
};


struct sc_ef_vi {
  struct sc_thread*           thread;
  struct sc_pkt*              jumbo;
  struct sc_netif*            netif;
  bool                        packed_stream_mode;
  int                         netif_id;
  ef_event*                   ef_events;
  struct sc_node_impl*        vi_recv_node;
  struct sc_node*             undo_node;
  struct sc_pkt_pool*         pkt_pool;
  struct sc_vi_stats*         stats;
  struct sc_vi_burst_stats*   burst_stats;
  struct sc_packet_list       vi_tx_q;
  int                         vi_tx_filling;
  int                         vi_tx_stop_filling_level;
  int                         vi_tx_refill_level;
  char*                       name;
  ef_vi                       vi;
  ef_driver_handle            dh;
  unsigned                    discard_mask;
  int                         jumbo_truncated;
  int                         id;
  unsigned                    flags;   /* sc_ef_vi_flags */
  int                         snap;
  int                         private_pool;
  int                         rx_prefix_len;
  int                         rx_ring_low_level;
  int                         rx_ring_high_level;
  int                         rx_ring_max;
  int                         rx_refill_batch;
  int                         rx_refill_batch_high;
  int                         rx_refill_batch_low;
  int                         poll_batch;
  unsigned                    rx_added;
  unsigned                    rx_removed;
  struct sc_pkt**             rx_pkts;
  unsigned                    tx_added;
  unsigned                    tx_removed;
  struct sc_pkt**             tx_pkts;
  struct sc_callback*         readable_cb;
  struct sc_callback*         burst_cb;
  uint64_t                    burst_interval_ns;
  uint64_t                    n_rx_pkts_prev;
  uint64_t                    n_rx_bytes_prev;
  uint64_t                    burst_pkts_threshold;
  uint64_t                    burst_bytes_threshold;
  int                         primed;
  struct sc_packed_stream_vi* packed_stream_vi;
  bool                        vi_running;
};


enum sc_vi_group_type {
  sc_vi_group_type_ef_vi,
};


typedef int (sc_vi_group_add_stream_fn)(struct sc_vi_group* vi_group,
                                        struct sc_stream* s,
                                        enum sc_capture_mode capture_mode,
                                        int promiscuous);


struct sc_vi_group {
  struct sc_session*         svg_tg;
  sc_vi_group_add_stream_fn* svg_add_stream_fn;
  enum sc_vi_group_type      svg_type;
  enum sc_capture_mode       svg_capture_mode;
  int                        svg_promiscuous;
  int                        svg_strip_fcs;
};


struct sc_ef_vi_group {
  struct sc_netif*      netif;
  struct sc_vi_group    sc_vi_group;
  ef_vi_set             ef_vi_set;
  ef_driver_handle      dh;
  int                   n_vis;
  int                   index;
  int                   vi_group_id;
  enum sc_capture_point capture_point;
};


struct sc_netif {
  struct sc_interface* interface;
  char*              name;  /* name of cluster or interface */
  ef_driver_handle   dh;
  ef_pd              pd;
  int                netif_id;
  bool               no_cluster;
  bool               is_packed_stream;
};


extern int __sc_ef_vi_init(struct sc_thread*,  const struct sc_attr*,
                           struct sc_ef_vi*,  struct sc_netif*,
                           unsigned sc_ef_vi_flags);

extern int sc_ef_vi_alloc(struct sc_ef_vi**, const struct sc_attr*,
                          struct sc_thread*, const char*,
                          unsigned sc_ef_vi_flags);

extern int sc_ef_vi_free(struct sc_session*, struct sc_ef_vi*);

extern int sc_ef_vi_set_recv_node(struct sc_ef_vi*, struct sc_node* to_node,
                                  const char* name_opt, const struct sc_attr*);

extern int sc_ef_vi_add_stream(struct sc_ef_vi*, struct sc_stream*,
                               enum sc_capture_mode, int promiscuous,
                               enum sc_capture_point capture_point);

extern void sc_ef_vi_transmit_list(struct sc_ef_vi* vi, 
                                   struct sc_packet_list* pl,
                                   struct sc_injector_node* inj);

extern void sc_ef_vi_about_to_sleep(struct sc_ef_vi* vi);

extern void sc_ef_vi_prep(struct sc_ef_vi*);

extern void sc_ef_vi_set_non_busy_wait(struct sc_ef_vi* vi);

extern int sc_netif_is_cluster(const struct sc_netif *const netif);

extern int sc_netif_alloc(struct sc_netif** netif_out,
                          unsigned pd_flags,
                          struct sc_session* scs,
                          const char* interface_name,
                          bool no_cluster,
                          bool report_erorrs);

extern int sc_netif_get(struct sc_netif** netif_out,
                        const struct sc_attr* attr,
                        struct sc_session* scs,
                        const char* interface_name);

extern int sc_netif_free(struct sc_session* tg, struct sc_netif* netif);


#endif /* __SC_EF_VI_H_ */
