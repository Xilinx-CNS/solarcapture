/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/


ST_CONSTANT(SC_STATS_MAX_NAME_LEN, 128)

ST_CONSTANT(SC_STATS_MAX_POOLS_LIST_LEN, 1024)


ST_STRUCT(sc_stats_file_header)
  ST_FIELD(int,      total_length,             magnitude)
ST_STRUCT_END


ST_STRUCT(sc_thread_stats)
  ST_FIELD(int,      id,                       config)
  ST_FIELD(int,      affinity,                 config)
  ST_FIELD(int,      managed,                  config)
  ST_FIELD(int,      fd_poll_max_events,       config)
  ST_FIELD(int,      fd_poll_nanos,            config)
  ST_FIELD(int,      state_requested,          sc_thread_state)
  ST_FIELD(int,      state,                    sc_thread_state)
  ST_FIELD(int,      wakes,                    ev_count)
  ST_FIELD(int,      woken,                    ev_count)
ST_STRUCT_END


ST_STRUCT(sc_idle_monitor_stats)
  ST_FIELD(uint64_t, idle_loops,               ev_count)
ST_STRUCT_END


ST_STRUCT(sc_mailbox_stats)
  ST_FIELD(int,      id,                       config)
  ST_FIELD(int,      managed,                  config)
  ST_FIELD(int,      thread_id,                config)
  ST_FIELD(int,      peer_id,                  config)
  ST_FIELD(int,      send_node_id,             config)
  ST_FIELD(int,      recv_node_id,             config)
  ST_FIELD(int,      send_min_pkts,            config)
  ST_FIELD(int,      send_max_nanos,           config)
  ST_FIELD(int,      recv_max_pkts,            config)
  ST_FIELD(int,      eos_in,                   flag)
  ST_FIELD(int,      eos_out,                  flag)
  ST_FIELD(int,      send_backlog,             pkt_count)
  ST_FIELD(int,      recv_backlog,             pkt_count)
  ST_FIELD(uint64_t, wakes,                    ev_count)
#if SC_MBOX_DEBUG_STATS
  ST_FIELD(uint64_t, sblocked,                 ev_count)
  ST_FIELD(uint64_t, rblocked,                 ev_count)
  ST_FIELD(uint64_t, sent_data,                ev_count)
  ST_FIELD(uint64_t, sent_ack,                 ev_count)
  ST_FIELD(uint64_t, recved_data,              ev_count)
  ST_FIELD(uint64_t, recved_ack,               ev_count)
  ST_FIELD(int,      send_list,                magnitude)
#endif
ST_STRUCT_END


ST_STRUCT(sc_node_stats)
  ST_FIELD(int,      id,                       config)
  ST_FIELD_STR(node_type_name, SC_STATS_MAX_NAME_LEN, config)
  ST_FIELD(int,      thread_id,                config)
  ST_FIELD(int,      state,                    config)
  ST_FIELD(int,      dispatch_order,           config)
  ST_FIELD(int,      n_links_in,               config)
  ST_FIELD(int,      n_links_out,              config)
  ST_FIELD(int,      is_free_path,             config)
  ST_FIELD_STR(pools_in, SC_STATS_MAX_POOLS_LIST_LEN, config)
  ST_FIELD(int,      eos_left,                 magnitude)
#if SC_NODE_STATS
  ST_FIELD(uint64_t, pkts_in,                  pkt_count)
  ST_FIELD(uint64_t, pkts_out,                 pkt_count)
#endif
ST_STRUCT_END


ST_STRUCT(sc_vi_stats)
  ST_FIELD(int,      id,                       config)
  ST_FIELD(int,      thread_id,                config)
  ST_FIELD(int,      vi_group_id,              config)
  ST_FIELD(int,      pool_id,                  config)
  ST_FIELD(int,      interface_id,             config)
  ST_FIELD(int,      recv_node_id,             config)
  ST_FIELD(int,      rx_refill_batch_low,      config)
  ST_FIELD(int,      rx_refill_batch_high,     config)
  ST_FIELD(int,      poll_batch,               config)
  ST_FIELD(int,      evq_size,                 config)
  ST_FIELD(int,      tx_ring_max,              config)
  ST_FIELD(int,      rx_ring_max,              config)
  ST_FIELD(int,      rx_ring_size,             config)
  ST_FIELD(int,      rx_ring_low_level,        config)
  ST_FIELD(int,      rx_ring_high_level,       config)
  ST_FIELD(int,      n_bufs_rx_req,            config)
  ST_FIELD(int,      n_bufs_rx_min,            config)
  ST_FIELD(int,      discard_mask,             config)
  ST_FIELD(int,      hw_timestamps,            config)
  ST_FIELD(int,      packed_stream_mode,       config)
  ST_FIELD(int,      packed_stream_unpack,     config)
  ST_FIELD(int,      packed_stream_pool_id,    config)
  ST_FIELD(int,      packed_stream_flush_nanos,config)

  ST_FIELD(uint64_t, n_rxq_low,                ev_count)
  ST_FIELD(uint64_t, n_free_pool_empty,        ev_count)
  ST_FIELD(uint64_t, n_rx_csum_bad,            pkt_count)
  ST_FIELD(uint64_t, n_rx_crc_bad,             pkt_count)
  ST_FIELD(uint64_t, n_rx_trunc,               pkt_count)
  ST_FIELD(uint64_t, n_rx_mcast_mismatch,      pkt_count)
  ST_FIELD(uint64_t, n_rx_ucast_mismatch,      pkt_count)
  ST_FIELD(uint64_t, n_rx_no_desc_trunc,       pkt_count)
  ST_FIELD(uint64_t, n_rx_pkts,                pkt_count)
  ST_FIELD(uint64_t, n_rx_bytes,               byte_count)
  ST_FIELD(uint64_t, packed_backlog,           magnitude)
  ST_FIELD(uint64_t, packed_backlog_max,       magnitude)
  ST_FIELD(uint64_t, n_packed_backlog_enter,   ev_count)
  ST_FIELD(uint64_t, n_wakes,                  ev_count)
  ST_FIELD(uint64_t, n_total_ev,               ev_count)
  ST_FIELD(uint64_t, n_tx_ev,                  ev_count)
  ST_FIELD(uint64_t, n_tx_doorbell,            ev_count)
  ST_FIELD(uint64_t, tx_backlog,               magnitude)
  ST_FIELD(uint64_t, n_tx_backlog_enter,       ev_count)

#if SC_VI_DEBUG_STATS
  ST_FIELD(uint64_t, jumbo_start,              ev_count)
  ST_FIELD(uint64_t, jumbo_finish,             ev_count)
  ST_FIELD(uint64_t, jumbo_drop,               ev_count)
  ST_FIELD(int,      recv_space,               magnitude)
  ST_FIELD(int,      recv_fill_level,          magnitude)
  ST_FIELD(int,      pool,                     magnitude)
#endif
ST_STRUCT_END

ST_STRUCT(sc_vi_burst_stats)
  ST_FIELD(uint64_t, n_bursts,                 ev_count)
ST_STRUCT_END

ST_STRUCT(sc_pool_stats)
  ST_FIELD(int,      id,                       config)
  ST_FIELD(int,      huge_pages,               magnitude)
  ST_FIELD(int,      allocated_bufs,           magnitude)
  ST_FIELD(int,      n_bufs,                   magnitude)
  ST_FIELD(int,      n_bufs_out_of_order,      pkt_count)
  ST_FIELD(int,      n_full_bins,              magnitude)
  ST_FIELD(int,      min_full_bins,            magnitude)
  ST_FIELD(uint64_t, interfaces,               config)
ST_STRUCT_END


ST_STRUCT(sc_vi_monitor_stats)
  ST_FIELD(int,      vi_id,                    config)
  ST_FIELD(uint64_t, pkts_dropped,             pkt_count)
ST_STRUCT_END
