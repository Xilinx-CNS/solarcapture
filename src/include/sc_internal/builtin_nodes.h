/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

#ifndef __SC_BUILTIN_NODES_H__
#define __SC_BUILTIN_NODES_H__


struct sc_session;
struct sc_pkt_predicate;


extern const struct sc_node_factory sc_writer_sc_node_factory;


extern const struct sc_node_factory sc_disk_writer_sc_node_factory;


extern const struct sc_node_factory sc_perf_writer_sc_node_factory;


extern const struct sc_node_factory sc_pcap_packer_sc_node_factory;


extern const struct sc_node_factory sc_ps_to_ps_packer_sc_node_factory;


extern const struct sc_node_factory sc_block_writer_sc_node_factory;


extern const struct sc_node_factory sc_eos_fwd_node_factory;


extern const struct sc_node_factory sc_reader_sc_node_factory;


extern const struct sc_node_factory sc_arista_ts_sc_node_factory;


extern const struct sc_node_factory sc_arista7150_ts_sc_node_factory;


extern const struct sc_node_factory sc_arista7280_64bit_ts_sc_node_factory;


extern const struct sc_node_factory sc_arista7280_48bit_ts_sc_node_factory;


extern const struct sc_node_factory sc_cpacket_ts_sc_node_factory;


extern const struct sc_node_factory sc_filter_sc_node_factory;


extern const struct sc_node_factory sc_tap_sc_node_factory;


extern const struct sc_node_factory sc_fd_reader_sc_node_factory;


extern const struct sc_node_factory sc_fd_writer_sc_node_factory;


extern const struct sc_node_factory sc_ts_adjust_sc_node_factory;


extern const struct sc_node_factory sc_pacer_sc_node_factory;


extern const struct sc_node_factory sc_rt_pacer_sc_node_factory;


extern const struct sc_node_factory sc_stopcock_sc_node_factory;


extern const struct sc_node_factory sc_signal_vi_sc_node_factory;


extern const struct sc_node_factory sc_shm_import_sc_node_factory;


extern const struct sc_node_factory sc_shm_export_sc_node_factory;


extern const struct sc_node_factory sc_shm_broadcast_sc_node_factory;


extern const struct sc_node_factory sc_repeater_sc_node_factory;


extern const struct sc_node_factory sc_line_reader_sc_node_factory;


extern const struct sc_node_factory sc_tracer_sc_node_factory;


extern const struct sc_node_factory sc_header_editor_sc_node_factory;


extern const struct sc_node_factory sc_exit_sc_node_factory;


extern const struct sc_node_factory sc_merge_sorter_sc_node_factory;


extern const struct sc_node_factory sc_rate_monitor_sc_node_factory;


extern const struct sc_node_factory sc_snap_sc_node_factory;


extern const struct sc_node_factory sc_sim_work_sc_node_factory;


extern const struct sc_node_factory sc_vi_monitor_sc_node_factory;


extern const struct sc_node_factory sc_batch_limiter_sc_node_factory;


extern const struct sc_node_factory sc_no_op_sc_node_factory;


extern const struct sc_node_factory sc_vss_sc_node_factory;


extern const struct sc_node_factory sc_pool_forwarder_sc_node_factory;


extern const struct sc_node_factory sc_range_filter_sc_node_factory;


extern const struct sc_node_factory sc_timestamp_filter_sc_node_factory;


extern const struct sc_node_factory sc_io_demux_sc_node_factory;


extern const struct sc_node_factory sc_append_to_list_sc_node_factory;


extern const struct sc_node_factory sc_delay_line_sc_node_factory;


extern const struct sc_node_factory sc_strip_vlan_sc_node_factory;


extern const struct sc_node_factory sc_pktgen_sc_node_factory;


extern const struct sc_node_factory sc_ps_packer_sc_node_factory;


extern const struct sc_node_factory sc_ps_unpacker_sc_node_factory;


extern const struct sc_node_factory sc_subnode_helper_sc_node_factory;


extern const struct sc_node_factory sc_vi_node_sc_node_factory;


extern const struct sc_node_factory sc_tunnel_sc_node_factory;


extern const struct sc_node_factory sc_rr_spreader_sc_node_factory;


extern const struct sc_node_factory sc_rr_gather_sc_node_factory;


extern const struct sc_node_factory sc_token_bucket_shaper_sc_node_factory;


extern const struct sc_node_factory sc_cpacket_encap_sc_node_factory;


extern const struct sc_node_factory sc_pass_n_sc_node_factory;


extern const struct sc_node_factory sc_flow_balancer_sc_node_factory;


extern const struct sc_node_factory sc_wrap_undo_sc_node_factory;


extern const struct sc_node_factory sc_tuntap_sc_node_factory;


extern int sc_bpf_predicate_alloc(struct sc_pkt_predicate** pred_out,
                                  struct sc_session*, const char* filter_str);


#endif  /* __SC_BUILTIN_NODES_H__ */
