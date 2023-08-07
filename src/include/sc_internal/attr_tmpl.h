/*
** SPDX-License-Identifier: MIT
** X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
*/

/*
 * SC_ATTR(type, name, status, default, objects, doc)
 *
 *        type: int or str
 *        name: name of attribute
 *      status: stable, stable_expert, hidden, beta, unstable or deprecated
 * default_val: default value of attribute (must be NULL for str attrs)
 * default_doc: description of default, or NULL
 *     objects: what type(s) of objects the attribute applies to
 *         doc: documentation
 */


/**********************************************************************
 * Generic attributes.
 */

SC_ATTR(str, name, stable, NULL, "(none)",
        "sc_session,sc_thread,sc_vi,sc_node,sc_mailbox,sc_pool",

        "The object name.  Object names are visible in log messages and in "
        "solar_capture_monitor, but have no other effect.")

SC_ATTR(str, group_name, stable, NULL, "(none)",
        "sc_session,sc_thread,sc_vi,sc_node,sc_mailbox,sc_pool",

        "The object group name.  Object group names are visible in log "
        "messages and in solar_capture_monitor, but have no other effect.")

SC_ATTR(int, managed, stable, 1, "1 (object is managed)",
        "sc_thread,sc_mailbox",

        "The managed attribute determines whether an object is polled by the "
        "SolarCapture core.  By default all objects are managed.\n"

        "If an sc_thread is unmanaged then SolarCapture does not create an "
        "OS thread of execution for that thread.  The application should "
        "poll the sc_thread by calling sc_thread_poll() as needed.\n"

        "If an sc_mailbox is unmanaged then it is not polled by the owning "
        "thread's polling loop.  The application should poll the mailbox by "
        "calling sc_mailbox_poll().")

SC_ATTR(int, batch_num_pkts, stable, -1, "(preemptive batching disabled)",
        "sc_mailbox",

        "This attribute, together with batch_timeout_nanos, "
        "controls batching in various parts of SolarCapture.  Where packets "
        "are be batched preemptively, they are held until at least "
        "batch_num_pkts are queued, or until batch_timeout_nanos have "
        "passed since the first packed in the batch was queued.\n"

        "If this attribute is set to 1 then preemptive batching is disabled.\n"

        "This attribute is overridden by mailbox_min_pkts.")

SC_ATTR(int, batch_timeout_nanos, stable, 100000, NULL,
        "sc_thread,sc_mailbox,sc_vi",

        "This attribute sets the timeout in nanoseconds for various forms of "
        "preemptive batching.  Settings this attribute to a higher value will "
        "increase latency on the paths where it is used, but may improve "
        "efficiency by encouraging batching.\n"

        "See batch_num_pkts and fd_poll_nanos for further details.  This "
        "attribute also sets the timeout for flushing packed buffers from "
        "an sc_vi in packed-stream mode, and may also control batching in "
        "the receive path of the network adapter.\n"

        "This attribute is overridden by mailbox_max_nanos, fd_poll_nanos "
        "and rx_batch_nanos where applicable.")

SC_ATTR(int, batch_max_pkts, stable, 0, "(batch size not limited)",
        "sc_vi,sc_mailbox",

        "This attribute can be used to limit the size of batches of packets.\n"

        "Batch sizes can grow large when a thread is heavily loaded, which "
        "may lead to a large working set size and reduced efficiency due to"
        "cache and TLB misses.\n"

        "This attribute is overridden by vi_recv_max_pkts, "
        "mailbox_recv_max_pkts and pool_refill_max_pkts where applicable.")


/**********************************************************************
 * sc_session attributes.
 */

SC_ATTR(int, log_level, stable, SC_LL_INFO, "3 (info)",
        "sc_session",

        "Control verbosity of log messages.  Values: 0(none), 1(errors), "
        "2(warnings), 3(info), 4(trace), 5(trace fast path).  Log messages at "
        "level 5 and above are only available in debug builds.")

SC_ATTR(str, log_base_dir, stable, NULL, "/var/tmp",
        "sc_session",

        "Set location of directory tree under which the log/stats directory "
        "used by solar_capture_monitor will be created.\n"

        "This attribute will be ignored if log_dir is specified.")

SC_ATTR(str, log_dir, stable, NULL, "/var/tmp/solar_capture_$user_$pid/$id",
        "sc_session",

        "Set location of log/stats directory used by solar_capture_monitor.")


/**********************************************************************
 * sc_vi attributes.
 */

SC_ATTR(str, capture_mode, stable, NULL, "steal",
        "sc_vi,sc_stream",

        "The capture_mode can be 'steal', in which case captured packets are "
        "removed from the adapter datapath, or 'sniff', in which case "
        "captured packets are copied from the adapter datapath.  The default "
        "capture_mode is 'steal'.\n"

        "The capture mode can be set per-VI or per-stream.")

SC_ATTR(str, vi_mode, unstable, NULL, "auto",
        "sc_vi",

        "The vi_mode can be one of 'packed_stream' and 'normal'.  If it "
        "is set to 'auto', solar_capture attempts to configure the vi for best "
        "performance on the system.")

SC_ATTR(int, promiscuous, stable, -1, "1 (enabled)",
        "sc_vi,sc_stream",

        "This attribute controls whether a 'sniff' mode capture is in "
        "promiscuous mode or not.  Promiscuous mode is enabled by default, "
        "and can be disabled by setting this attribute to 0.\n"

        "In promiscuous mode SolarCapture receives a copy of all packets "
        "arriving at the interface.  Otherwise SolarCapture receives a copy "
        "of all packets delivered to the host.  ie. Packets that would "
        "normally be discarded by the adapter are only captured when "
        "promiscuous mode is enabled.")


SC_ATTR(str, capture_point, stable, NULL, "ingress",
        "sc_vi",

        "The capture point controls which datapath is tapped.  It can be set "
        "to 'ingress' (default) or 'egress'.")

SC_ATTR(int, snap, stable, SC_SNAP_UNSPECIFIED, "0 (no snap)",
        "sc_vi",

        "This attribute controls how many bytes of each packet are captured.  "
        "By default the whole packet is captured.\n"

        "When possible the 'snap' is applied in hardware, and only the "
        "specified amount of packet data is transfered into the host.  On "
        "adapters that do not support hardware snap, the whole packet is "
        "transferred into the host and the snap is applied in software.")

SC_ATTR(int, hw_snap, stable, SC_SNAP_UNSPECIFIED, "0 (no snap)",
        "sc_vi",

        "This attribute performs that same function as 'snap', except that it "
        "is only applied when it can be performed in hardware.  It has "
        "no effect on adapters that do not support hardware snap.")

SC_ATTR(str, cluster, stable, NULL, "(no clustering)",
        "sc_vi",

        "This attribute turns on 'application clustering', which causes "
        "captured packets to be distributed over a cluster of application "
        "instances.  This attribute enables application clustering and gives "
        "the name of the cluster.")

SC_ATTR(int, unpack_packed_stream, unstable, 1, NULL,
        "sc_vi",

        "Whether to unpack packed stream packets.  If this is set to zero, "
        "sc_vi emits complete packed stream buffers for efficient disk "
        "writing.  If this is set to non-zero, sc_vi emits unpacked packets "
        "which can then be consumed by any node.")

SC_ATTR(int, require_hw_timestamps, stable, 0, NULL,
        "sc_vi",

        "When set to non-zero, cause VI allocation to fail if hardware "
        "timestamps are not available.")

SC_ATTR(int, force_sw_timestamps, stable, 0, NULL,
        "sc_vi",

        "When set to non-zero, use software timestamps even when hardware "
        "timestamps are available.")

SC_ATTR(int, rx_ring_max, stable, -1, "depends on vi_mode",
        "sc_vi",

        "Set the size and maximum fill level of the RX descriptor ring, which "
        "provides buffering between the network adapter and software.  The "
        "RX ring sizes supported are 512, 1024, 2048 and 4096.")


SC_ATTR(int, tx_ring_max, stable, 504, NULL,
        "sc_vi,sc_pool",

        "Set the size of the TX descriptor ring, which is used to pass "
        "injected packets from software to the network adapter.  The "
        "requested value is rounded up to the next size supported by the "
        "adapter.  At time of writing the ring sizes supported are 512, 1024, "
        "2048 and 4096.  (4096 is not supported on 7000-series adapters).")

SC_ATTR(int, poll_batch, stable_expert, 32, NULL,
        "sc_vi",

        "Maximum number of network events to handle for each VI in each "
        "polling loop iteration.")

SC_ATTR(int, rx_ring_low, stable_expert, 60, NULL,
        "sc_vi",

        "If the RX ring fill level falls below this level, the fill level is "
        "considered to be 'low', and the ring is refilled by "
        "rx_refill_batch_low buffers in each polling loop iteration.\n"

        "This attribute is expressed as a percentage of rx_ring_max.")

SC_ATTR(int, rx_ring_high, stable_expert, 80, NULL,
        "sc_vi",

        "If the RX ring fill level rises above this level, the fill level is "
        "considered to be 'high', and the ring is refilled by "
        "rx_refill_batch_high buffers in each polling loop iteration.\n"

        "This attribute is expressed as a percentage of rx_ring_max.")

SC_ATTR(int, rx_refill_batch_high, stable_expert, -1, "depends on vi_mode",
        "sc_vi",

        "Number of buffers to add to the RX ring in each polling loop "
        "iteration when the ring is 'high'.")

SC_ATTR(int, rx_refill_batch_low, stable_expert, -1, "depends on vi_mode",
        "sc_vi",

        "Number of buffers to add to the RX ring in each polling loop "
        "iteration when the ring is 'low'.")

SC_ATTR(int, vi_recv_max_pkts, stable, -1, "(batch_max_pkts)",
        "sc_vi",

        "Maximum number of received packets to forward out of the sc_vi "
        "in each polling loop iteration.\n"

        "This option can be used to control the balance between polling "
        "the hardware for new packets, and processing received packets.  By "
        "default the number of received packets processed in each polling "
        "loop is limited by the 'poll_batch' attribute.  If vi_recv_max_pkts "
        "is set to a value smaller than poll_batch, then when busy fewer "
        "packets are forwarded to the sc_vi's receive-node, which effectively "
        "means that more CPU time is reserved for handling network events.\n"

        "It only makes sense to set this attribute when packet processing "
        "work is done in the same thread as the ef_vi.  When processing "
        "packets in another thread, use the mailbox_recv_max_pkts attribute "
        "to control batching if needed.")

SC_ATTR(int, n_bufs_rx, stable, -1, "(unset; see pool_size)",
        "sc_vi",

        "Target number of packet buffers to allocate for each sc_vi for "
        "receive buffers.  Since the size of buffers and how they are used "
        "depends on vi_mode, it is usually better to use the pool_size "
        "attribute instead.")

SC_ATTR(int, n_bufs_rx_min, deprecated, -1, "MIN(n_bufs_rx, 8192)",
        "sc_vi",

        "Minumum number of packet buffers to allocate for each VI for "
        "receive.  If this minimum is not achieved, then an error will be "
        "raised.  (Which call will return the error is not specified).")

SC_ATTR(int, discard_mask, stable, 0, NULL,
        "sc_vi",

        "The discard_mask attribute instructs an sc_vi to discard packets "
        "with errors.  The discard_mask should be set to 0 or to a "
        "combination of the following flags:\n"

        "  SC_CSUM_ERROR\n"
        "  SC_CRC_ERROR\n"
     /* "  SC_TRUNCATED\n" -- not documented as always discarded */
        "  SC_MCAST_MISMATCH\n"
        "  SC_UCAST_MISMATCH\n"

        "All adapters support detection of Ethernet CRC errors "
        "(SC_CRC_ERROR).  The other error types may not be detected by all "
        "adapters, so portable applications should not depend on them "
        "working.")

SC_ATTR(int, active_discard, hidden, 0, NULL, "sc_vi", NULL)

SC_ATTR(int, rx_batch_nanos, stable, -1, "(batching enabled if applicable)",
        "sc_vi",

        "This attribute sets the timeout for batching in the network adapter "
        "receive path.  Batching usually improves throughput and efficiency "
        "at the cost of latency.\n"

        "Set rx_batch_nanos=0 to disable batching.  If this attribute is not "
        "set, then batching is enabled if available and the timeout is taken "
        "from batch_timeout_nanos, except that batching is disabled if "
        "batch_timeout_nanos is 0.\n"

        "NB. Not all network interfaces support batching, and not all support "
        "setting a timeout for batching.  Some network interfaces may use "
        "batching regardless of this setting.")


SC_ATTR(int, vi_burst_interval_ns, hidden, 0, NULL,
        "sc_vi",

        "Interval for burst detection.  Burst detection is disabled if set to "
        "0.")


SC_ATTR(int, vi_burst_pkts_threshold, hidden, 0, NULL,
        "sc_vi",

        "Burst is registered if this threshold is exceeded in burst_interval.  "
        "Setting this to 0 disables burst detection by packet count.")


SC_ATTR(int, vi_burst_bytes_threshold, hidden, 0, NULL,
        "sc_vi",

        "Burst is registered if this threshold is exceeded in burst_interval.  "
        "Setting this to 0 disables burst detection by byte count.")


SC_ATTR(str, vi_mmap_fname, hidden, NULL, "(none)",
        "sc_vi",

        "If set, DMA buffers for the VI are exported via the specified file")


SC_ATTR(int, n_bufs_unpack_pool, stable, -1,
        "(unset; see n_bufs_unpack_pool_max)",
        "sc_vi",

        "Set the number of buffers in the pool used to unpack packets received "
        "on an sc_vi in packed-stream mode.  This places a limit the number "
        "of packets that can be 'in-flight' in the node graph downstream "
        "of the VI.  This is usually a good thing because it reduces the "
        "working set size.\n"

        "See also n_bufs_unpack_pool_max.")

SC_ATTR(int, n_bufs_unpack_pool_max, stable, 14000, NULL,
        "sc_vi",

        "Set an upper limit on the number of buffers in the pool used to "
        "unpack packets received on an sc_vi in packed-stream mode.\n"

        "Set to -1 to remove this limit.  You are likely to want to increase "
        "or remove this limit only if the node graph holds up large numbers "
        "of packets and you want to prevent head-of-line blocking.\n"

        "This attribute is ignored if n_bufs_unpack_pool is set.")

SC_ATTR(int, linear_header, stable, 100, NULL,
        "sc_vi",

        "Set the minimum number of bytes required in the first contiguous "
        "buffer segment.\n"

        "In general, SolarCapture packets can be split over multiple buffers."
        "  Set this attribute to ensure that at least the given number "
        "of bytes (subject to packet length) will be presented in the first "
        "contiguous buffer segment.  This is important because some nodes "
        "only operate on data in the first segment.")


SC_ATTR(int, pd_flags, hidden, 0, NULL, "sc_vi", NULL)

SC_ATTR(int, strip_fcs, stable, -1, "-1 (don't care)",
        "sc_vi",

        "This attribute specifies whether the ethernet frame check sequence "
        "is required to be stripped from captured packets.\n"

        "By default solar_capture will use the current setting of the "
        "interface (strip_fcs=-1).  If it is required to not strip the FCS "
        "set strip_fcs=0.  If it is required to strip the FCS then set "
        "strip_fcs=1.")

SC_ATTR(int, affinity_core, stable, -1, "(thread is not affinitised)",
        "sc_thread",

        "Set the CPU core that the thread should be affinitised to.  By "
        "default threads are not affinitised by SolarCapture.")

SC_ATTR(int, idle_monitor, stable, 1, "1 (enabled when busy_wait=1)",
        "sc_thread",

        "This attribute controls whether the idle_loops statistic is turned "
        "on.  By default it is turned for threads with busy_wait=1.  Set to "
        "0 to disable the idle_loops statistic.")

SC_ATTR(int, busy_wait, stable, 1, "1 (enabled)",
        "sc_thread",

        "Control whether or not a thread 'busy waits'.  Set to 0 to disable "
        "busy-waiting.\n"

        "By default SolarCapture threads busy-wait.  That is, they poll for "
        "network events and other I/O continuously, using all available CPU "
        "time on the core they are running on.  This helps achieve good "
        "accuracy of software timestamps, and reduces the chances of loss "
        "and the expense of high CPU utilisation.\n"

        "In releases prior to SolarCapture 1.3 threads that manage any VIs "
        "must busy-wait.")

SC_ATTR(int, fd_poll_nanos, stable, -1, "(batch_timeout_nanos)",
        "sc_thread",

        "Set the polling interval for file descriptors managed by a "
        "SolarCapture thread.  See sc_epoll_ctl().")

SC_ATTR(int, fd_poll_max_events, beta, 256, NULL,
        "sc_thread",

        "Set the maximum number of events to handle each time file "
        "descriptors are polled.")

SC_ATTR(int, vid_optional, hidden, 0, NULL,
        "sc_stream",

        "Set to 1 to make 'vid' optional when adding a stream to a VI. "
        "If the full stream is not supported by the NIC, solar_capture will "
        "retry without the 'vid' field.")


/**********************************************************************
 * sc_mailbox attributes.
 */

SC_ATTR(int, mailbox_min_pkts, stable, -1, "(batch_num_pkts)",
        "sc_mailbox",

        "This attribute, together with mailbox_max_nanos, controls batching "
        "on the send side of mailboxes.  The default is 1, which disables "
        "preemptive batching.\n"

        "Packets 'sent' to a mailbox are forwarded to the receiving thread "
        "when either (a) at least mailbox_min_pkts are queued or (b) "
        "packets have been waiting at least mailbox_max_nanos.\n"

        "Note that a batch of packets can only be forwarded to the receiving "
        "thread after the previous batch of packets has been consumed.  If "
        "the receiving thread is falling behind, packets will accumulate on "
        "the send side.")

SC_ATTR(int, mailbox_max_nanos, stable, -1, "(batch_timeout_nanos)",
        "sc_mailbox",

        "Mailbox send-side batching timeout.  See mailbox_min_pkts for "
        "details.")

SC_ATTR(int, mailbox_recv_max_pkts, stable, -1, "(batch_max_pkts)",
        "sc_mailbox",

        "This attribute is used to limit the size of batches of packets "
        "emitted by the receive side of mailboxes.  When this attribute is "
        "set, packets are forwarded from the mailbox to the associated node "
        "in batches of at most mailbox_recv_max_pkts packets at a time.\n"

        "Limiting batch size can improve efficiency when the receiving thread "
        "is overloaded as large batches of packets can cause CPU caches "
        "and/or TLB to thrash.")


/**********************************************************************
 * sc_pool attributes.
 */

SC_ATTR(int, private_pool, stable, 0, NULL,
        "sc_pool,sc_vi",

        "When allocating a VI or a node that uses a buffer pool, setting this "
        "attribute to 1 ensures that a private buffer pool is used.  By "
        "default, buffer pools can be shared by multiple VIs and nodes if "
        "they are in the same thread.")

SC_ATTR(int, n_bufs_tx, deprecated, -1, NULL,
        "sc_pool",

        "Target number of packet buffers to allocate for each node that uses a "
        "buffer pool.\n"

        "This is deprecated in favour of pool_size and pool_n_bufs.  This "
        "attribute overrides pool_size and pool_n_bufs.")

SC_ATTR(int, n_bufs_tx_min, deprecated, -1, "MIN(n_bufs_tx, 128)",
        "sc_pool",

        "Minimum number of packet buffers to allocate for each node that uses "
        "a buffer pool.  If this minimum is not achieved, then an error will "
        "be raised.  (Which call will return the error is not specified).")

SC_ATTR(int, pool_n_bufs, stable, -1, "(unset; see pool_size)",
        "sc_pool",

        "The target number of buffers to allocate in a pool.\n"

        "If the pool is a private pool (see private_pool attribute) then this "
        "will set the number of buffers in the pool.  Otherwise if the pool is "
        "shared then this many buffers will be added to the pool for each node "
        "using the pool.\n"

        "This attribute overrides pool_size, and is overridden by n_bufs_tx.")

SC_ATTR(size, pool_size, stable, -1, "(depends; see description)",
        "sc_pool,sc_vi",

        "If allocating an sc_pool: The target amount of buffering to allocate "
        "in the pool.  This attribute is ignored if pool_n_bufs or n_bufs_tx "
        "is set.  If none of these attributes are set then the default is 512 "
        "buffers.\n"

        "If allocating an sc_vi: The target amount of receive buffering to "
        "allocate in the pool used by the sc_vi.  This attribute is ignored if "
        "n_bufs_rx is set.  If neither of these attributes are set "
        "then the default is 128MiB.\n"

        "If the pool is a private pool (see private_pool attribute) then this "
        "will set the size of the pool.  Otherwise if the pool is shared then "
        "the size of the pool is increased by the requested amount for each "
        "object (sc_vi or node) that uses the pool.")

SC_ATTR(int, request_huge_pages, stable, 1, NULL,
        "sc_pool",

        "Setting this attribute to 1 causes the packet pool to use explicitly "
        "allocated huge pages if available.  Even if this attribute is not "
        "set, transparent huge pages may be used if supported on the system.")

SC_ATTR(int, require_huge_pages, stable, 0, NULL,
        "sc_pool",

        "Setting this attribute to 1 causes the packet pool to only use "
        "explicitly allocated huge pages.  If enough huge pages are not "
        "available, buffer allocation fails.\n"

        "Note that setting this attribute implies request_huge_pages.")

#ifndef SC_POOL_REFILL_MAX_PKTS_DEFAULT
# define SC_POOL_REFILL_MAX_PKTS_DEFAULT      512
#endif

SC_ATTR(int, pool_refill_max_pkts, stable, 0, "(see description)",
        "sc_pool",

        "This attribute sets a limit on the number of buffers that are "
        "returned to a pool in each polling loop.\n"

        "The reason for having such a limit is to avoid spending a large "
        "amount of time on this task when a node has just freed a large "
        "number of buffers.  However, if the limit is set too low a backlog "
        "can form which increases working set size and may reduce performance."
        "\n"

        "If this attribute is not set, then the refill limit is taken from "
        "batch_max_pkts (if set) or otherwise is 512.")

#ifndef SC_DMA_PKT_BUF_LEN_STR
# define SC_STR(x)  #x
# define SC_DMA_PKT_BUF_LEN_STR  SC_STR(SC_DMA_PKT_BUF_LEN)
#endif

SC_ATTR(size, buf_size, stable, -1, SC_DMA_PKT_BUF_LEN_STR,
        "sc_pool",

        "Set the size of the payload area of packet buffers.\n"

        "Note that the default value may vary in future versions, but will be "
        "at least 1600 bytes.")

SC_ATTR(int, buf_inline, stable, -1, "(small buffers are inline)",
        "sc_pool",

        "This attribute controls how packet buffers are laid out in memory.  "
        "By default small buffers (including default-sized buffers) are "
        "allocated 'inline'.  This means that the payload buffer and "
        "sc_packet meta-data are allocated together in a single linear buffer, "
        "which ensures that meta-data and payload are in the same page.\n"

        "The alternative method allocates meta-data and payload buffers "
        "separately.  This method is suitable when buffers are large or need "
        "to be aligned on a power-of-2 boundary.")

SC_ATTR(size, pool_bin_size, beta, -1, "256KiB",
        "sc_pool",

        "This attribute controls the size of packet pool bins.\n"

        "Each pool is divided into a set of bins, each of which contains a "
        "set of buffers that are contiguous in memory.  Packet buffers are "
        "allocated from a bin sequentially in order to optimise memory access "
        "patterns and maximise TLB locality.\n"

        "The bin size contributes to the working set size because all of the "
        "packets in a bin are allocated before moving on to a new bin.  "
        "Therefore packets in a bin can only be recycled once the whole bin "
        "has been consumed.")

SC_ATTR(int, use_full_bins, hidden, 0, "0",
        "sc_pool",

        "When set, we only ever serve buffers from full bins (normally we "
        "prefer full bins but fall back to part-filled if no full bins are "
        "available).\n"

        "Note that this can lead to the pool being dry even if only a small "
        "number of buffers (one per bin) are in flight.")


/**********************************************************************
 * sc_writer attributes.
 */

SC_ATTR(int, legacy_writer, unstable, 0, "(use high-performance writer)",
        "sc_writer",

        "Select version of sc_writer node.  The default 'high performance' "
        "writer should be suitable in most cases.  It copies packets into "
        "aligned buffers before writing to disk, and uses asynchronous I/O "
        "and direct I/O where available.  A downside is that output files "
        "are not readable until closed by SolarCapture.\n"

        "Setting this attribute to 1 selects the 'legacy' writer.  It "
        "achieves a lower level of performance, but it is safe to read the "
        "output file while it is being written.\n"

        "WARNING: This attribute is likely to be removed in the near future "
        "and replaced with a node argument.")

SC_ATTR(int, n_bufs_pcap, deprecated, 5100, NULL,
        "sc_writer,sc_pcap_packer",

        "This attribute controls the number of buffers used by an sc_writer"
        "node.  See also buf_size_pcap.\n"

        "WARNING: This attribute is likely to be removed in the near future "
        "and replaced with a node argument.")

SC_ATTR(int, force_sync_writer, unstable, 0, "(use asynchronouse I/O)",
        "sc_writer,sc_perf_writer",

        "Set this attribute to 1 to disable asynchronous I/O.\n"

        "WARNING: This attribute is likely to be removed in the near future "
        "and replaced with a node argument.")

SC_ATTR(size, buf_size_pcap, unstable, 0, "32KiB",
        "sc_writer,sc_pcap_packer",

        "This attribute controls the size of buffers used by an sc_writer"
        "node.\n"

        "WARNING: This attribute is likely to be removed in the near future "
        "and replaced with a node argument.")
