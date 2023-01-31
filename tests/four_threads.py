#!/usr/bin/python2
'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''


import sys, optparse, time, os
sys.path.append('../src/python')
sys.path.append('../src')
import solar_capture as sc
import solar_capture.stats as stats


if __name__ == '__main__':
    n_bufs = 25*1024

    t0 = sc.Thread()
    t1 = sc.Thread()
    t2 = sc.Thread()
    t3 = sc.Thread()

    pd0 = sc.PD('eth2')
    memory0 = sc.Memory(t0, (1<<11) * n_bufs)
    memreg0 = sc.MemReg(t0, pd0, memory0)

    pd1 = sc.PD('eth3')
    memory1 = sc.Memory(t1, (1<<11) * n_bufs)
    memreg1 = sc.MemReg(t1, pd1, memory1)

    fwd0 = sc.CounterNode(t0)
    fwd1 = sc.CounterNode(t1)
    counter0 = sc.CounterNode(t2)
    counter1 = sc.CounterNode(t2)
    pcap = sc.PcapNode(t3, {'filename':'/dev/null', 'snaplen':60})
    r2_refill = sc.ViRefillerNode(t0)
    r5_refill = sc.ViRefillerNode(t1)

    sc.connect_nodes(fwd0, 'sender0', counter0)
    sc.connect_nodes(fwd1, 'sender1', counter1)
    sc.connect_nodes(counter0, 'sender2', pcap)
    sc.connect_nodes(counter1, 'sender3', pcap)

    sc.connect_threads(t1=t3, t2_node=r2_refill)
    sc.connect_threads(t1=t3, t2_node=r5_refill)

    vi0 = sc.VI(t0, pd0, refill_batch_size=32, n_ef_events=64, evq_size=4096,
                rxq_size=2048, n_bufs=n_bufs, node=fwd0,
                filters=sc.Filter('all'))
    vi1 = sc.VI(t1, pd1, refill_batch_size=32, n_ef_events=64, evq_size=4096,
                rxq_size=2048, n_bufs=n_bufs, node=fwd1,
                filters=sc.Filter('all'))

    sc.go()
    while True:
        stats.print_stats(os.getenv('SC_LOG_DIRECTORY',
                                    '/var/tmp/solar_capture_%d' % os.getpid()))
        time.sleep(1)
