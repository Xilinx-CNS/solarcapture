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


def main():
    if len(sys.argv) != 3:
        print 'Usage:', sys.argv[0], 'interface filename'
        sys.exit(1)

    intf = sys.argv[1]
    filename = sys.argv[2]

    t0 = sc.Thread()
    t1 = sc.Thread()
    t2 = sc.Thread()

    s0 = sc.MboxNode(t0, t1, 's0')
    s1 = sc.MboxNode(t1, t2, 's1')
    s2 = sc.MboxNode(t2, t0, 's2')
    r0 = sc.MboxNode(t1, t0, 'r0')
    r1 = sc.MboxNode(t2, t1, 'r1')
    r2 = sc.MboxNode(t0, t2, 'r2')
    sc.mbox_connect(s0, r0)
    sc.mbox_connect(s1, r1)
    sc.mbox_connect(s2, r2)

    n_bufs = 25 * 1024
    pd = sc.PD(intf)
    memory = sc.Memory(t0, (1<<11) * n_bufs)
    memreg = sc.MemReg(t0, pd, memory)

    pcap = sc.PcapNode(t2, {'filename':filename, 'snaplen':60})
    refill = sc.ViRefillerNode(t0, r2)

    r0.set_recv(s1)
    r1.set_recv(pcap)

    vi = sc.VI(t0, pd, refill_batch_size=32, n_ef_events=64, evq_size=4096,
               rxq_size=2048, n_bufs=n_bufs, node=s0,
               filters=sc.Filter('all'))

    sc.go()
    while True:
        stats.print_stats(os.getenv('SC_LOG_DIRECTORY',
                                    '/var/tmp/solar_capture_%d' % os.getpid()))
        time.sleep(1)


if __name__ == '__main__':
    main()
