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

    n_bufs = 25*1024
    pd = sc.PD(intf)
    memory = sc.Memory(t0, (1<<11) * n_bufs)
    memreg = sc.MemReg(t0, pd, memory)

    pcap0 = sc.PcapNode(t0, {'filename':filename + '_0', 'snaplen':60})
    pcap1 = sc.PcapNode(t1, {'filename':filename + '_1', 'snaplen':60})

    vi_set = sc.ViSet(pd, 2, filters=sc.Filter('all'))
    vi0 = sc.VI(t0, vi_set, refill_batch_size=32, n_ef_events=64, evq_size=4096,
                rxq_size=2048, n_bufs=n_bufs / 2, node=pcap0)
    vi1 = sc.VI(t1, vi_set, refill_batch_size=32, n_ef_events=64, evq_size=4096,
                rxq_size=2048, n_bufs=n_bufs / 2, node=pcap1)

    sc.go()
    while True:
        stats.print_stats(os.getenv('SC_LOG_DIRECTORY',
                                    '/var/tmp/solar_capture_%d' % os.getpid()))
        time.sleep(1)


if __name__ == '__main__':
    main()
