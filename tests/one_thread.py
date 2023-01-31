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

    n_bufs = 25*1024
    t = sc.Thread()
    pd = sc.PD(intf)
    memory = sc.Memory(t, (1<<11) * n_bufs)
    mr = sc.MemReg(t, pd, memory)

    node = sc.PcapNode(t, {'filename':filename, 'snaplen':60})
    sc.VI(t, pd, refill_batch_size=32, n_ef_events=64, evq_size=4096,
          rxq_size=2048, n_bufs=n_bufs, node=node, filters=sc.Filter('all'))

    sc.go()
    while True:
        stats.print_stats(os.getenv('SC_LOG_DIRECTORY',
                                    '/var/tmp/solar_capture_%d' % os.getpid()))
        time.sleep(1)


if __name__ == '__main__':
    main()
