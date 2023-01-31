#!/usr/bin/python2
'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''


'''
This is a test for the sc_shm_broadcast node. The test expects mmap_path to be
a hugetlbfs location.
'''

import sys, os, time

top = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), '..', '..'))
sys.path.append(os.path.join(top, 'src', 'python'))
import solar_capture as sc


def usage():
    print 'Usage: python', sys.argv[0], 'interface capture_file ', \
        'shm_path busy_wait'
    sys.exit(1)


def main():
    if len(sys.argv) != 5:
        usage()

    intf     = sys.argv[1]
    filename = sys.argv[2]
    mmap_path = sys.argv[3]
    busy_wait = sys.argv[4]

    sc_tg = sc.new_session()

    t_attr = {}
    t_attr['busy_wait'] = busy_wait
    t0 = sc_tg.new_thread(attr=t_attr)
    t1 = sc_tg.new_thread(attr=t_attr)

    writer = t1.new_node('sc_writer', args={'filename':filename})

    attr={}
    attr['unpack_packed_stream'] = 0

    vi = t0.new_vi(intf, attr=attr)
    broadcast_n = t1.new_node('sc_shm_export',
                              args={'path':mmap_path})
    # Add the streams we want to capture.  This vi will capture all traffic to
    # its interface.
    vi.add_stream(sc_tg.new_stream('all'))


    sc.connect(vi, writer)
    sc.connect(writer, broadcast_n)

    # Once we have created the necessary components, and linked them together
    # as desired, we kick off the actual packet handling.
    sc_tg.go()

    while True:
        time.sleep(10000)

if __name__ == '__main__':
    main()
