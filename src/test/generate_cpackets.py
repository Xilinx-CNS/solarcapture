#! /usr/bin/python2
'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''

import os, sys, time, select
top = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), '..', '..'))
sys.path.append(os.path.join(top, 'src', 'python'))
import solar_capture

class Pipeline(object):
    tail = None
    def __init__(self, thread):
        self.thread = thread

    def add(self, name, attr={}, **args):
        node = self.thread.new_node(name, args=args, attr=attr)
        if self.tail:
            self.tail.connect(node)
        self.tail = node

#Generates some random packets with cpacket timestamps attached
def main(size=60, pps=100, output_file='/tmp/cpacket_test_output.pcap'):
    session = solar_capture.new_session()
    pipeline = Pipeline(session.new_thread())
    print "Outputting pcap to %s" % output_file

    pipeline.add('sc_pool_forwarder')
    pipeline.add('sc_pktgen', size=str(size), pps=str(pps))
    pipeline.add('sc_range_filter', range='-1000')
    pipeline.add('sc_cpacket_encap')
    pipeline.add('sc_writer', filename=output_file)
    pipeline.add('sc_exit')

    session.go()
    while True:
        time.sleep(1)


if __name__ == '__main__':
    args = {}
    for arg in sys.argv[1:]:
        if '=' in arg:
            k, v = arg.split('=', 1)
            if v.isdigit():
                v = int(v)
            args[k] = v

    main(**args)
