#! /usr/bin/python2
'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''

import os, sys, time, select
top = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), '..', '..'))
sys.path.append(os.path.join(top, 'src', 'python'))
import solar_capture

# Takes in an input pcap and generates an output pcap, with the packets repeated
# X times where X is specified using n_repeats=X.

class Pipeline(object):
    tail = None
    def __init__(self, thread):
        self.thread = thread

    def add(self, name, attr={}, **args):
        node = self.thread.new_node(name, args=args, attr=attr)
        if self.tail:
            self.tail.connect(node)
        self.tail = node
        return node


def main(input_file=None, output_file=None, n_repeats=0, recycle=False):
    session = solar_capture.new_session()
    pipeline = Pipeline(session.new_thread())
    if input_file == None:
        print "No input file, set with input_file= argument"
        return
    if output_file == None:
        output_file = ''.join(input_file.split('.')[0:-1]) + '_repeats' + \
                      '.' + input_file.split('.')[-1]
    print "Reading from %s, writing with repeats to %s" % \
                (input_file, output_file,)
    pipeline.add('sc_reader', attr={'n_bufs_tx': 1000000}, filename=input_file, prefill='all-input')
    repeater = pipeline.add('sc_repeater', n_repeats=n_repeats)
    pipeline.add('sc_writer', filename=output_file)
    ex = pipeline.add('sc_exit')
    if recycle:
        ex.connect(repeater, "recycle")

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
