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
def main(input_file=None, output_file=None, fcs_present=None):
    session = solar_capture.new_session()
    pipeline = Pipeline(session.new_thread())
    if input_file == None:
        print "No input file, set with input_file= argument"
        return
    if fcs_present == 'true':
        fcs_present = True
    elif fcs_present == 'false':
        fcs_present = False
    elif fcs_present == None:
        fcs_present = -1;
    else:
        print "fcs_present should be true, false or not set"
        return
    if output_file == None:
        output_file = ''.join(input_file.split('.')[0:-1]) + '_cpackets' + \
                      '.' + input_file.split('.')[-1]
    print "Reading from %s, writing with cpacket timestamps to %s" % \
                (input_file, output_file,)
    pipeline.add('sc_reader', filename=input_file)
    pipeline.add('sc_cpacket_encap', fcs_present=fcs_present)
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
