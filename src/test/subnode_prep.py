#!/usr/bin/python2
'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''

import os, sys, time, re, pprint, signal

top = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), '..', '..'))
sys.path.append(os.path.join(top, 'src', 'python'))
os.putenv('SC_NODE_PATH', os.path.join(top, 'src', 'test', 'nodes'))
import solar_capture

def main(args):
    (filename, ) = args

    session = solar_capture.new_session()
    thread = session.new_thread()

    sh = thread.new_node('sct_sh_test')
    rd = thread.new_node('sc_reader', args=dict(filename=filename))

    a = thread.new_node('sc_exit')
    b = thread.new_node('sc_exit')

    rd.connect(sh)
    sh.connect('a', a)
    sh.connect('b', b)

    session.go()
    while True:
        time.sleep(1)


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except solar_capture.SCError as e:
        print e
        sys.exit(1)
