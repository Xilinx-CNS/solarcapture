#!/usr/bin/python2
'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''

import os, sys, time, re, pprint, signal

top = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), '..', '..'))
sys.path.append(os.path.join(top, 'src', 'python'))
import solar_capture

ARGS = {'pktgen': {'pps': '1', 'size': None},
        'tracer': {'mode': None}}
def main(f=None, **node_args):
    args = {}
    for node, defaults in ARGS.items():
        args.setdefault(node, {})
        for key, default in defaults.items():
            if key in node_args:
                args[node][key] = node_args.pop(key)
            elif default is not None:
                args[node][key] = default
    if node_args:
        print "ERROR: Unknown arg '%s'" % (node_args.keys()[0])
        sys.exit(1)

    session = solar_capture.new_session()
    thread = session.new_thread()

    if f:
        pipeline = thread.new_node('sc_fd_reader', args={'filename': f})
    else:
        fwd = thread.new_node('sc_pool_forwarder')
        pktgen = thread.new_node('sc_pktgen', args=args['pktgen'])
        pacer = thread.new_node('sc_pacer')
        pipeline = fwd.connect(pktgen).connect(pacer)

    tracer = thread.new_node('sc_tracer', args=args['tracer'])
    sc_exit = thread.new_node('sc_exit')
    pipeline.connect(tracer).connect(sc_exit)

    session.go()
    while True:
        time.sleep(1)

if __name__ == '__main__':
    args = {}
    for arg in sys.argv[1:]:
        if '=' not in arg:
            arg += '=1'
        k, v = arg.split('=', 1)
        args[k] = v
    main(**args)
