#!/usr/bin/python2
'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''


'''
This is a test for the sc_shm_import node. It attaches to a shared
memory export for a running instance of SolarCapture and writes the output
to a pcap file
'''

import sys, os, time, signal

top = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), '..', '..'))
sys.path.append(os.path.join(top, 'src', 'python'))
import solar_capture as sc


usage_text = """
usage:
  %s <shm_path> [options]

options:
  packed=1              - set attribute unpack_packed_stream=0
  filename=...          - write packets to file
  reliable=1            - back-pressure if we fall behind
  tracer=1              - add sc_tracer node to pipeline
  work=2000             - add sc_sim_work node with 2000ns work per packet
  exit=0                - do not add sc_exit node at end of pipeline
  busy_wait=0           - create busy_wait thread
"""


def usage_msg(f):
    me = os.path.basename(sys.argv[0])
    f.write(usage_text % me)


def usage_err():
    usage_msg(sys.stderr)
    sys.exit(1)


def main(args):
    if len(args) < 1:
        usage_err()
    shm_path = args[0]
    args = args[1:]

    packed = 0
    filename = ""
    reliable = 0
    tracer = 0
    work = 0
    exit = 1
    busy_wait = 1
    for arg in args:
        try:
            key, val = arg.split('=', 1)
            exec "%s = type(%s)('%s')" % (key, key, val)
        except:
            raise
            usage_err()

    scs = sc.new_session()
    t_attr = dict()
    t_attr['busy_wait'] = busy_wait
    thrd = scs.new_thread(attr=t_attr)

    attr = dict()
    if packed:
        attr['unpack_packed_stream'] = 0
    pipe = thrd.new_node('sc_shm_import',
                         args=dict(path=shm_path, reliable=reliable),
                         attr=attr)
    if filename:
        pipe = pipe.connect(thrd.new_node('sc_writer',
                                          args=dict(filename=filename)))
    if work:
        pipe = pipe.connect(thrd.new_node('sc_sim_work',
                                          args=dict(per_packet_ns=work)))
    if tracer:
        pipe = pipe.connect(thrd.new_node('sc_tracer'))
    if exit:
        pipe = pipe.connect(thrd.new_node('sc_exit'))

    scs.go()
    while True:
        time.sleep(10000)


if __name__ == '__main__':
    main(sys.argv[1:])
