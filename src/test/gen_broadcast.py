#!/usr/bin/python2
'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''


'''
This is a test for the sc_shm_broadcast node using synthetically
generated packets.
'''

import sys, os, time

top = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), '..', '..'))
sys.path.append(os.path.join(top, 'src', 'python'))
import solar_capture as sc


PS_BUFFER_SIZE = 65536 # (maximum) size of packed-stream buffers


usage_text = """
usage:
  %s <shm_path> [options]

options:
  filename=...          - write packets to file
  pktgen=0              - disable initialisation of packet content
  pps=<rate>            - limit packet rate
  pack=1                - use packed-stream format
  max_channels=<n>      - set max number of channels

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

    filename = ""
    pktgen = 1
    pps = 0.0
    pack = 0
    max_channels = 1
    for arg in args:
        try:
            key, val = arg.split('=', 1)
            exec "%s = type(%s)('%s')" % (key, key, val)
        except:
            raise
            usage_err()

    scs = sc.new_session()
    thrd = scs.new_thread()
    pipe = thrd.new_node('sc_pool_forwarder')

    if pktgen:
        pipe = pipe.connect(thrd.new_node('sc_pktgen',
                                          args=dict(protocol='udp',
                                                    size='600')))

    if pps:
        pipe = pipe.connect(thrd.new_node('sc_ts_adjust',
                                          args=dict(start_now=1, pps=pps)))
        pipe = pipe.connect(thrd.new_node('sc_pacer'))

    if pack:
        pipe = pipe.connect(thrd.new_node('sc_ps_packer',
                                          attr=dict(buf_size=PS_BUFFER_SIZE)))

    if filename:
        pipe = pipe.connect(thrd.new_node('sc_writer',
                                          args=dict(filename=filename)))

    pipe = pipe.connect(thrd.new_node('sc_shm_broadcast',
                                      args=dict(path=shm_path,
                                                max_channels=max_channels)))

    scs.go()
    while True:
        time.sleep(10000)


if __name__ == '__main__':
    main(sys.argv[1:])
