#!/usr/bin/python2
'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''


import os, sys, time

top = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), '..', '..'))
os.putenv('SC_NODE_PATH', os.path.join(top, 'src', 'test', 'nodes'))
sys.path.append(os.path.join(top, 'src', 'python'))
import solar_capture as sc


args = sys.argv[1:]
assert len(args) == 0

scs = sc.new_session()
t1 = scs.new_thread()
t2 = scs.new_thread()

pipe = t1.new_node('sct_sender')
pipe = sc.connect(pipe, t1.new_node('sc_ts_adjust',
                                    args=dict(start_now=1, pps=20)))
pipe = sc.connect(pipe, t1.new_node('sc_pacer'))
pipe = sc.connect(pipe, t2.new_node('sc_sim_work',
                                    args=dict(per_packet_ns=int(.1e9))))

scs.go()
while True:
    time.sleep(10000)
