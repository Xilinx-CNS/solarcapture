#!/usr/bin/python2
'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''


import sys, time, os

top = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), '..', '..'))
os.putenv('SC_NODE_PATH', os.path.join(top, 'src', 'test', 'nodes'))
sys.path.append(os.path.join(top, 'src', 'python'))
import solar_capture as sc


args = sys.argv[1:]
assert len(args) >= 1
cores = [int(a) for a in args]
n_hops = len(cores)

scs = sc.new_session()

c2t = dict([(c, scs.new_thread(attr=dict(affinity_core=c))) \
                for c in set(cores)])
thrds = [c2t[c] for c in cores]

thrd = thrds[0]
sct_sender = thrd.new_node('sct_sender', args=dict(n=1))
pipeline = sct_sender

repeater = thrd.new_node('sc_repeater')
pipeline = sc.connect(pipeline, repeater)

if n_hops > 1:
    thrd = thrds[1]
mipg = thrd.new_node('sct_measure_ipg', args=dict(exit=1, iter=10000000))
pipeline = sc.connect(pipeline, mipg)

for i in range(n_hops - 2):
    touch = thrds[i+2].new_node('sct_touch')
    pipeline = sc.connect(pipeline, touch)

sc.connect(pipeline, repeater, 'recycle')

scs.go()
while True:
    time.sleep(10000)
