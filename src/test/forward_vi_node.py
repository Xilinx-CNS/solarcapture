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

scs = sc.new_session()
thrd = scs.new_thread()

vis = dict()

args = sys.argv[1:]
for arg in args:
    assert '/' in arg, "expected: INTF_FROM/INTF_TO..."
    if1, if2 = arg.split('/')
    if if1 not in vis:
        vis[if1] = thrd.new_node('sc_vi_node', args=dict(interface=if1))
    if if2 not in vis:
        vis[if2] = thrd.new_node('sc_vi_node', args=dict(interface=if2))
    sc.connect(vis[if1], vis[if2])

scs.go()
while True:
    time.sleep(10000)
