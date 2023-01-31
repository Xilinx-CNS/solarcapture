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
assert len(args) == 0

scs = sc.new_session()
thrd = scs.new_thread()
thrd.new_node('sct_always_busy')
pipe = thrd.new_node('sc_fd_reader', args=dict(fd=0))
pipe = sc.connect(pipe, thrd.new_node('sc_line_reader'))
pipe = sc.connect(pipe, thrd.new_node('sc_tracer'))
scs.go()
while True:
    time.sleep(10000)
