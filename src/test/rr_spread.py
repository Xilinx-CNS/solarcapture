#!/usr/bin/python2
'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''

######################################################################

import sys, time, os

top = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), '..', '..'))
sys.path.append(os.path.join(top, 'src', 'python'))
import solar_capture as sc


args = sys.argv[1:]
assert len(args) == 1
n_workers = int(args[0])

thrd_attr = dict(busy_wait=0)

scs = sc.new_session()
thrd = scs.new_thread(attr=thrd_attr)

src = thrd.new_node('sc_pool_forwarder')
src = src.connect(thrd.new_node('sct_seq32', args=dict(offset=0)))
src = src.connect(thrd.new_node('sc_rr_spreader'))

sink = thrd.new_node('sc_rr_gather')
sink.connect(thrd.new_node('sct_seq32_check', args=dict(offset=0)))

for i in range(n_workers):
    wthrd = scs.new_thread(attr=thrd_attr)
    worker = wthrd.new_node('sc_sim_work', args=dict(per_packet_ns=1000000))
    sc.connect(src, worker)
    sc.connect(worker, sink)

scs.go()
while True:
    time.sleep(10000)
