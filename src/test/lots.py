#!/usr/bin/python2
'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''

######################################################################

import os, sys, signal, time

top = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), '..', '..'))
sys.path.insert(0, os.path.join(top, 'src', 'python'))
import solar_capture as sc


def test_lots_of_pools():
    scs = sc.new_session()
    thread = scs.new_thread()
    noop = thread.new_node('sc_no_op')
    for pf in [thread.new_node('sc_pool_forwarder') for i in range(250)]:
        sc.connect(pf, noop)
    scs.go()
    while 1:
        time.sleep(100)


signal.signal(signal.SIGINT, signal.SIG_DFL)
test_lots_of_pools()
