#!/usr/bin/python2
'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''

######################################################################

import sys, time, os

top = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), '..', '..'))
os.putenv('SC_NODE_PATH', os.path.join(top, 'src', 'test', 'nodes'))
sys.path.append(os.path.join(top, 'src', 'python'))
import solar_capture as sc


for i in range(10):
    scs = sc.new_session()
    thrd = scs.new_thread()
    pipe = thrd.new_node("sc_pool_forwarder")
    pipe = pipe.connect(thrd.new_node("sc_pass_n", args=dict(n=1)))
    pipe = pipe.connect(thrd.new_node("sc_exit", args=dict(exit_code=123)))
    exit_code = scs.run()
    assert exit_code == 123
    del(scs)
