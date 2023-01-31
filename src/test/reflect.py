#!/usr/bin/python2
'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''

######################################################################

import sys, time, os


######################################################################
# main()

top = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), '..', '..'))
sys.path.append(os.path.join(top, 'src', 'python'))
import solar_capture as sc


args = sys.argv[1:]
assert len(args) == 1
interface = args[0]

scs = sc.new_session()
thrd = scs.new_thread()
vi = thrd.new_vi(interface)
vi.add_stream(scs.new_stream('all'))
sc.connect(vi, vi)
scs.go()
while True:
    time.sleep(10000)
