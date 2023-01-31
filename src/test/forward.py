#!/usr/bin/python2
'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''

######################################################################

import sys, time, os


usage_text = """
usage:
  %prog <rx-intf>[/rx_core]:<tx-intf>[/tx_core]

examples:
  # Forward eth4->eth5 and eth5->eth4, single thread, any core
  %prog eth4:eth5 eth5:eth4

  # Forward eth4->eth5 using core 2 and eth5->eth4 using core 4
  %prog eth4/2:eth5/2 eth5/4:eth4/4

"""


def usage_msg(f):
    me = os.path.basename(sys.argv[0])
    f.write(usage_text.replace("%prog", me))


def usage_err():
    usage_msg(sys.stderr)
    sys.exit(1)


def get_thread(scs, core):
    core = int(core)
    if not hasattr(scs, 'core2thread'):
        scs.core2thread = dict()
    if core not in scs.core2thread:
        if core < 0:
            attr = dict()
        else:
            attr = dict(affinity_core=core)
        scs.core2thread[core] = scs.new_thread(attr=attr)
    return scs.core2thread[core]


######################################################################
# main()

top = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), '..', '..'))
sys.path.append(os.path.join(top, 'src', 'python'))
import solar_capture as sc


args = sys.argv[1:]
if len(args) < 1:
    usage_err()

scs = sc.new_session()

for arg in args:
    try:
        rx_intf, tx_intf = arg.split(':')
        if '/' in rx_intf:
            rx_intf, rx_core = rx_intf.split('/')
        else:
            rx_core = -1
        if '/' in tx_intf:
            tx_intf, tx_core = tx_intf.split('/')
        else:
            tx_core = -1
    except:
        usage_err()

    rx_thrd = get_thread(scs, rx_core)
    tx_thrd = get_thread(scs, tx_core)

    vi = rx_thrd.new_vi(rx_intf)
    vi.add_stream(scs.new_stream('all'))
    inj = tx_thrd.new_node('sc_injector', args=dict(interface=tx_intf))
    sc.connect(vi, inj)

scs.go()
while True:
    time.sleep(10000)
