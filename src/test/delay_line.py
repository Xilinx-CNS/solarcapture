#!/usr/bin/python2
'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''

######################################################################

import sys, time, os


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

def usage():
    print 'Usage: python', sys.argv[0], \
        ' <rx_intf>/<core>:<tx_intf>/<core>:[[num_cons]:[[min_delay]:[max_delay]]]\n\n' \
        ' To setup a simple passthough bidirectionally one would use\n' \
        , sys.argv[0], \
        ' ethX:ethY:1:0 ethY:ethX:1:0\n\n' \
        ' To setup a more complex cpu pinned and multiple delay line on both directions\n' \
        , sys.argv[0], \
        ' ethX/0:ethY/1:10:20:250 ethY/2:ethX/3:2:50:100\n'
    sys.exit(1)

top = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), '..', '..'))
sys.path.append(os.path.join(top, 'src', 'python'))
import solar_capture as sc


args = sys.argv[1:]
if len(args) < 1:
    usage()

scs = sc.new_session()

for arg in args:
    params = arg.split(':')
    num_params = len(params)

    if num_params == 5:
        num_lines = int(params[2])
        delay = '%s-%s' % (params[3], params[4])
    if num_params == 4:
        delay = params[3]
        num_lines = int(params[2])
    if num_params == 3:
        num_lines = int(params[2])
        if num_lines == 1:
            delay = '100'
        else:
            delay = '100-200'
    if num_params == 2:
        num_lines = 10
        delay = '100-200'
    if num_params <= 1:
        print 'Not enough params for instance'
        usage()

    rx_intf = params[0]
    tx_intf = params[1]

    if '/' in rx_intf:
        rx_intf, rx_core = rx_intf.split('/')
    else:
        rx_core = -1
    if '/' in tx_intf:
        tx_intf, tx_core = tx_intf.split('/')
    else:
        tx_core = -1

    rx_thrd = get_thread(scs, rx_core)
    tx_thrd = get_thread(scs, tx_core)

    vi = rx_thrd.new_vi(rx_intf, attr=dict(force_sw_timestamps=1, rx_ring_max=4096, n_bufs_rx=640000, n_bufs_rx_min=160000))
    vi.add_stream(scs.new_stream('all'))
    inj = tx_thrd.new_node('sc_injector', args=dict(interface=tx_intf))

    print 'Rx=%s' % rx_intf
    print 'Tx=%s' % tx_intf

    if num_lines == 1 and delay == '0':
        sc.connect(vi, inj)

        print 'Passthrough'
    else:
        dl = tx_thrd.new_node('sc_delay_line',
                              args=dict(num_lines=num_lines, msec=delay))
        sc.connect(vi, dl)
        sc.connect(dl, inj)

        print 'DLs=%d' % num_lines
        print 'delay_range=%s' % delay

scs.go()
while True:
    time.sleep(10000)
