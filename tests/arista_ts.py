#!/usr/bin/python2
'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''

'''
This test app checks the functionality of the sc_arista_ts SolarCapture node.

                           keyframes
VI ---------> sc_arista_ts ---------> sc_rate_monitor ---------> free
                   |\
                   | \
                   |  --------------> sc_rate_monitor ---------> free
   everything else |       un-synced
                   |
                   |
                   v
              sc_rate_monitor ---------------------------------> free

With the -t option, the "everything else" sc_rate_monitor is replaced by an
sc_tracer, and another sc_tracer sits between the VI and the sc_arista_ts node.

Behaviour can be verified by checking the output of solar_capture_monitor:
packets should be observed on the "keyframes" path at the rate at which the
switch sends them; other packets should at first follow the "un-synced" path,
and then (with occasional exceptions as un-syncable packets arrive or the sync
is lost briefly) should follow the "everything else" path. The tracing should
show that timestamps are being adjusted in a consistent fashion.
'''

import sys, os, time, signal, getopt

top = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), '..'))
if os.path.exists(os.path.join(top, 'src', 'python', 'solar_capture')):
    sys.path.append(os.path.join(top, 'src', 'python'))
import solar_capture as sc


def usage():
    print >> sys.stderr, 'Usage:', sys.argv[0], '[-t] interface'
    sys.exit(1)


def main():
    try:
        optlist, args = getopt.getopt(sys.argv[1:], 't')
    except getopt.GetoptError:
        usage()

    if len(args) != 1:
        usage()

    tracing = '-t' in [t[0] for t in optlist]
    intf = args[0]

    sc_session = sc.new_session()
    thread = sc_session.new_thread()

    arista_ts = thread.new_node('sc_arista_ts',
                                args={'log_level': 'errors',
                                      'kf_ip_dest': '255.255.255.255', 
                                      'kf_eth_dhost': 'ff:ff:ff:ff:ff:ff'})

    rate_kf      = thread.new_node('sc_rate_monitor',
                                   attr={'name': 'keyframes'})
    rate_no_sync = thread.new_node('sc_rate_monitor',
                                   attr={'name': 'un-synced'})

    # Node arrangement varies a bit depending on whether we're tracing: if so,
    # an extra sc_tracer sits between the VI and the sc_arista_ts node, and
    # re-timestamped packets go to another tracer; if not, those latter packets
    # go to an sc_rate_monitor instead.
    if tracing:
        pre_tracer   = thread.new_node('sc_tracer', attr={'name': 'in'})
        node_default = thread.new_node('sc_tracer', attr={'name': 'out'})
        first_node   = pre_tracer
        sc.connect(pre_tracer, arista_ts)
    else:
        node_default = thread.new_node('sc_rate_monitor',
                                        attr={'name': 're-timestamped'})
        first_node   = arista_ts

    sc.connect(arista_ts, 'keyframes', rate_kf)
    sc.connect(arista_ts, 'no_sync',   rate_no_sync)
    sc.connect(arista_ts, '',          node_default)

    vi = thread.new_vi(intf)
    vi.add_stream(sc_session.new_stream('all'))
    sc.connect(vi, first_node)

    sc_session.go()

    while True:
        time.sleep(10000)


if __name__ == '__main__':
    main()
