#! /usr/bin/python2
'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''

#
# This script injects data from a pcap file into the sc_arista_ts node.
# It is expected that the pcap file contains data captured from an arista
# switch, including both keyframes and arista-timestamped packets.
#
# Memory permitting, you should set n_bufs and buf_size to large enough
# values to read the entire pcap file into memory - otherwise the rate at
# which we can inject packets into the arista node will be disk-bandwidth
# limited.

import os, sys, time

top = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), '..', '..'))
sys.path.insert(0, os.path.join(top, 'src', 'python'))
import solar_capture


DEFAULT_OPTS = {
    'n_bufs': 1000,
    'buf_size': -1,
    'pps': 0,
    'output_pcap': None,
    'discard_keyframes': 1,
    'realtime': 0,
    'log_level': 'verbose',
    'kf_ip_dest': '255.255.255.255',
    'kf_eth_dhost': '',
    'strip_ticks': -1,
    'has_fcs': -1,
}


def usage_msg(s):
    s.write("usage:\n")
    s.write("  %s <pcap_file> [option=value ...]\n" % (sys.argv[0]))
    s.write("\n")
    s.write("options:\n")
    for k, v in DEFAULT_OPTS.items():
        s.write("  %s (default %r)\n" % (k, v))


def usage_err():
    usage_msg(sys.stderr)
    sys.exit(1)


def main(pcap_file, n_bufs, buf_size, pps, output_pcap, kf_ip_dest, kf_eth_dhost,
         discard_keyframes, realtime, log_level, strip_ticks,
         has_fcs):
    session = solar_capture.new_session()
    thread = session.new_thread()

    reader_args = dict(filename=pcap_file)
    if realtime or pps:
        reader_args['prefill'] = 'all-input'
    reader_attr = {'n_bufs_tx': n_bufs, 'buf_size': buf_size}
    reader = thread.new_node('sc_reader', args=reader_args, attr=reader_attr)
    pipe = reader

    if realtime or pps:
        ts_args = {'start_now': 1}
        if pps:
            ts_args['pps'] = pps
        tsa = thread.new_node('sc_ts_adjust', args=ts_args)
        pacer = thread.new_node('sc_pacer')
        pipe = pipe.connect(tsa).connect(pacer)

    arista_args = {'kf_ip_dest': kf_ip_dest, 'log_level': log_level, 'switch_model': '7150'}
    if kf_eth_dhost:
        arista_args['kf_eth_dhost'] = kf_eth_dhost
    if has_fcs >= 0:
        arista_args['has_fcs'] = has_fcs
    if strip_ticks >= 0:
        arista_args['strip_ticks'] = strip_ticks
    arista = thread.new_node('sc_arista_ts', args=arista_args)
    pipe = pipe.connect(arista)
    ex = thread.new_node('sc_exit')
    if discard_keyframes:
        solar_capture.connect(arista, 'keyframes', ex)

    if output_pcap:
        writer_args = dict(filename=output_pcap, format='pcap-ns')
        pipe = pipe.connect(thread.new_node('sc_writer', args=writer_args))
    pipe = pipe.connect(ex)

    session.go()
    while True:
        time.sleep(1)


if __name__ == '__main__':
    args = sys.argv[1:]
    if '-h' in args or '--help' in args:
        usage_msg(sys.stdout)
        sys.exit(0)

    if len(args) < 1:
        usage_err()
    pcap_file = args[0]
    if not os.path.isfile(pcap_file):
        usage_err()

    opts = dict(DEFAULT_OPTS)
    for arg in args[1:]:
        if '=' not in arg:
            usage_err()
        k, v = arg.split('=', 1)
        if k not in opts:
            usage_err()
        opts[k] = type(opts[k])(v)

    main(pcap_file, **opts)
