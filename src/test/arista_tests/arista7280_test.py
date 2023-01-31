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
    'output_pcap' : None,
    'realtime' : 0,
    'rollover_window_ms': None,
    'filter_oui': None,
    'strip_ticks': -1,
    'ts_format': None,
    'ts_src_mac': -1,
    'replacement_src_mac': None,
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


def main(pcap_file, n_bufs, buf_size, pps, output_pcap, realtime,
         rollover_window_ms, filter_oui, strip_ticks, ts_format, ts_src_mac,
         replacement_src_mac):
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

    arista_args = {'switch_model': '7280'}
    if rollover_window_ms is not None:
        arista_args['rollover_window_ms'] = rollover_window_ms
    if filter_oui is not None:
        arista_args['filter_oui'] = filter_oui
    if strip_ticks >= 0:
        arista_args['strip_ticks'] = strip_ticks
    if ts_format is not None:
        arista_args['ts_format'] = ts_format
    if ts_src_mac >= 0:
        arista_args['ts_src_mac'] = ts_src_mac
    if replacement_src_mac is not None:
        arista_args['replacement_src_mac'] = replacement_src_mac

    arista = thread.new_node('sc_arista_ts', args=arista_args)
    pipe = pipe.connect(arista)
    ex = thread.new_node('sc_exit')

    if output_pcap:
        writer_args = dict(filename=output_pcap, format='pcap-ns')
        pipe = pipe.connect(thread.new_node('sc_writer', args=writer_args))
    pipe.connect(ex)

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
        if opts[k] is not None:
            opts[k] = type(opts[k])(v)
        else:
            opts[k] = v

    main(pcap_file, **opts)
