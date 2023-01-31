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


usage_text = """
usage:
  %prog% [options] <source> <sink> <num_consumers>

source:
  <interface-name> or sc:<node_spec>

sink:
  <shm-path-prefix> or sc:<node_spec>

"""


def usage_msg(f):
    prog = os.path.basename(sys.argv[0])
    f.write(usage_text.replace('%prog%', prog))


def usage_err():
    usage_msg(sys.stderr)
    sys.exit(1)


def main():
    import optparse
    op = optparse.OptionParser()
    op.add_option("-m", "--mode", action='store', default='estimate',
                  help="Set sc_flow_balancer mode")
    op.add_option("-c", "--copy-mode", action='store', default='copy',
                  help="Set sc_flow_balancer copy_mode")
    opts, args = op.parse_args()

    if len(args) != 3:
        usage_err()
    source = args[0]
    sink = args[1]
    n_consumers = int(args[2])

    scs = sc.new_session()
    cap_thrd = scs.new_thread()
    bal_thrd = cap_thrd
    exp_thrd = cap_thrd

    if source.startswith('sc:'):
        src = cap_thrd.new_node_from_str(source[3:])
    else:
        vi_attr = dict()
        vi_attr['unpack_packed_stream'] = (opts.copy_mode == 'zc')
        src = cap_thrd.new_vi(source, attr=vi_attr)
        src.add_stream(scs.new_stream('all'))
    fb_args = dict(mode=opts.mode, copy_mode=opts.copy_mode)
    flow_bal = bal_thrd.new_node('sc_flow_balancer', args=fb_args)
    sc.connect(src, flow_bal)

    for i in range(n_consumers):
        if sink.startswith('sc:'):
            sink_node = exp_thrd.new_node_from_str(sink[3:])
        else:
            path = "%s-%d" % (sink, i)
            sink_node = exp_thrd.new_node('sc_shm_export', args=dict(path=path))
        sc.connect(flow_bal, sink_node)

    scs.go()
    while True:
        time.sleep(10000)


if __name__ == '__main__':
    main()
