#!/usr/bin/python2
'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''

######################################################################

import sys, time, os


def ip4_str_is_broadcast(ip4_str):
    return [int(i) for i in ip4_str.split('.')] == [0xff, 0xff, 0xff, 0xff]


def ip4_str_is_mcast(ip4_str):
    if not ip4_str:
        return False
    return (int(ip4_str.split('.')[0]) & 0xf0) == 0xe0 and \
        not ip4_str_is_broadcast(ip4_str)


def ip4_str_to_mac(ip4_str):
    if ip4_str_is_broadcast(ip4_str):
        return "ff:ff:ff:ff:ff:ff"
    elif ip4_str_is_mcast(ip4_str):
        ip4 = ip4_str.split('.')
        return "01:00:5e:%02x:%02x:%02x" % \
            (int(ip4[1]) & 0x7f, int(ip4[2]), int(ip4[3]))
    else:
        raise ValueError("'%s' is not broadcast or multicast" % ip4_str)


######################################################################
# main()

top = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), '..', '..'))
sys.path.append(os.path.join(top, 'src', 'python'))
import solar_capture as sc

os.putenv('SC_NODE_PATH', os.path.join(top, 'src', 'test', 'nodes'))


args = sys.argv[1:]
assert len(args) >= 1, "usage: %s <tx_intf>:<rx_intf>..." % sys.argv[0]

streams = [s.split(':') for s in args]
interactive = True
tx_bufs_per_stream = 128


scs = sc.new_session()
ctl_thrd = scs.new_thread(attr=dict(busy_wait=0))

if interactive:
    ctl_pipe = ctl_thrd.new_node('sc_fd_reader', args=dict(fd=0))
else:
    rfd, wfd = os.pipe()
    tx_rate_ctl = os.fdopen(wfd, 'w', 0)
    ctl_pipe = ctl_thrd.new_node('sc_fd_reader', args=dict(fd=rfd))

ctl_pipe = sc.connect(ctl_pipe, ctl_thrd.new_node('sc_line_reader'))
# This no-op node is only here so we can add a 'controller' link below.
# sc_line_reader cares what its outgoing link is called, but sc_no_op
# doesn't.
ctl_pipe = sc.connect(ctl_pipe, ctl_thrd.new_node('sc_no_op'))


stream_i = -1

for stream in streams:
    stream_i += 1
    tx_intf, rx_intf = stream
    rx_thrd = scs.new_thread()
    tx_thrd = scs.new_thread()

    tx_pipe = tx_thrd.new_node('sc_pool_forwarder',
                               attr=dict(n_bufs_tx=tx_bufs_per_stream))
    pg_args = dict()
    # -1 due to bug in sc_pktgen! (XXX check - is this still an issue?)
    pg_args['n'] = str(tx_bufs_per_stream - 1)
    pg_args['size'] = str(42 + 4)
    pg_args['smac'] = '00:ff:01:01:01:%02d' % stream_i
    pg_args['protocol'] = 'udp'
    pg_args['saddr'] = '172.16.133.100'
    pg_args['sport'] = '8080'
    pg_args['dport'] = '8080'
    if 0:
        pg_args['daddr'] = '224.1.1.%d' % stream_i
        pg_args['dmac'] = ip4_str_to_mac(pg_args['daddr'])
    else:
        pg_args['daddr'] = '192.168.0.%d' % (stream_i + 1)
        pg_args['dmac'] = '00:0F:53:20:8C:F0'
        pg_args['smac'] = '00:0F:53:20:8C:E0'
    tx_pipe = sc.connect(tx_pipe, tx_thrd.new_node('sc_pktgen', args=pg_args))
    repeater = tx_thrd.new_node('sc_repeater')
    tx_pipe = sc.connect(tx_pipe, repeater)

    tx_pipe = sc.connect(tx_pipe, tx_thrd.new_node('sct_seq32'))
    pacer = tx_thrd.new_node('sc_rt_pacer', args=dict(running=0))
    tx_pipe = sc.connect(tx_pipe, pacer)
    inj = tx_thrd.new_node('sc_injector',
                           args=dict(interface=tx_intf,
                                     csum_ip=1, csum_tcpudp=1),
                           attr=dict(name=tx_intf))
    tx_pipe = sc.connect(tx_pipe, inj)
    tx_pipe = sc.connect(tx_pipe, repeater, 'recycle')

    ctl_pipe = sc.connect(ctl_pipe, 'controller', pacer, 'controller')

    vi = rx_thrd.new_vi(rx_intf)
    udp_stream = 'udp:%s:%s' % (pg_args['daddr'], pg_args['dport'])
    vi.add_stream(scs.new_stream(udp_stream))
    sc.connect(vi, rx_thrd.new_node('sct_seq32_check',
                                    attr=dict(name=rx_intf)))


scs.go()

if interactive:
    while True:
        time.sleep(100000)
    sys.exit(0)

rate = 0
rate_inc = 100000
while True:
    rate += rate_inc
    tx_rate_ctl.write('%d\n' % rate)
    time.sleep(1)
