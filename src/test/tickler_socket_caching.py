#!/usr/bin/python2
'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''

######################################################################

import sys, time, os, optparse, subprocess, re

top = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), '..', '..'))
sys.path.append(os.path.join(top, 'src', 'python'))
import solar_capture as sc
import solar_capture.stats as stats
os.putenv('SC_NODE_PATH', os.path.join(top, 'src', 'test', 'nodes'))


req = '''\
GET /index.html HTTP/1.0
User-Agent: Wget/1.12 (linux-gnu)
Accept: */*
Host: localhost:8088

'''


def run_cmd(cmd):
    child = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    stdout = child.communicate()[0]
    assert child.returncode == 0
    return stdout


def parse_intf(intf):
    fields = [
        ('inet addr:', 'ip'),
        ('inet ',      'ip'),
        ('HWaddr ',    'mac'),
        ('ether ',     'mac'),
        ]
    d = {}
    for l in run_cmd(['ifconfig', intf]).split('\n'):
        for pat, k in fields:
            if pat in l and k not in d:
                d[k] = l.split(pat)[1].split()[0]
    return d


def mk_tickler(thrd, intf, **tickler_args):
    tickler = thrd.new_node('sct_tickler', args=tickler_args, attr=dict(
            [('name', 'tickler'), ('group_name', 'tickler')]))
    inj_args = dict(interface=intf, csum_ip=1, csum_tcpudp=1)
    inj = thrd.new_node('sc_injector', args=inj_args)
    sc.connect(tickler, 'tx', inj)
    return tickler


def mk_trigger(thrd):
    rfd, wfd = os.pipe()
    fd_reader = thrd.new_node('sc_fd_reader', args=dict(fd=rfd))
    ln_reader = sc.connect(fd_reader, thrd.new_node('sc_line_reader'))
    ts_adjust = thrd.new_node('sc_ts_adjust',
                              args=dict(start_now=1, pps=1.0))
    pacer = thrd.new_node('sc_pacer', args=dict(running=0))
    sc.connect(ln_reader, pacer, 'controller')
    sc.connect(thrd.new_node('sc_pool_forwarder'), ts_adjust)
    sc.connect(ts_adjust, pacer)
    return pacer, os.fdopen(wfd, 'w', 0)


def main():
    usage = '%prog [options] intf srv_mac srv_ip srv_port'
    op = optparse.OptionParser(usage=usage)
    op.add_option('-r', '--rate-profile', action='store',
                  default='20000,4000000,20000',
                  help='init_rate[,final_rate[,step]].  Rate per thread')
    op.add_option('-d', '--duration', action='store', default=1, type='int',
                  help='Test duration in seconds')
    opts, args = op.parse_args()
    if len(args) != 4:
        op.print_usage()
        sys.exit(1)
    intf, srv_mac, srv_ip, srv_port = args
    lcl = parse_intf(intf)

    scs = sc.new_session()
    thrd = scs.new_thread()
    vi = thrd.new_vi(intf,  attr=dict(rx_ring_max=4096))
    vi.add_stream(scs.new_stream('eth:%s' % lcl['mac']))

    tickler = mk_tickler(thrd, intf, local_mac=lcl['mac'], local_ips=lcl['ip'],
                         local_ports='1024-65534', server_mac=srv_mac,
                         server=srv_ip, server_port=srv_port,
                         request=req.replace('\n', '\r\n'))
    sc.connect(vi, tickler)
    trigger, ctl = mk_trigger(thrd)
    sc.connect(trigger, tickler, 'trigger')
    scs.go()

    scs_stat_dir = stats.find_session_dirs_for_process(os.getpid()).pop()
    scs_stats = stats.Session(scs_stat_dir)
    tickler_stats = [x for x in scs_stats.object_list
                     if (isinstance(x, stats.Node) and
                         x.node_type_name == 'sct_tickler')]
    assert len(tickler_stats) == 1
    tickler_stats = tickler_stats[0]
    stat_fields = ['tx_syn', 'tx_msg', 'tx_ack', 'tx_fin', 'rx_msg',
                   'rx_msg_psh', 'rx_msg_dup', 'rx_ack', 'rx_bytes',
                   'not_for_me', 'latency']
    stats_prev = [(f, v) for (f, v) in tickler_stats.get_all_fields()
                  if f in stat_fields]
    print '#' + '\t'.join(stat_fields)

    rates = map(int, opts.rate_profile.split(','))
    if len(rates) >= 2:
        rates[1] += 1
        rates = range(*rates)
    for r in rates:
        ctl.write('%s\n' % r)
        time.sleep(opts.duration)
        tickler_stats.update_fields()
        stats_cur = [(f, v) for (f, v) in tickler_stats.get_all_fields()
                      if f in stat_fields]
        to_print = [(c - p) / opts.duration for ((f1,p), (f2,c)) in
                    zip(stats_prev, stats_cur) if f1 == f2]
        to_print = map(str, to_print);
        print '\t'.join(to_print)
        stats_prev = stats_cur


if __name__ == '__main__':
    main()
