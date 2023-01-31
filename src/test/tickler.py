#!/usr/bin/python2
'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''

######################################################################

import sys, time, os


good_req = """\
GET /index.html HTTP/1.0
User-Agent: Wget/1.12 (linux-gnu)
Accept: */*
Host: localhost:8088

"""

bad_req = """\
GET /index.html HTTP/1.0
User-Agent: WordPress/3 (linux-gnu)
Accept: */*
Host: localhost:8088

"""


def mk_stdin_line_reader(strip_blank=1):
    stdin_fd = 0
    stdin_node = thrd.new_node('sc_fd_reader', args=dict(fd=stdin_fd))
    line_rdr = thrd.new_node('sc_line_reader',
                             args=dict(strip_blank=strip_blank))
    sc.connect(stdin_node, line_rdr)
    return line_rdr


def mk_client(thrd, req, ips, server_port, log=0, name=None):
    if '\r\n' not in req:
        req = req.replace('\n', '\r\n')
    tcpcl_args = dict(local_mac='00:0F:53:0C:03:90',
                      local_ips=ips,
                      local_ports='1024-65534',
                      server_mac='00:0F:53:0C:03:88',
                      server='dellr210h-l',
                      server_port=str(server_port),
                      request=req,
                      log=log)
    tcpcl = thrd.new_node('sct_tickler', args=tcpcl_args,
                          attr=dict(name=name))

    inj_args = dict(interface='eth4', csum_ip=1, csum_tcpudp=1)
    inj = thrd.new_node('sc_injector', args=inj_args)

    sc.connect(tcpcl, "tx", inj)
    return tcpcl


def mk_interactive_trigger(thrd, fd=0):
    ctl = thrd.new_node('sc_fd_reader', args=dict(fd=fd))
    ctl = sc.connect(ctl, thrd.new_node('sc_line_reader'))
    ts_adjust = thrd.new_node('sc_ts_adjust',
                              args=dict(start_now=1, pps=1.0))
    pacer = thrd.new_node('sc_pacer', args=dict(running=0))
    sc.connect(ctl, pacer, 'controller')
    sc.connect(thrd.new_node('sc_pool_forwarder'), ts_adjust)
    sc.connect(ts_adjust, pacer)
    return pacer


def mk_scripted_trigger(thrd, script=None, fd=None, stdin=False):
    if script:
        ctl = thrd.new_node('sc_mem_reader', args=dict(str=script))
        ctl = sc.connect(ctl, thrd.new_node('sc_line_reader'))
    elif stdin:
        ctl = mk_stdin_line_reader()
    elif fd is not None:
        ctl = thrd.new_node('sc_fd_reader', args=dict(fd=fd))
        ctl = sc.connect(ctl, thrd.new_node('sc_line_reader'))
    else:
        assert False

    pacer = thrd.new_node('sc_pacer')
    ts_adjust = thrd.new_node('sc_ts_adjust',
                              args=dict(start_now=1))
    sc.connect(ctl, ts_adjust, 'controller')
    sc.connect(thrd.new_node('sc_pool_forwarder'), ts_adjust)
    sc.connect(ts_adjust, pacer)
    return pacer


def mk_pipe_trigger(thrd):
    rfd, wfd = os.pipe()
    return mk_interactive_trigger(thrd, rfd), wfd


def pause_and_exit(n_sec, exit_code=0):
    for i in range(n_sec, 0, -1):
        sys.stderr.write("\r%d " % i)
        time.sleep(1)
    sys.stderr.write("\n")
    sys.exit(exit_code)


######################################################################
# main()

top = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), '..', '..'))
sys.path.append(os.path.join(top, 'src', 'python'))
import solar_capture as sc

os.putenv('SC_NODE_PATH', os.path.join(top, 'src', 'test', 'nodes'))


args = sys.argv[1:]
assert len(args) == 1, "usage: %s <mode>" % sys.argv[0]
mode = args[0]

supported_modes = [
    'good',
    'bad',
    'ddos',
    'interactive',
    'interactive_bad',
    'interactive_ddos'
    ]
if mode not in supported_modes:
    sys.stderr.write("ERROR: mode must be one of:\n  " +
                     '\n  '.join(supported_modes) + '\n')
    sys.exit(1)

scs = sc.new_session()
thrd = scs.new_thread()
vi = thrd.new_vi('eth4')
vi.add_stream(scs.new_stream('all'))
in_pipe = vi

bad_ctl = None
good_ctl = None

if 'ddos' in mode or 'bad' in mode:
    bad_client = mk_client(thrd, bad_req, "192.168.0.1-192.168.127.254",
                           server_port=8088, name='baad')
    in_pipe = sc.connect(in_pipe, bad_client)
    if 'interactive' in mode:
        trigger = mk_interactive_trigger(thrd)
    else:
        trigger, bad_fd = mk_pipe_trigger(thrd)
        bad_ctl = os.fdopen(bad_fd, 'w', 0)
    sc.connect(trigger, bad_client, "trigger")

if 'bad' not in mode:
    good_client = mk_client(thrd, good_req, "192.168.128.1-192.168.254.254",
                            server_port=8088, name='good')
    in_pipe = sc.connect(in_pipe, good_client)
    if 'interactive' in mode and 'ddos' not in mode:
        trigger = mk_interactive_trigger(thrd)
    else:
        trigger, good_fd = mk_pipe_trigger(thrd)
        good_ctl = os.fdopen(good_fd, 'w', 0)
    sc.connect(trigger, good_client, "trigger")

scs.go()

ddos_good_rate = 40000

try:
    if 'ddos' in mode:
        good_ctl.write('%s\n' % ddos_good_rate)
        ctl = bad_ctl
    elif 'bad' in mode:
        ctl = bad_ctl
    else:
        ctl = good_ctl

    if 'interactive' in mode:
        while True:
            time.sleep(100000)
    else:
        init_rate = 1000
        rates = range(2000, 300000+1, 2000)
        rates = range(20000, 4000000+1, 20000)

        ctl.write('%s\n' % init_rate)
        time.sleep(5)
        for rate in rates:
            ctl.write('%s\n' % rate)
            time.sleep(1)
        time.sleep(1)
        if good_ctl:
            good_ctl.write('stop\n')
        if bad_ctl:
            bad_ctl.write('stop\n')
        pause_and_exit(10)
except KeyboardInterrupt:
    sys.stderr.write("\nInterrupted...hold on...stopping...\n")
    if good_ctl:
        good_ctl.write('stop\n')
    if bad_ctl:
        bad_ctl.write('stop\n')
    pause_and_exit(10)
