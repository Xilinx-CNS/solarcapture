#!/usr/bin/python2
'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''

######################################################################

import sys, time, os, subprocess, threading
from functools import partial


def usage_msg(f):
    def o(line):
        f.write(line + '\n')
    me = os.path.basename(sys.argv[0])
    o("usage:")
    o("  %s <required-params> [options]" % me)
    o("")
    o("required-params:")
    o("  replay_file=<pcap-file>       - pcap file containing packets to send")
    o("  replay_interface=<interface>  - network interface to transmit on")
    o("  rx_host=<hostname>            - host that is receiving packets")
    o("  drop_detect=<mode>            - how to detect drops on rx_host")
    o("")
    o("options:")
    o("  rx_buffer=<bytes>             - amount of buffering at receiver")
    o("  interactive=1                 - enable interactive mode")
    o("")


def usage_err(msg=None):
    if msg:
        sys.stderr.write("\nERROR: %s\n\n" % msg)
    usage_msg(sys.stderr)
    sys.exit(1)


def get_drops_netstat(sp, interface):
    sp.stdin.write("netstat -I%s\n" % interface)
    sp.stdout.readline()
    header = sp.stdout.readline().split()
    counters = sp.stdout.readline().split()
    return int(dict(zip(header, counters))['RX-DRP'])


def set_rate_Mbps(mbps):
    if mbps:
        pacer_ctl.write('bw %s\n' % (mbps * 1e6))
    else:
        pacer_ctl.write('stop\n')


def set_rate_pps(pps):
    if pps:
        pacer_ctl.write('pps %s\n' % int(pps))
    else:
        pacer_ctl.write('stop\n')


def mk_replay(filename, interface, interactive=False):
    scs = sc.new_session()
    slow_thrd = scs.new_thread(attr=dict(busy_wait=0))
    fast_thrd = scs.new_thread()

    if interactive:
        rfd = sys.stdin.fileno()
        pacer_ctl = None
    else:
        rfd, wfd = os.pipe()
        pacer_ctl = os.fdopen(wfd, 'w', 0)
    ctl_pipe = slow_thrd.new_node('sc_fd_reader', args=dict(fd=rfd))
    ctl_pipe = sc.connect(ctl_pipe, slow_thrd.new_node('sc_line_reader'))

    reader_args = dict(filename=filename, prefill='all-input')
    reader_attr = dict(n_bufs_tx=6000000, require_huge_pages=1)
    reader = slow_thrd.new_node('sc_reader', args=reader_args, attr=reader_attr)
    pkt_pipe = reader

    repeater = fast_thrd.new_node('sc_repeater')
    pkt_pipe = sc.connect(pkt_pipe, repeater)

    pacer = fast_thrd.new_node('sc_rt_pacer')
    pkt_pipe = sc.connect(pkt_pipe, pacer)
    ctl_pipe = ctl_pipe.connect(pacer, 'controller')

    pkt_pipe = sc.connect(pkt_pipe, to_interface=interface)
    pkt_pipe = sc.connect(pkt_pipe, repeater, 'recycle')

    scs.go()
    return pacer_ctl


current_rate = [0.0]
def set_rate(rate):
    if rate < current_rate[0]:
        current_rate[0] = rate
        set_rate_fn(current_rate[0])
        return
    while (rate - current_rate[0]) / rate > 0.01:
        new_rate = (rate + current_rate[0]) / 2
        current_rate[0] = new_rate
        set_rate_fn(current_rate[0])
        time.sleep(0.1)
    current_rate[0] = rate
    set_rate_fn(current_rate[0])


def run(rate, how_long, drops_start=None):
    print "run:   rate %d for %.1fs" % (rate, how_long)
    set_rate(rate)
    while how_long > 0.0:
        sleep_for = min(how_long, 1.0)
        time.sleep(sleep_for)
        how_long -= sleep_for
        if drops_start is not None:
            drops_end = get_drops_fn()
            if drops_end != drops_start:
                print "run:   %d drops" % (drops_end - drops_start)
                return drops_end
    return get_drops_fn()


def bisect_rate(set_rate_fn, get_drops_fn,
                rate_min, rate_max, interval=0.0, error=0.01,
                buffer_size=0, min_interval=1.5, max_interval=60.0,
                drain_interval=5.0):
    # Use floating point to ensure we'll converge.
    rate_min = float(rate_min)
    rate_max = float(rate_max)
    interval = float(interval)
    error = float(error)
    min_interval = float(min_interval)
    max_interval = float(max_interval)
    drain_interval = min(float(drain_interval), min_interval)

    # Must ensure that min_interval is >1s else there is a risk that drop
    # count may not change if only updated once per sec.
    assert min_interval >= 1.1

    msg = "bisect_rate: %.1f -- %.1f  interval=(%s,%s,%s) error=%s " % \
          (rate_min, rate_max, min_interval, interval, max_interval, error)
    if buffer_size:
        msg += " buffer_size=%s" % buffer_size
    print msg

    time.sleep(drain_interval)

    def accurate_interval(rate):
        if buffer_size:
            return buffer_size / (rate * error)
        else:
            return 0.0
    def test_interval(rate):
        i = interval
        if i < accurate_interval(rate):
            i = accurate_interval(rate)
        if i < min_interval:
            i = min_interval
        elif i > max_interval:
            i = max_interval
        return i

    rate_low = rate_min
    rate_high = rate_max
    rate = rate_low
    drops_end = get_drops_fn()
    while True:
        rate = rate_low + (rate_high - rate_low) / 2
        print "bisect_rate: TEST: %.1f -- %.1f" % (rate_low, rate_high)
        drops_start = drops_end
        drops_end = run(rate, test_interval(rate), drops_start)
        if drops_end - drops_start:
            rate_high = rate
            # Set rate low again; check drops stop.
            drops_start = run(0.0, drain_interval)
            drops_end = run(rate_low, drain_interval, drops_start)
            if drops_end - drops_start:
                # Still got drops at rate_low.  This means we previously
                # got a false positive.  That can happen because either (a)
                # the interval is short or (b) the rate tested was only
                # slightly above the achievable rate.
                set_rate_fn(0)
                return (rate_low - (rate_high - rate_low), rate_low, False)
        else:
            rate_low = rate

        # Do we have a result we're happy with?
        mid_pt = (rate_low + rate_high) / 2
        if float(rate_high - rate_low) < mid_pt * error:
            set_rate_fn(0)
            return (rate_low, rate_high, True)


def find_max_rate_from_below(set_rate_fn, get_drops_fn,
                             rate_start, rate_inc=0.0, rate_mul=1.01,
                             duration=60.0):
    rate_start = float(rate_start)
    rate_inc = float(rate_inc)
    rate_mul = float(rate_mul)
    duration = float(duration)

    good_rate = None
    rate = rate_start
    drops_end = get_drops_fn()

    while True:
        drops_start = drops_end
        drops_end = run(rate, duration, drops_start)
        if drops_end - drops_start:
            return good_rate
        good_rate = rate
        rate = rate * rate_mul + rate_inc


def get_param(params, name, default=None):
    v = params[name]
    if v is None:
        v = default
    return v

######################################################################
# main()

top = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), '..', '..'))
sys.path.append(os.path.join(top, 'src', 'python'))
import solar_capture as sc


required_param = dict()

params = dict(mode=required_param,
              unit="pps",
              replay_interface=required_param,
              replay_file=required_param,
              rx_host=required_param,
              drop_detect=required_param,
              rx_interface="",
              rx_buffer=0,
              error=0.01,
              range="",
              interval="",
              rate_start=20000,
              rate_mul=1.01,
              wait_time=15,
              warm_time=300,
              warm_rate=20000,
              recover_time=60)

for arg in sys.argv[1:]:
    if '=' not in arg:
        usage_err("args must be of the form key=value")
    k, v = arg.split('=', 1)
    if k not in params:
        usage_err("unknown parameter '%s'" % k)
    if params[k] is not required_param:
        v = type(params[k])(v)
    params[k] = v
missing_required_params = [v for v in params.values() if v is required_param]
if missing_required_params:
    usage_err("required parameters missing: %s" % repr(missing_required_params))


pacer_ctl = mk_replay(params['replay_file'], params['replay_interface'],
                      interactive=(params['mode'] == 'interactive'))

# Run a shell on the remote host that we can use to query drops.
sp = subprocess.Popen("ssh -T root@%s" % params['rx_host'],
                      stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                      bufsize=1, shell=True)

if params['drop_detect'].startswith('netstat:'):
    interface = params['drop_detect'].split(':', 1)[1]
    get_drops_fn = lambda : get_drops_netstat(sp, interface)
else:
    sys.stderr.write("ERROR: bad drop_detect " + \
                     "(expected netstat:<intf>)")
    sys.exit(1)

if params['unit'] == 'pps':
    set_rate_fn = set_rate_pps
elif params['unit'] == 'Mbps':
    set_rate_fn = set_rate_Mbps
else:
    usage_err("bad unit=%s" % params['unit'])


if params['mode'] == 'interactive':
    prev_drops = get_drops_fn()
    while True:
        time.sleep(1)
        drops = get_drops_fn()
        print "drops:%s" % (drops - prev_drops)
        prev_drops = drops
elif params['mode'] == 'autoramp':
    print "Allow time to startup..."
    time.sleep(params['wait_time'])
    print "Warm up..."
    drops_start = get_drops_fn()
    drops_end = run(params['warm_rate'], params['warm_time'], drops_start)
    phases = [(1.3, 45), (1.1, 30), (1.03, 20), (1.01, 60)]
    start_rate = None
    for rate_mul, duration in phases:
        if start_rate:
            print "Recover at %s..." % (start_rate / 4)
            set_rate(start_rate / 4)
            time.sleep(params['recover_time'])
        else:
            start_rate = params['rate_start']
        result = find_max_rate_from_below(set_rate_fn=set_rate_fn,
                                          get_drops_fn=get_drops_fn,
                                          rate_start=start_rate,
                                          rate_mul=rate_mul, duration=duration)
        if result is None:
            print "FAILED"
            sys.exit(2)
        start_rate = result / rate_mul
    print
    print "RESULT: %.1f" % result
elif params['mode'] == 'ramp':
    print "Allow time to startup..."
    time.sleep(params['wait_time'])
    print "Warm up..."
    drops_start = get_drops_fn()
    drops_end = run(params['warm_rate'], params['warm_time'], drops_start)
    phases = [(1.3, 45), (1.1, 30), (1.03, 20), (1.01, 60)]
    start_rate = params['rate_start']
    if params['interval']:
        duration = float(params['interval'])
    else:
        duration = 30
    result = find_max_rate_from_below(set_rate_fn=set_rate_fn,
                                      get_drops_fn=get_drops_fn,
                                      rate_start=start_rate,
                                      rate_mul=params['rate_mul'],
                                      duration=duration)
    if result is None:
        print "FAILED"
        sys.exit(2)
    print
    print "RESULT: %.1f" % result
elif params['mode'] == 'bisect':
    args = dict()
    if params['range']:
        rate_min, rate_max = [float(x) for x in params['range'].split(',')]
    else:
        rate_min, rate_max = (10, 10000)
    if params['interval']:
        args['min_interval'], args['max_interval'] = \
                [float(x) for x in params['interval'].split(',')]
    else:
        min_interval, max_interval = (120, 120)
    if params['error']:
        args['error'] = params['error']
    if params['rx_buffer']:
        args['buffer_size'] = params['rx_buffer'] * 8 / 1e6

    result = bisect_rate(set_rate_fn=set_rate_fn, get_drops_fn=get_drops_fn,
                         rate_min=rate_min, rate_max=rate_max,
                         min_interval=min_interval, max_interval=max_interval,
                         **args)
    print
    print "result:", result
    print "RESULT: %.1f" % ((result[0] + result[1]) / 2.0)
else:
    sys.stderr.write('ERROR: bad mode (expected bisect, ramp or interactive)')
    sys.exit(1)
