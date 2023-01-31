#!/usr/bin/python2
'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''

######################################################################

import sys, time, os


def mk_stdin_line_reader():
    stdin_fd = 0
    stdin_node = thrd.new_node('sc_fd_reader', args=dict(fd=stdin_fd))
    line_rdr = thrd.new_node('sc_line_reader')
    sc.connect(stdin_node, line_rdr)
    return line_rdr


######################################################################
# main()

top = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), '..', '..'))
sys.path.append(os.path.join(top, 'src', 'python'))
import solar_capture as sc


args = sys.argv[1:]
print args
fname_in, interface = args

scs = sc.new_session()
thrd = scs.new_thread()

reader_args = dict(filename=fname_in, prefill='all-input')
reader = thrd.new_node('sc_reader', args=reader_args)
pipeline = reader

if 0:
    ts_adjust_args = dict(start_now=1, pps=10)
    ts_adjust = thrd.new_node('sc_ts_adjust', args=ts_adjust_args)
    pipeline = sc.connect(pipeline, ts_adjust)

repeater = None
if 1:
    repeater = thrd.new_node('sc_repeater')
    pipeline = sc.connect(pipeline, repeater)

if 0:
    ts_adjust_args = dict(start_now=1)
    ts_adjust = thrd.new_node('sc_ts_adjust', args=ts_adjust_args)
    pipeline = sc.connect(pipeline, ts_adjust)

    if 1:
        line_rdr = mk_stdin_line_reader()
        sc.connect(line_rdr, ts_adjust, "controller")

if 0:
    #ts_adjust_args = dict(start_now=1, offset=2, speedup=.1)
    ts_adjust_args = dict(offset=2, speedup=.1)
    ts_adjust = thrd.new_node('sc_ts_adjust', args=ts_adjust_args)
    pipeline = sc.connect(pipeline, ts_adjust)

if 0:
    tracer = thrd.new_node('sc_tracer')
    pipeline = sc.connect(pipeline, tracer)

if 0:
    pacer = thrd.new_node('sc_pacer')
    pipeline = sc.connect(pipeline, pacer)

if 1:
    pacer = thrd.new_node('sc_rt_pacer')
    pipeline = sc.connect(pipeline, pacer)
    line_rdr = mk_stdin_line_reader()
    sc.connect(line_rdr, pacer, "controller")

if 0:
    limiter = thrd.new_node('sc_token_bucket_shaper',
                            args=dict(max_pps=1.3e6, show_config=1))
    pipeline = sc.connect(pipeline, limiter)

if 0:
    fname_out = interface
    writer = thrd.new_node('sc_writer', args={'filename':fname_out})
    pipeline = sc.connect(pipeline, writer)
else:
    pipeline = sc.connect(pipeline, to_interface=interface)

if 1:
    pipeline = sc.connect(pipeline, thrd.new_node('sc_exit'))

if repeater and 1:
    pipeline = sc.connect(pipeline, repeater, "recycle")

scs.go()
while True:
    time.sleep(10000)
