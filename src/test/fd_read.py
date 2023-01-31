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

scs = sc.new_session()
for arg in args:
    thrd = scs.new_thread()
    pipe = thrd.new_node("sc_fd_reader", args=dict(filename=arg))
    pipe = sc.connect(pipe, thrd.new_node("sc_tracer"))
    pipe = sc.connect(pipe, thrd.new_node("sc_line_reader"))
    pipe = sc.connect(pipe, thrd.new_node("sc_tracer"))
    pipe = sc.connect(pipe, thrd.new_node("sc_exit"))

scs.go()
while True:
    time.sleep(10000)
