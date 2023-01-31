#!/usr/bin/python2
'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''

######################################################################

import sys, time, os


######################################################################
# main()

top = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), '..', '..'))
sys.path.append(os.path.join(top, 'src', 'python'))
import solar_capture as sc


args = sys.argv[1:]
assert len(args) == 1
ranges = args[0]

scs = sc.new_session()
thrd = scs.new_thread()

pipe = thrd.new_node('sc_fd_reader', args=dict(fd=sys.stdin.fileno()))
pipe = pipe.connect(thrd.new_node('sc_line_reader', args=dict(add_new_line=1)))
pipe = pipe.connect(thrd.new_node('sc_range_filter',
                                  args=dict(range=ranges, debug=1)))
pipe = pipe.connect(thrd.new_node('sc_fd_writer',
                                  args=dict(fd=sys.stdout.fileno())))
pipe = pipe.connect(thrd.new_node('sc_exit'))

scs.go()
while True:
    time.sleep(10000)
