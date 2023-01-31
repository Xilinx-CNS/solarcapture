#!/usr/bin/python2
'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''

######################################################################

import sys, time, os

# (You don't need these two lines in your code).
top = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), '../../..'))
sys.path.append(os.path.join(top, 'src', 'python'))

import solar_capture as sc


usage_text = """\
usage:
  %me% <interface>

description:
  Reflect packets received on an interface back to the sender.
"""


def usage_msg(strm):
    me = os.path.basename(sys.argv[0])
    strm.write(usage_text.replace('%me%', me))


def usage_err(msg=None):
    if msg:
        sys.stderr.write()
    usage_msg(strm=sys.stderr)
    sys.exit(1)


######################################################################
# main()

# Get command line arguments.
args = sys.argv[1:]
while args and args[0] and args[0][0] == '-':
    if args[0] == '-h' or args[0] == '--help':
        usage_msg(sys.stdout)
        sys.exit(0)
    else:
        usage_err()
if len(args) != 1:
    usage_err()
interface = args[0]

scs = sc.new_session()
thrd = scs.new_thread()

# Create a VI to capture received packets.  Filter out multicast and
# broadcast, and forward unicast to a reflect node and then back out of the
# same interface.
vi = thrd.new_vi(interface)
vi.add_stream(scs.new_stream("all"))
pipeline = vi
pipeline = sc.connect(pipeline, thrd.new_node('sc_filter',
                                              args=dict(bpf='not multicast')))
pipeline = sc.connect(pipeline, thrd.new_node('reflect'))
pipeline = sc.connect(pipeline, to_interface=interface)

scs.go()
while True:
    time.sleep(10000)
