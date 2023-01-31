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
  %me% <source-interface> <dest-interface> <bpf-filter>

description:
  Forward packets from source-interface to dest-interface.  Packets
  matching the filter are discarded.  The filter is specified using BPF
  syntax.  (See 'man pcap-filter').

examples:
  # Forward from eth1 to eth2, blocking packets to/from TCP port 80.
  %me% eth1 eth2 "tcp port 80"

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
if len(args) != 3:
    usage_err()
if_in = args[0]
if_out = args[1]
bpf_filter = args[2]

scs = sc.new_session()
thrd = scs.new_thread()

# Create a VI to capture received packets.  Forward them via an sc_filter
# node to the destination interface.
vi = thrd.new_vi(if_in)
vi.add_stream(scs.new_stream("all"))
filter = thrd.new_node('sc_filter', args=dict(bpf=bpf_filter))
sc.connect(vi, filter)
sc.connect(filter, 'not_matched', to_interface=if_out)

scs.go()
while True:
    time.sleep(10000)
