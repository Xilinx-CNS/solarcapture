#!/usr/bin/python2
'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''


import sys, time, os

top = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), '..', '..'))
os.putenv('SC_NODE_PATH', os.path.join(top, 'src', 'test', 'nodes'))
sys.path.append(os.path.join(top, 'src', 'python'))
import solar_capture as sc


args = sys.argv[1:]
assert len(args) == 2
input_interface = args[0]
output_filename = args[1]

output_file = open(output_filename, 'w')
output_fd = output_file.fileno()

scs = sc.new_session()
thrd = scs.new_thread()
if ':' in input_interface:
    pipe = thrd.new_node_from_str(input_interface)
else:
    pipe = thrd.new_vi(input_interface)
    pipe.add_stream(scs.new_stream('all'))
pipe = pipe.connect(thrd.new_node('sc_pcap_packer'))
pipe = pipe.connect(thrd.new_node('sc_tracer'))
pipe = pipe.connect(thrd.new_node('sc_fd_writer', args=dict(fd=output_fd)))
pipe = pipe.connect(thrd.new_node('sc_exit'))
scs.go()
while True:
    time.sleep(10000)
