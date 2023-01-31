#!/usr/bin/python2
'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''

######################################################################

import sys, time, os


usage_text = """
usage:
  %prog [options]

options:
  threads=2             - Create a separate thread for injection and/or export
  tx_interface=...      - Inject packets on given interface
  shm_path=...          - Create shm export at given path
  n_packets=...         - Stop after given number of packets
"""


def usage_msg(f):
    me = os.path.basename(sys.argv[0])
    f.write(usage_text.replace("%prog", me))


def usage_err():
    usage_msg(sys.stderr)
    sys.exit(1)


######################################################################
# main()

top = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), '..', '..'))
os.putenv('SC_NODE_PATH', os.path.join(top, 'src', 'test', 'nodes'))
sys.path.append(os.path.join(top, 'src', 'python'))
import solar_capture as sc


args = sys.argv[1:]
threads = 1
tx_interface = ""
shm_path = ""
n_packets = 0
for arg in args:
    try:
        key, val = arg.split('=', 1)
        exec "%s = type(%s)('%s')" % (key, key, val)
    except:
        usage_err()
        raise

scs = sc.new_session()
t1 = scs.new_thread()
if threads > 1:
    t2 = scs.new_thread()
else:
    t2 = t1

# Give sct_sender larger packet pool than sct_wrap so that we stress
# sct_wrap running out of buffers.
pipe = t1.new_node('sct_sender', attr=dict(n_bufs_tx=1024))
if n_packets > 0:
    pipe = sc.connect(pipe, t1.new_node('sc_pass_n', args=dict(n=n_packets)))
pool_attr = dict(buf_size=0, n_bufs_tx=512, private_pool=1)
pipe = sc.connect(pipe, t1.new_node('sct_wrap', attr=pool_attr))
if shm_path is not "":
    pipe = sc.connect(pipe, t2.new_node('sc_shm_broadcast',
                                        args=dict(path=shm_path)))
if tx_interface is not "":
    pipe = sc.connect(pipe, t2.new_node('sc_injector',
                                        args=dict(interface=tx_interface)))
pipe = sc.connect(pipe, t2.new_node('sc_exit'))

scs.go()
while True:
    time.sleep(10000)
