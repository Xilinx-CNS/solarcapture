#!/usr/bin/python2
'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''

######################################################################

import sys, time, os


usage_text = """
usage:
  %prog <interface> [opt=val]...

options:
  n=<num_pkts_to_send>    - set number of packets to send
  n_bufs=<n_bufs>         - set size of buffer pool
  repeat=0                - do not repeat (send only n_bufs packets)
  recycle=0               - do not recycle buffers -- repeat by copying
  pace=1                  - add sc_ts_adjust and sc_pacer nodes
  tap=1                   - inject "tap" output from sc_tap node
  tap_reliable=1          - set sc_tap "reliable" arg

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
sys.path.append(os.path.join(top, 'src', 'python'))
import solar_capture as sc

os.putenv('SC_NODE_PATH', os.path.join(top, 'src', 'test', 'nodes'))


args = sys.argv[1:]
if len(args) < 1:
    usage_err()

# Leading args without = in them give interface names.
interfaces = []
while args and '=' not in args[0]:
    interfaces.append(args.pop(0))

# Remaining args are key=val config options.
default_config = dict(n=0,
                      n_bufs=128,
                      repeat=1,
                      recycle=1,
                      pace=0,
                      tap=0,
                      tap_reliable=0)
config = dict(default_config)
for a in args:
    try:
        assert '=' in a
        exec a in dict(), config
    except:
        usage_err()
if set(config) - set(default_config):
    usage_err()

sys.stdout.write("interfaces: %s\n" % repr(interfaces))
sys.stdout.write("config: %s\n" % repr(config))


scs = sc.new_session()
thrd = scs.new_thread()

for intf in interfaces:
    pipe = thrd.new_node('sc_pool_forwarder',
                         attr=dict(n_bufs_tx=config['n_bufs']))
    if config['n'] or (config['repeat'] and config['recycle']):
        if config['repeat'] and config['recycle']:
            n = config['n_bufs']
        else:
            n = config['n']
        pipe = sc.connect(pipe, thrd.new_node('sc_pass_n', args=dict(n=n)))
    pktgen = thrd.new_node('sc_pktgen', args=dict(protocol='udp'))
    pipe = sc.connect(pipe, pktgen)
    if config['repeat']:
        repeater = thrd.new_node('sc_repeater')
        pipe = sc.connect(pipe, repeater)
        if config['n']:
            pass_n = thrd.new_node('sc_pass_n', args=dict(n=config['n']))
            pipe = sc.connect(pipe, pass_n)
    if config['pace']:
        ts_adjust = thrd.new_node('sc_ts_adjust',
                                  args=dict(start_now=1, pps=1e9))
        pacer = thrd.new_node('sc_pacer')
        pipe = sc.connect(pipe, ts_adjust)
        pipe = sc.connect(pipe, pacer)
    inj = thrd.new_node('sc_injector',
                        args=dict(interface=intf, csum_ip=1, csum_tcpudp=1))
    if config['tap']:
        reliable = config['tap_reliable']
        pipe = sc.connect(pipe, thrd.new_node('sc_tap',
                                              args=dict(reliable=reliable)))
        sc.connect(pipe, 'tap', inj)
    else:
        pipe = sc.connect(pipe, inj)
    if config['n']:
        pipe = sc.connect(pipe, thrd.new_node('sc_exit'))
    if config['repeat'] and config['recycle']:
        pipe = sc.connect(pipe, repeater, 'recycle')

scs.go()
while True:
    time.sleep(10000)
