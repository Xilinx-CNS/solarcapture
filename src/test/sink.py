#!/usr/bin/python2
'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''

######################################################################

import sys, time, os


usage_text = """
usage:
  %prog <interface>... [opt=val]...

interface:
  <interface-name>
  sc:<node-spec>

options:
  cap_core=CPU_CORE   - set CPU core for capture thread
  work_core=CPU_CORE  - set CPU core for work thread
  stream=STREAM       - one or more streams to capture separated by ';'
  cap_mon=1           - monitor capture performance with sc_rate_monitor
  work_mon=1          - monitor worker performance with sc_rate_monitor
  tracer=1            - add sc_tracer node
  bpf=BPF_FILTER      - filter packets
  work_ns=NS          - simulate NS nanoseconds of work per packet
  touch_metadata=1    - touch packet metadata
  touch_payload=1     - touch packet payload
  sink=NODE_SPEC      - send packets to a custom node

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


known_args = [
    'cap_core',
    'work_core',
    'stream',
    'cap_mon',
    'work_mon',
    'bpf',
    'work_ns',
    'touch_wrapper',
    'touch_payload',
    'tracer',
    'sink',
    ]


args = sys.argv[1:]
config = dict()
interfaces = []
for arg in args:
    if arg.startswith('sc:'):
        interfaces.append(arg)
    elif '=' in arg:
        k, v = arg.split('=', 1)
        config[k] = v
    else:
        interfaces.append(arg)

bad_args = set(config.keys()).difference(known_args)
if bad_args:
    usage_err()
if len(interfaces) <= 0:
    usage_err()

cap_core = int(config.get('cap_core', -1))
work_core = int(config.get('work_core', -2))

scs = sc.new_session()
cap_thrd = scs.new_thread(attr=dict(affinity_core=cap_core))
if work_core == cap_core or True:
    work_thrd = cap_thrd
else:
    work_thrd = scs.new_thread(attr=dict(affinity_core=work_core))

for intf in interfaces:
    if intf.startswith('sc:'):
        source = cap_thrd.new_node_from_str(intf[3:])
    else:
        source = cap_thrd.new_vi(intf)
        streams = config.get('stream', 'all').split(';')
        for stream in streams:
            source.add_stream(sc.Stream(stream))
    pipeline = source

    if int(config.get('cap_mon', 0)):
        mon = cap_thrd.new_node('sc_rate_monitor',
                                attr=dict(name='cap-%s' % intf))
        pipeline = sc.connect(pipeline, mon)

    bpf = config.get('bpf', 0)
    if bpf:
        bpfn = work_thrd.new_node('sc_filter', args=dict(bpf=bpf))
        pipeline = sc.connect(pipeline, bpfn)

    work_ns = int(config.get('work_ns', 0))
    touch_wrapper = int(config.get('touch_wrapper', 0))
    touch_payload = int(config.get('touch_payload', 0))
    if work_ns or touch_wrapper or touch_payload:
        work = work_thrd.new_node('sc_sim_work',
                                  args=dict(per_packet_ns=work_ns,
                                            touch_wrapper=touch_wrapper,
                                            touch_payload=touch_payload))
        pipeline = sc.connect(pipeline, work)

    if int(config.get('work_mon', 0)):
        mon = work_thrd.new_node('sc_rate_monitor',
                                 attr=dict(name='work-%s' % intf))
        pipeline = sc.connect(pipeline, mon)

    if int(config.get('tracer', 0)):
        pipeline = sc.connect(pipeline, work_thrd.new_node('sc_tracer'))

    if config.get('sink', None):
        misc_node = work_thrd.new_node_from_str(config['sink'])
        pipeline = sc.connect(pipeline, misc_node)

    if pipeline == source:
        # We have to connect the source to something!
        pipeline = sc.connect(pipeline, work_thrd.new_node('sc_no_op'))


scs.go()
while True:
    time.sleep(10000)
