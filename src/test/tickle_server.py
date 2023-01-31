#!/usr/bin/python2
'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''

######################################################################

import sys, time, os


response_body = """\
<!DOCTYPE html>
<html>
<head><title>Hello</title></head>
<body>
<h1>Hello world!</h1>
</body>
</html>
"""


def mk_response(body, keepalive):
    if keepalive:
        keepalive = 'keep-alive'
    else:
        keepalive = 'close'
    hdrs = ['HTTP/1.1 200 OK',
            'Server: SolarCapture Tickler',
            'Date: Fri, 25 Apr 2014 08:26:02 GMT',
            'Content-Type: text/plain',
            'Content-Length: %d' % len(body),
            'Last-Modified: Wed, 12 Mar 2014 10:49:38 GMT',
            'Connection: %s' % keepalive,
            ]
    hdrs = '\r\n'.join(hdrs)
    hdrs += '\r\n\r\n'
    return hdrs + body


######################################################################
# main()

top = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), '..', '..'))
sys.path.append(os.path.join(top, 'src', 'python'))
import solar_capture as sc

os.putenv('SC_NODE_PATH', os.path.join(top, 'src', 'test', 'nodes'))


import optparse
op = optparse.OptionParser()
op.add_option("-k", "--keepalive", action='store_true', default=False,
              help="Enable persistent connections")
opts, args = op.parse_args()
assert len(args) == 1, "usage: %s <interface>" % sys.argv[0]
interface = args[0]

scs = sc.new_session()
thrd = scs.new_thread()
vi = thrd.new_vi(interface)
vi.add_stream(scs.new_stream('all'))

server_args = dict(local_mac='00:0F:53:0C:03:88',
                   local_ip='dellr210h-l',
                   local_port='8088',
                   keepalive=opts.keepalive,
                   response=mk_response(response_body,
                                        keepalive=opts.keepalive),
                   log=0)
server = thrd.new_node('sct_tickler', args=server_args)

inj_args = dict(interface=interface, csum_ip=1, csum_tcpudp=1)
inj = thrd.new_node('sc_injector', args=inj_args)

sc.connect(vi, server)
sc.connect(server, "tx", inj)

scs.go()
while True:
    time.sleep(100000)
