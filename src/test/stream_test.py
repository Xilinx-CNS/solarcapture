#!/usr/bin/python2
'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''


'''
This is a app for testing the different types of streams that
SolarCapture supports.
'''

import os, sys, time

top = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), '..', '..'))
sys.path.append(os.path.join(top, 'src', 'python'))
import solar_capture as sc


def usage():
    print 'Usage: python', sys.argv[0], \
        'interface <siena|ef10-low-latency|ef10-full-feature>'
    sys.exit(1)


def try_stream(intf, stream):
    sc_tg = sc.new_session(attr={'log_level': 0})
    thread = sc_tg.new_thread()
    vi = thread.new_vi(intf)
    vi.add_stream(sc_tg.new_stream(stream))


def main():
    if len(sys.argv) != 3:
        usage()

    streams = [
        'all',

        'udp:1.1.1.1:1',
        'ip_protocol=udp,dhost=1.1.1.1,dport=2',
        'udp,dhost=1.1.1.1,dport=3',
        'ip_protocol=udp,dhost=1.1.1.1,dport=1,shost=1.1.1.1,sport=1',
        'udp,dhost=1.1.1.1,dport=2,shost=1.1.1.1,sport=1',

        'tcp:1.1.1.1:1',
        'ip_protocol=tcp,dhost=1.1.1.1,dport=2',
        'tcp,dhost=1.1.1.1,dport=3',
        'ip_protocol=tcp,dhost=1.1.1.1,dport=1,shost=1.1.1.1,sport=1',
        'tcp,dhost=1.1.1.1,dport=2,shost=1.1.1.1,sport=1',

        'eth:00:0F:53:21:15:50',
        'dmac=00:0F:53:21:15:51',

        'eth:vid=1,00:0F:53:21:15:50',
        'dmac=00:0F:53:21:15:51,vid=2'
        ]

    streams_ef10 = [
        'mismatch',
        ]

    streams_ef10_full = [
        'udp:vid=2,239.1.2.3:12345',
        'udp:vid=1,172.16.130.109:12345,239.1.2.3:12345',
        'tcp:vid=1,239.1.2.3:12345',
        'tcp:vid=1,172.16.130.109:12345,239.1.2.3:12345',
        ]

    intf = sys.argv[1]
    if sys.argv[2] == 'ef10-low-latency':
        streams += streams_ef10
    if sys.argv[2] == 'ef10-full-feature':
        streams += streams_ef10 + streams_ef10_full

    failures = 0
    for s in streams:
        if os.fork() == 0:
            try_stream(intf, s)
            sys.exit(0)
        else:
            pid, rc = os.wait()
            if rc != 0:
                print "FAIL: %r (pid=%d rc=%d)" % (s, pid, rc)
                failures += 1
            else:
                print "PASS: %r" % s

    sys.exit(failures)


if __name__ == '__main__':
    main()
