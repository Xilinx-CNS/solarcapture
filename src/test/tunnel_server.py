#!/usr/bin/python2
'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''


'''
This is a server for the sc_tunnel node.
'''

import sys, os, time

top = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), '..', '..'))
sys.path.append(os.path.join(top, 'src', 'python'))
import solar_capture as sc


def usage():
    print 'Usage: python', sys.argv[0]
    sys.exit(1)


def main():
    if len(sys.argv) != 1:
        usage()

    in_file1  = '/home/kchu/build/pcap/test3.pcap'
    in_file2  = '/home/kchu/build/pcap/test3.pcap'
    in_file3  = '/home/kchu/build/pcap/test3.pcap'
    out_file1 = '/home/kchu/share/test3_out1.pcap'
    out_file2 = '/home/kchu/share/test3_out2.pcap'
    out_file3 = '/home/kchu/share/test3_out3.pcap'

    session = sc.new_session(attr={'log_level':0})
    thread  = session.new_thread()
    reader1 = thread.new_node('sc_reader', args={'filename':in_file1})
    reader2 = thread.new_node('sc_reader', args={'filename':in_file2})
    tunnel  = thread.new_node('sc_tunnel', args={'passive_open':1,
                                                'socket_fd':sys.stdin.fileno()},
                                           attr={'buf_size':10240})
    writer3 = thread.new_node('sc_writer', args={'filename':out_file3})
    exit_n  = thread.new_node('sc_exit')

    sc.connect(reader1, '', tunnel, 'file1')
    sc.connect(reader2, '', tunnel, 'file2')
    sc.connect(tunnel, 'file3', writer3)
    sc.connect(writer3, exit_n)

    session.go()

    while True:
        time.sleep(1)

if __name__ == '__main__':
    main()
