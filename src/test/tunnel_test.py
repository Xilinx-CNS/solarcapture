#!/usr/bin/python2
'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''


'''
This is a test for the sc_tunnel node.
'''

import sys, os, time

top = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), '..', '..'))
sys.path.append(os.path.join(top, 'src', 'python'))
import solar_capture as sc


def usage():
    print 'Usage: python', sys.argv[0], '<passive/active>', \
        'in_file1 in_file2 in_file3', 'out_file2 out_file2 out_file3'
    sys.exit(1)


def main():
    if len(sys.argv) != 8:
        usage()

    in_file1 = sys.argv[2]
    in_file2 = sys.argv[3]
    in_file3 = sys.argv[4]
    out_file1 = sys.argv[5]
    out_file2 = sys.argv[6]
    out_file3 = sys.argv[7]

    session = sc.new_session()
    thread  = session.new_thread()
    exit_n  = thread.new_node('sc_exit')

    if sys.argv[1] == 'passive':
        reader1 = thread.new_node('sc_reader', args={'filename':in_file1})
        reader2 = thread.new_node('sc_reader', args={'filename':in_file2})
        tunnel  = thread.new_node('sc_tunnel', args={'passive_open':1,
                                                     'server_port':'4500'},
                                               attr={'buf_size':10240})
        writer3 = thread.new_node('sc_writer', args={'filename':out_file3})
        sc.connect(reader1, '', tunnel, 'file1')
        sc.connect(reader2, '', tunnel, 'file2')
        sc.connect(tunnel, 'file3', writer3)
        sc.connect(tunnel, '#exit', exit_n)
        sc.connect(writer3, exit_n)
    else:
        reader3 = thread.new_node('sc_reader', args={'filename':in_file3})
        tunnel  = thread.new_node('sc_tunnel', args={'passive_open':0,
                                                     'server_name':'localhost',
                                                     'server_port':'4500'},
                                               attr={'buf_size':10240})
        writer1 = thread.new_node('sc_writer', args={'filename':out_file1})
        writer2 = thread.new_node('sc_writer', args={'filename':out_file2})
        sc.connect(reader3, '', tunnel, 'file3')
        sc.connect(tunnel, 'file1', writer1)
        sc.connect(tunnel, 'file2', writer2)
        sc.connect(tunnel, '#exit', exit_n)
        sc.connect(writer1, exit_n)
        sc.connect(writer2, exit_n)

    session.go()

    while True:
        time.sleep(1)

if __name__ == '__main__':
    main()
