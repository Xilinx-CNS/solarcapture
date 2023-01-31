#!/usr/bin/env python
'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''

"""
Test script for a pair of processes connected via shm_import/shm_export.

Start server with:
  shm_channel <path>
  shm_channel <path> ext_io_demux
Then start client with:
  shm_channel <path> client

 * Server has a pktgen which pushes 1 pkt/s down the shm
 * Client receives these  and hexdumps them to screen
 * Data on either side's stdin is pushed to other side over control channel
 * server -> client ctl msgs are just hexdumped
 * client -> server ctl msgs open/close a stopcock node, pausing the flow of
   packets over the shm
"""
import os
import sys
import struct
import signal
import time

top = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), '..', '..'))
sys.path.append(os.path.join(top, 'src', 'python'))
os.putenv('SC_NODE_PATH', os.path.join(top, 'src', 'test', 'nodes'))
import solar_capture


def make_pipe(thread, line_reader=True):
    r_fd, w_fd = os.pipe()
    node = thread.new_node('sc_fd_reader', args={'fd': r_fd})
    if line_reader:
        lr_args = {'lstrip': 0, 'rstrip': 0, 'strip_blank': 0, 'add_nul': 0}
        line_reader = thread.new_node('sc_line_reader', args=lr_args)
        node = node.connect(line_reader)
    return w_fd, node


def client_setup(session, thread, shm_path):
    """Sets up a shm_import connected to a node which hexdumps all
    packets. Also provides an FD which users can use to send control
    messages to the server."""
    # Incoming packets over shm are sent to a dump node
    import_args = {'path': shm_path, 'reliable': 1}
    shm_import = thread.new_node('sc_shm_import', args=import_args)
    shm_dump = thread.new_node('sct_dump_pkts', args={'label': 'shm'})
    sc_exit = thread.new_node('sc_exit')
    shm_import.connect(shm_dump).connect(sc_exit)

    # Incoming ctl messages from server go to another dump node
    ctl_dump = thread.new_node('sct_dump_pkts', args={'label': 'ctl'})
    shm_import.connect('ctl', ctl_dump)

    # Each line the user writes to w_fd is sent as a ctl message to server
    w_fd, line_reader = make_pipe(thread)
    line_reader.connect(shm_import, 'ctl')
    return w_fd


def server_setup(session, thread, shm_path, use_ext_ctl, connection_check):
    """Sets up a packet source connected to shm_export via a stopcock.
    Incoming control messages from client can close/open the stopcock,
    pausing and resuming packet flow over the shm."""
    fwd = thread.new_node('sc_pool_forwarder')
    pktgen = thread.new_node('sc_pktgen', args={'pps': '1', 'size': '60'})
    pacer = thread.new_node('sc_pacer')
    ctl_sc = thread.new_node('sc_stopcock')
    conn_id = thread.new_node('sct_connection_id')
    shm_export = thread.new_node('sc_shm_export', args={'path': shm_path, 'use_ext_ctl': use_ext_ctl, 'check_conn_id': connection_check })
    sc_exit = thread.new_node('sc_exit')

    # Add a second stopcock for end-of-stream handling
    eos_w_fd, eos_reader = make_pipe(thread, line_reader=False)
    eos_sc = thread.new_node('sc_stopcock')
    eos_reader.connect(eos_sc, 'ctl')

    (fwd.connect(pktgen).connect(pacer).connect(ctl_sc).connect(conn_id).
     connect(eos_sc).connect(shm_export).connect(sc_exit))
    if use_ext_ctl:
        io_demux = thread.new_node('sc_io_demux', args={'listen': 'unix:' + shm_path + '_sock' })
        io_demux.connect("shm_ctl", shm_export, "shm_ctl")
        shm_export.connect("shm_ctl", io_demux, "shm_ctl")

    # Incoming ctl messages from client go to stopcock and then are hexdumped
    ctl_dump = thread.new_node('sct_dump_pkts', args={'label': 'ctl'})
    if use_ext_ctl:
        io_demux.connect('ctl', ctl_sc, 'ctl')
    else:
        shm_export.connect('ctl', ctl_sc, 'ctl')
    ctl_sc.connect('ctl', ctl_dump)

    # Each line the user writes to w_fd is sent as a ctl message to client
    w_fd, line_reader = make_pipe(thread)
    w_fd_conn, line_reader_conn = make_pipe(thread)
    if use_ext_ctl:
        line_reader.connect(io_demux, 'ctl')
    else:
        line_reader.connect(shm_export, 'ctl')

    line_reader_conn.connect(conn_id, 'ctl')

    def signal_handler(signum, frame):
        print "Received signal", signum
        os.close(eos_w_fd)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    return w_fd, w_fd_conn


def main(shm_path, client=0, use_ext_ctl=0, connection_check=0):
    session = solar_capture.new_session()
    thread = session.new_thread()
    if client:
        w_fd = client_setup(session, thread, shm_path)
    else:
        w_fd, w_fd_conn = server_setup(session, thread, shm_path, use_ext_ctl, connection_check)

    session.go()
    time.sleep(1)

    buffer = ''
    while True:
        try:
            buffer += os.read(sys.stdin.fileno(), 1024)
        except OSError:
            continue
        while '\n' in buffer:
            data, buffer = buffer.split('\n', 1)
            if not data:
                continue
            if client:
                if data not in ['0', '1']:
                    print "ERROR: expected '0' or '1'"
                    continue
                data = struct.pack('i', 1 if data == '0' else 0)
                os.write(w_fd, data + '\n')
            else:
                msg = data.split(' ')
                if msg[0] == 'conn':
                    if len(msg) != 2 or not msg[1].isdigit():
                        print 'ERROR: expected conn <id>'
                        continue
                    data = struct.pack('i', int(msg[1]))
                    os.write(w_fd_conn, data + '\n')
                else:
                    os.write(w_fd, data + '\n')




if __name__ == '__main__':
    if len(sys.argv) < 2:
        print "USAGE:", sys.argv[0], "<shm_path> [client]"
        sys.exit(1)
    try:
        socket_path = sys.argv[1]
        opts = {}
        for arg in sys.argv[2:]:
            if '=' not in arg:
                arg += '=1'
            k, v = arg.split('=', 1)
            if v.isdigit():
                v = int(v)
            opts[k] = v
        main(socket_path, **opts)
    except solar_capture.SCError as e:
        print e
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(0)
