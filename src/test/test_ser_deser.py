#!/bin/python2
'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''

import solar_capture as sc
import sys
import os
import select
import struct


def make_pipe_in(thread, attr):
    r_fd, w_fd = os.pipe()
    node = thread.new_node('sc_fd_reader', args={'fd': r_fd,
                                                 'fill_buffers': 1},
                           attr=attr)
    return w_fd, node


def make_pipe_out(thread, attr):
    r_fd, w_fd = os.pipe()
    node = thread.new_node('sc_fd_writer', args={'fd': w_fd}, attr=attr)
    return r_fd, node


def create_serialise_deserialise_pipe(session, thread, ser_buf_size,
                                      deser_buf_size, buf_size, metadata_len):
    attr = {'buf_size': buf_size}
    w_fd, pkt_in_node = make_pipe_in(thread, attr)
    serialiser = thread.new_node('sct_pkt_serialiser', attr={'buf_size': ser_buf_size}, args={'metadata_len': metadata_len})
    deserialiser = thread.new_node('sct_pkt_deserialiser', attr={'buf_size': deser_buf_size})
    r_fd, pkt_out_node = make_pipe_out(thread, attr)
    pkt_in_node.connect(deserialiser).connect(serialiser).connect(pkt_out_node)
    return w_fd, r_fd


def main(ser_buf_size, deser_buf_size, buf_size, metadata_len):
    serialise_formatter = struct.Struct(format='=IIHQIH')
    hdr_size = serialise_formatter.size
    session = sc.new_session()
    thread = session.new_thread()
    w_fd, r_fd = create_serialise_deserialise_pipe(session, thread, ser_buf_size,
                                                   deser_buf_size, buf_size, metadata_len)
    session.go()
    buffer = ''
    output = ''
    print 'Enter <metadata> <data>'
    while True:
        to_read, _, _ = select.select([r_fd, sys.stdin.fileno()], [], [])
        if sys.stdin.fileno() in to_read:
            buffer += os.read(sys.stdin.fileno(), 1024)
            while '\n' in buffer:
                msg, buffer = buffer.split('\n', 1)
                if ' ' in msg:
                    metadata, data = msg.split(' ', 1)
                    metadata = metadata.ljust(metadata_len, ' ')
                else:
                    metadata = ''.ljust(metadata_len, ' ')
                    data = msg
                serialised_hdr = serialise_formatter.pack(len(data), metadata_len, 0, 0, 0, 0)
                serialised_message = serialised_hdr + metadata + data
                os.write(w_fd, serialised_message)

        if r_fd in to_read:
            output += os.read(r_fd, 1024)
            if len(output) >= hdr_size:
                packet_len, metadata_len, _, _, _, _ = serialise_formatter.unpack(output[:hdr_size])
                if len(output) >= hdr_size + packet_len + metadata_len:
                    output = output[hdr_size:]
                    print 'OUTPUT: metadata "%s" packet data "%s"' % (output[:metadata_len], output[metadata_len:metadata_len + packet_len])
                    output = output[metadata_len + packet_len:]


if __name__ == '__main__':
    buf_size = None
    if len(sys.argv) == 5:
        ser_buf_size = int(sys.argv[1])
        deser_buf_size = int(sys.argv[2])
        buf_size = int(sys.argv[3])
        metadata_len = int(sys.argv[4])

    else:
        print 'ERROR call with %s <ser_buf_size> <deser_buf_size> <standard_buf_size> <metadata_len>' % sys.argv[0]
        exit(-1)
    main(ser_buf_size, deser_buf_size, buf_size, metadata_len)
