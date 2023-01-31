#!/usr/bin/python2
'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''


'''
This is a test for the sc_tunnel node.
'''

import sys, os, time, random, thread

top = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), '..', '..'))
sys.path.append(os.path.join(top, 'src', 'python'))
import solar_capture as sc


usage_text = """\
usage:
  %prog DIR [BUF-SIZE] [MULTIPLIER]

  Test will create a number of pcap files in DIR, with the file name giving
  the expected number of packets in each file.  The test passes if the
  number of packets in each file matches the name.

  If the MULTIPLIER option is given then the number of packets passed to
  each file is multipled by the given value.
"""


def usage_msg(f):
    me = os.path.basename(sys.argv[0])
    f.write(usage_text.replace("%prog", me))


def usage_err():
    usage_msg(sys.stderr)
    sys.exit(1)


def build_session(dir, passive, f_links, b_links, buf_size):
    # The buffer size for sc_writer is required to be at least the max size
    # of incoming packets + the size of file and record headers.
    writer_buf_size = max(buf_size + 200, 32*1024)

    scs = sc.new_session()
    thrd  = scs.new_thread()
    attr = dict(pool_n_bufs=20, buf_size=buf_size)

    tun = thrd.new_node('sc_tunnel', args=dict(passive_open=passive,
                                               server_name='localhost',
                                               server_port='4500'),
                        attr=attr)
    for l in f_links:
        pipe = thrd.new_node('sc_pool_forwarder', attr=attr)
        pipe = pipe.connect(thrd.new_node('sc_pass_n', args=dict(n=l)))
        sc.connect(pipe, tun, str(l))
    for l in b_links:
        fname = "%s/%s.pcap" % (dir, str(l))
        attr['buf_size_pcap'] = writer_buf_size
        wr = thrd.new_node('sc_writer', args=dict(filename=fname,
                                                  snap=buf_size),
                           attr=attr)
        sc.connect(tun, str(l), wr)
        sc.connect(wr, thrd.new_node('sc_exit'))
    sc.connect(tun, '#exit', thrd.new_node('sc_exit'))

    # Do prep in background as sc_tunnel prep may block while connecting.
    thread.start_new_thread(scs.go, ())


def main():
    args = sys.argv[1:]
    if len(args) < 1 or len(args) > 3:
        usage_err()

    dir = args[0]
    buf_size = 1000
    multiplier = 1
    if len(args) >= 2:
        buf_size = int(args[1])
    if len(args) >= 3:
        multiplier = int(args[2])

    f_links = [2, 4, 6, 8]
    b_links = [1, 3, 5, 7]

    f_links = [l*multiplier for l in f_links]
    b_links = [l*multiplier for l in b_links]

    build_session(dir, 1, f_links, b_links, buf_size)

    # Shuffle links so that we add them in a different order.  (So we can
    # prove that links are matched by name, not by the order they are
    # added).
    random.shuffle(f_links)
    random.shuffle(b_links)

    build_session(dir, 0, b_links, f_links, buf_size)

    while True:
        time.sleep(1000)


if __name__ == '__main__':
    main()
