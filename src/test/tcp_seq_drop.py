#!/usr/bin/python2
'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''

######################################################################

import optparse, os, sys, time


usage_text = """\
  %prog [options] <ingress_intf> <egress_intf>

Description:
  Forward packets between network interfaces, dropping R repetitions
  of a TCP sequence number.  Capture is written to disk before any
  packets are dropped. Wait W ms before starting the next sequence
  of drops.  Only TCP packets with payload are dropped, all other
  packets will always be forwarded.  If R is zero, all traffic is
  forwarded."""


######################################################################

top = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), '..', '..'))
sys.path.append(os.path.join(top, 'src', 'python'))
import solar_capture as sc

os.putenv('SC_NODE_PATH', os.path.join(top, 'src', 'test', 'nodes'))

def main():
    option_parser = optparse.OptionParser(usage=usage_text)
    option_parser.add_option("-r", "--drop-rep", metavar="R",
                             dest="drop_rep", type="int", default=3,
                             help="repeatedly drop packets with same TCP\
 sequence number N times [default: %default]")
    option_parser.add_option("-w", "--drop-wait", metavar="W",
                             dest="drop_wait_ms", type="int", default=500,
                             help="wait M ms between each sequence of drops\
 [default: %default]")
    option_parser.add_option("-i", "--init-tcp-count", metavar="I",
                             dest="init_tcp_count", type="int", default=30,
                             help="wait until I TCP packets have been\
 observed before dropping [default: %default]")
    option_parser.add_option("-e", "--drop-extra", metavar="E",
                             dest="drop_extra", type="int", default=0,
                             help="drop additional non-consecutive packets\
 [default: %default]")
    option_parser.add_option("-d", "--output-dir", metavar="/path/for/pcap",
                             dest="output_dir", type="string", default="/tmp",
                             help="output directory for pcap files\
 [default: %default]")
    option_parser.add_option("-s", "--snap", metavar="SNAP",
                             dest="snap", type="int", default=0,
                             help="snap value for capture written to disk\
 [default: %default]")
    option_parser.add_option("-f", "--format", metavar="FORMAT",
                             dest="output_format", type="string", default="pcap",
                             help="output format, options are pcap or pcap-ns\
 [default: %default]")
    options, args = option_parser.parse_args()

    if len(args) != 2:
        option_parser.print_help()
        sys.exit(1)
    ingress_intf, egress_intf = args

    # Create a session and a thread.
    scs = sc.new_session()
    thrd = scs.new_thread()

    # Create a VI on the ingress interface and capture all its traffic.
    ingress_vi = thrd.new_vi(ingress_intf)
    ingress_vi.add_stream(scs.new_stream("all"))

    # Create a tap node
    #   Give option to snap since we usually only care about traffic patterns
    tap = thrd.new_node('sc_tap', args={'snap':options.snap})

    # Create a TCP Seq Drop node
    tcp_seq_drop = thrd.new_node('sct_tcp_seq_drop', library='sct_tcp_seq_drop.so',
                                 args={'drop_rep':options.drop_rep,
                                       'drop_extra':options.drop_extra,
                                       'drop_wait_ms':options.drop_wait_ms,
                                       'init_tcp_count':options.init_tcp_count})

    # Create a writer node
    output_pcap = os.path.join(options.output_dir,ingress_intf+'.pcap')
    writer = thrd.new_node('sc_writer',
                           args={'filename':output_pcap,
                                 'format':options.output_format})

    # Connect the nodes
    sc.connect(ingress_vi, tap)
    sc.connect(tap, "", tcp_seq_drop)
    sc.connect(tap, "tap", writer)
    sc.connect(tcp_seq_drop, to_interface=egress_intf)

    scs.go()
    while True:
        time.sleep(10000)

if __name__ == '__main__':
    main()
