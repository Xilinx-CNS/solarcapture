#!/usr/bin/python2
'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''

######################################################################

import optparse, os, sys, time


usage_text = """\
usage:
  %prog drop_n <n> <ingress_intf> <egress_intf>

description:
  Forward packets between network interfaces, dropping each <n>th packet.
  If <n> is zero, all traffic is forwarded."""


######################################################################

top = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), '..', '..'))
sys.path.append(os.path.join(top, 'src', 'python'))
import solar_capture as sc

os.putenv('SC_NODE_PATH', os.path.join(top, 'src', 'test', 'nodes'))

def main():
    option_parser = optparse.OptionParser(usage=usage_text)
    options, args = option_parser.parse_args()

    if len(args) != 4 or args[0] != 'drop_n':
        option_parser.print_help()
        sys.exit(1)
    n, ingress_intf, egress_intf = args[1:]

    # Create a session and a thread.
    scs = sc.new_session()
    thrd = scs.new_thread()

    # Create a VI on the ingress interface and capture all its traffic.
    ingress_vi = thrd.new_vi(ingress_intf)
    ingress_vi.add_stream(scs.new_stream("all"))

    # Create a SorePkt instance in "drop_n" mode.
    sorepkt_drop_n = thrd.new_node('sct_sorepkt_drop_n',
                                   library='sct_sorepkt.so', args={'n': n})

    # Forward packets to the other interface through SorePkt.
    sc.connect(ingress_vi, sorepkt_drop_n)
    sc.connect(sorepkt_drop_n, to_interface=egress_intf)
    # We don't create a "drop" link as we don't care about the dropped packets.

    scs.go()
    while True:
        time.sleep(10000)

if __name__ == '__main__': main()
