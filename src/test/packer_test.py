#!/usr/bin/python2
'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''

import sys, time, os


# Set up PYTHONPATH so we can import the in-tree solar_capture module
top = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), '..', '..'))
sys.path.append(os.path.join(top, 'src', 'python'))
import solar_capture


PS_BUFFER_SIZE = 65536 # (maximum) size of packed-stream buffers

def main(pcap_file):
    session = solar_capture.new_session()
    thread = session.new_thread()


    # sc_reader: reads packets from a pcap file and outputs them one at a time
    reader_args = {'filename': pcap_file}
    pipeline = pcap_reader = thread.new_node('sc_reader', args=reader_args)


    # sc_ps_packer: takes individual packets as input, packs them into
    #               packed-stream format buffers and outputs the packed buffers
    packer = thread.new_node('sc_ps_packer', attr={'buf_size': PS_BUFFER_SIZE})
    pipeline = pipeline.connect(packer)


    ###########################################################################
    # Insert a node here and it will receive packed-stream buffers on
    # its input link.
    #
    # my_node = thread.new_node('...', attr={...}, args={...})
    # pipline = pipeline.connect(my_node)
    ###########################################################################


    # sc_exit: Once all packets have been processed, this node will
    #          cause the test app to exit
    sc_exit = thread.new_node('sc_exit')
    pipeline = pipeline.connect(sc_exit)
    session.go()
    while True:
        time.sleep(1)



if __name__ == '__main__':
    if len(sys.argv) != 2:
        print "USAGE: %s <input_file.pcap>" % sys.argv[0]
        sys.exit(1)
    pcap_file = sys.argv[1]
    main(pcap_file)
