'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''

'''
Description: Simple example which chains BPF filters together. The
configuration file has the following format:
<bpf filter 1>,<filename1>.pcap
<bpf filter 2>,<filename 2>.pcap
...
<bpf filter n>,<filename n>.pcap
unmatched,<unmatched packets file>.pcap
This will chain filters 1 through n together, with filter i+1 being
applied to the packets which fail to match filter i's criteria. Any
ackets not being matched by any of the filters will be captured in
he unmatched pcap file. All of the work will be executed on a single
thread.


Example:
Using the following configuration file will result in 3 filters being
reated (2 on destination ports 5545 and 6676, and the 3rd on source
port 12345) and applied in the order listed, with the remaining unmatched
traffic being caught in the file unmatched.pcap.

cat <<EOF > demo_config_file
dst port 5545,port5545.pcap
dst port 6676,port6676.pcap
src port 12345,port1345.pcap
unmatched,unmatched.pcap
EOF


Notes:
The filter matching is exclusive. In the example listed above,
the first filter will filter out any destination port 5545 packets. On
all packets which do not match this filter, filter out any packets with
destination port 6676. On all packets which have not matched the first
two filters, filter out any packets with source port 12345.

The VI is created as a steal VI with an all filter inserted, so all
packets arriving on the specified interface will be intercepted by this
script.

If unmatched traffic is not wanted, then omit the last line
"unmatched,<unmatched packets file>.pcap" in the configuration file.

You need to specify at least one filter. Only specifying the unmatched
filter will not suffice.


Running this script:
python chaining_bpf_nodes.py <config file> eth<X>
'''

import sys
import os
import time
import signal
import mimetypes

import solar_capture as sc

SNAP_LEN = 0


def usage():
    print 'USAGE: python ', sys.argv[0], ' <config file> <source interface>\n'
    sys.exit(1)


class BPFOptions:

    ERRBADREC = "ERROR: Bad entry detected in configuration file"
    ERRNOFILT = """ERROR: No filters specified. You need to specify at
least one filter in addition to the unmatched filter.
Exiting"""

    def __init__(self, filename):
        self.filename = filename
        self.filters = []
        self.unmatched_file = None
        self.parse_file()

    def parse_file(self):
        for line in file(self.filename):
            if line.count(',') != 1:
                sys.exit(self.ERRBADREC)
            stream, filename = line.split(',')
            if stream == 'unmatched':
                self.unmatched_file = filename.rstrip()
            else:
                self.filters.append((stream, filename.rstrip()))
        if not self.filters:
            sys.exit(self.ERRNOFILT)


def main():
    if len(sys.argv) != 3:
        usage()

    # Get the name of the interface to capture on
    cfg_file = sys.argv[1]
    src_intf = sys.argv[2]

    optlist = BPFOptions(cfg_file)
    bpf_instances = []
    writer_instances = []

    # pipe to handle kill signal. This uses the fd_reader node to signal
    # to solarcapture when the process has been terminated.
    r_fd, w_fd = os.pipe()

    # used to handle end-of-capture signals (Ctrl-C)
    def signal_handler(signum, frame):
        try:
            os.close(w_fd)
        except OSError as ex:
            if ex.errno != errno.EBADF:
                raise

    # Create a new session
    # A session is an association between components that together form
    # a single SolarCapture topology.  This allows the application to
    # start and stop the topology as a unit.
    scs = sc.new_session()

    # Create a thread to do the capture and writeout on
    cthread = scs.new_thread()

    # Create a VI on the capture thread.
    vi = cthread.new_vi(src_intf)

    # add the streams we want to capture to the VI. In this example, the VI
    # will steal all traffic arriving on the interface
    vi.add_stream(scs.new_stream("all"))

    # Now, for each specified filter, create a filter node and a writer node
    for bpf_filter, target_file in optlist.filters:
        bpf_args = dict(bpf=bpf_filter)
        bpf_instances.append(cthread.new_node("sc_filter", args=bpf_args))
        writer_args = dict(filename=target_file, snap=SNAP_LEN)
        writer_instances.append(cthread.new_node('sc_writer',
                                args=writer_args))

    if optlist.unmatched_file:
        # Create a writer node to catch all unmatched packets
        unmatched_writer_args = dict(filename=optlist.unmatched_file,
                                     snap=SNAP_LEN)
        unmatched_writer = cthread.new_node('sc_writer',
                                            args=unmatched_writer_args)

    # Create signal handling and cleanup nodes
    signal_vi = cthread.new_node('sc_signal_vi')
    exiter = cthread.new_node('sc_exit')
    reader = cthread.new_node('sc_fd_reader', args={'fd': r_fd})

    # Connect nodes together to form node graph. Note that the i+1st filter
    # is filtering on the packets rejected by the the ith filter:

    # Connect Vi and signal handler
    vi.connect(signal_vi)
    reader.connect(signal_vi, 'ctl')

    # Add in the first filter node and its associated writer
    signal_vi.connect(bpf_instances[0])
    bpf_instances[0].connect(writer_instances[0])
    writer_instances[0].connect(exiter)

    # If there is more than one BPF filter specified, then this section will
    # handle chaining these together
    n_instances = len(bpf_instances)
    for i in range(1, (n_instances)):
        bpf_instances[i-1].connect("not_matched", bpf_instances[i])
        bpf_instances[i].connect(writer_instances[i]).connect(exiter)

    if optlist.unmatched_file:
        sc.connect(bpf_instances[n_instances-1], "not_matched",
                   unmatched_writer)
        sc.connect(unmatched_writer, exiter)

    # Kick off packet handling
    scs.go()

    # Add some signal handling
    for signum in [signal.SIGINT, signal.SIGTERM, signal.SIGQUIT]:
        signal.signal(signum, signal_handler)

    while True:
        time.sleep(1)

if __name__ == '__main__':
    main()
