#!/usr/bin/python2
'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''

######################################################################

import sys, time, os


usage_text = """
usage:
  %prog <input-file>... <output-file>

"""


def usage_msg(f):
    me = os.path.basename(sys.argv[0])
    f.write(usage_text.replace("%prog", me))


def usage_err():
    usage_msg(sys.stderr)
    sys.exit(1)


######################################################################
# main()

top = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), '..', '..'))
sys.path.append(os.path.join(top, 'src', 'python'))
import solar_capture as sc


args = sys.argv[1:]
if len(args) < 2:
    usage_err()
source_files = args[:-1]
dest_file = args[-1]

scs = sc.new_session()
thrd = scs.new_thread()
merge = thrd.new_node('sc_merge_sorter')
for s in source_files:
    sc.connect(thrd.new_node('sc_reader', args=dict(filename=s)), merge)
dest = thrd.new_node('sc_writer', args=dict(filename=dest_file,
                                            format='pcap-ns'))
sc.connect(merge, dest)
sc.connect(dest, thrd.new_node('sc_exit'))
scs.go()
while True:
    time.sleep(10000)
