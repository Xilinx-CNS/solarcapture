#! /usr/bin/python2
'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''

import unittest, multiprocessing
import solar_capture

def run_session():
    session = solar_capture.new_session()
    thread = session.new_thread()
    fwd = thread.new_node('sc_pool_forwarder', attr={'n_bufs_tx': 1000})
    bcast = thread.new_node('sc_shm_broadcast', args={'path': '/tmp/foo'})
    fwd.connect(bcast)
    session.go()

class RegressionPoolDry(unittest.TestCase):

    def test_pool_align(self):
        # Regression test for bug 65003.  There is a ~10% chance that
        # the pool will be allocated in a location that dodges the
        # bug, so repeat the test a few times to be sure of hitting it
        for i in range(8):
            p = multiprocessing.Process(target=run_session)
            p.start()
            p.join()
