#!/usr/bin/python2
'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''


import os
import sys
import re
import time
import random
import subprocess
import string
import getpass
import shutil
import tempfile

top = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), '..', '..'))
os.putenv('SC_NODE_PATH', os.path.join(top, 'src', 'test', 'nodes'))
sys.path.append(os.path.join(top, 'src'))
sys.path.append(os.path.join(top, 'src', 'python'))
import solar_capture as sc


class TestFailure(Exception):
    def __init__(self, n_tests_failed):
        self.n_tests_failed = n_tests_failed

    def __str__(self):
        return repr(self.n_tests_failed)


def run_cmd(cmd, want_rc=0):
    child = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    stdout = child.communicate()[0]
    if want_rc:
        return (stdout, child.returncode)
    else:
        assert child.returncode == 0
        return stdout


def get_n_hpages():
    for l in run_cmd(['cat', '/proc/meminfo']).split('\n'):
        match = re.match('HugePages_Total:\s+(\d+)', l)
        if match != None:
            return int(match.group(1))


def configure_hpages(num):
    child = subprocess.Popen(['echo', str(num)], stdout=open(
            '/proc/sys/vm/nr_hugepages', 'w'))
    child.communicate()
    assert child.returncode == 0


def mon_run(args=None):
    if os.path.exists('/usr/bin/solar_capture_monitor'):
        path = '/usr/bin/solar_capture_monitor'
    else:
        path = os.path.join(os.path.dirname(
                sys.argv[0]), '..', 'solar_capture_monitor')
    if args == None:
        args = ['dump']
    return run_cmd([path] + args)


def get_sc_path():
    if os.path.exists('/usr/bin/solar_capture'):
        return '/usr/bin/solar_capture'
    else:
        return os.path.join(os.path.dirname(
                sys.argv[0]), '..', 'solar_capture')


def mon_parse(output=None):
    '''
    Return a list of SC objects.  Each SC object is a
    dictionary of its properties.
    '''
    if output == None:
        output = mon_run()

    ret = []
    for l in output.split('\n'):
        match = re.match('^(\S+):$', l)
        if match:
            name = match.group(1)
            ret.append({'obj_type':name})
            continue
        match = re.match('^\s+(\S+)\s+(\S.*)$', l)
        if match:
            key = match.group(1)
            # Value is either a int, None, or string
            value = match.group(2)
            try:
                value = int(value)
            except ValueError:
                if value == '(null)':
                    value = None
            ret[-1][key] = value
    return ret


def mon_get_objs(**constraints):
    '''
    Return a list of dictionaries that match the constraints
    dictionary.
    '''
    output = mon_parse()
    res = []
    for o in output:
        for k,v in constraints.items():
            try:
                if o[k] != v:
                    break
            except KeyError:
                break
        else:
            res.append(o)
    return res


def print_passed(*args):
    for a in args:
        print a + '_test: Passed'


def validate_output(out_dict_lst, raise_on_error=True, **in_dict):
    '''
    Validate that each k,v in in_dict occur in out_dict.  If any
    values in in_dict is None, then verifies that it does not appear
    in out_dict.

    Returns number of failed tests.
    '''
    ret = 0
    if len(out_dict_lst) != 1:
        for k,_ in in_dict:
            ret += 1
    else:
        out_dict = out_dict_lst[0]
        for k,v in in_dict.items():
            if v != None:
                if k in out_dict.keys() and out_dict[k] == v:
                    pass
                else:
                    ret += 1
            else:
                if k in out_dict.keys():
                    ret += 1
    if raise_on_error and ret:
        raise TestFailure(ret)
    return ret


def list_intfs():
    intfs = []
    for line in run_cmd(["ip", "addr", "show"]).split('\n'):
        if line and line[0].isdigit():
            intfs.append({'name': line.split()[1].rstrip(':'), 'mac': ''})
        elif 'link/ether ' in line:
            intfs[-1]['mac'] = line.split('link/ether ')[1].split()[0]
    return intfs


def get_sf_intfs():
    return [i['name'] for i in list_intfs() if i['mac'].startswith('00:0f:53')]


def vi_alloc(**attr):
    sf_intfs = get_sf_intfs()
    s = sc.new_session()
    thread = sc.Thread(s)
    vi = sc.VI(thread, intf_or_vi_group=sf_intfs[0], attr=attr)
    s.go()
    return vi

ALL_TESTS = []
def test_case(fn):
    ALL_TESTS.append(fn.__name__)
    return fn

@test_case
def names_test():
    attr = {'name':'Akhi rocks!', 'group_name':'He really really rocks!'}
    s = sc.new_session(attr=attr)
    s.go()
    validate_output(mon_get_objs(obj_type='Session'), **attr)
    print_passed(*attr.keys())


@test_case
def thread_test():
    attr   = {'affinity_core':0, 'managed':0, 'idle_monitor':0}
    search = {'affinity':0, 'managed':0, 'idle_loops':None}
    s = sc.new_session()
    thread = s.new_thread(attr=attr)
    s.go()
    validate_output(mon_get_objs(obj_type='Thread'), **search)
    print_passed(*attr.keys())


@test_case
def log_dir_test():
    rand_path = tempfile.mktemp(dir='/tmp')
    session = sc.new_session(attr={'log_dir':rand_path})
    session.go()
    if not os.path.exists(os.path.join(rand_path, 'sc_info')):
        raise TestFailure(1)
    shutil.rmtree(rand_path)
    print_passed('log_dir')


@test_case
def force_sw_timestamps_test():
    # This only works on 7122s.
    sf_intfs = get_sf_intfs()
    s = sc.new_session()
    thread = sc.Thread(s)
    vi0 = sc.VI(thread, intf_or_vi_group=sf_intfs[0],
                attr={'name':'vi0', 'force_sw_timestamps':1})
    vi1 = sc.VI(thread, intf_or_vi_group=sf_intfs[0],
                attr={'name':'vi1', 'force_sw_timestamps':0})
    s.go()
    validate_output(mon_get_objs(obj_type='Vi', name='vi0'), hw_timestamps=0)
    validate_output(mon_get_objs(obj_type='Vi', name='vi1'), hw_timestamps=1)
    print_passed('force_sw_timestamps')


@test_case
def require_hw_timestamps_test():
    # This is only really effective on sienas and not very useful on
    # other nics as you can get hw_timestamps without requesting it.
    s = sc.new_session()
    thread = sc.Thread(s)
    vi = sc.VI(thread, intf_or_vi_group=get_sf_intfs()[0],
               attr={'require_hw_timestamps':1})
    # On siena this will fail which is a success.
    try:
        s.go()
    except sc.SCError, e:
        pass
    else:
        validate_output(mon_get_objs(obj_type='Vi'), hw_timestamps=1)
    print_passed('require_hw_timestamps')


@test_case
def vi_test():
    attr = {'rx_ring_max':1024, 'rx_ring_high':50, 'rx_ring_low':25,
            'rx_refill_batch_high':32, 'rx_refill_batch_low':80,
            'tx_ring_max':1024, 'n_bufs_rx':40960, 'n_bufs_rx_min':40960,
            'poll_batch':16}

    search = dict(attr)
    search['rx_ring_high_level'] = search.pop('rx_ring_high')
    search['rx_ring_low_level']  = search.pop('rx_ring_low')
    search['n_bufs_rx_req']      = search.pop('n_bufs_rx')

    # These are always 1 less than specified
    search['rx_ring_max'] -= 1
    search['tx_ring_max'] -= 1

    # These are specified as %
    search['rx_ring_high_level'] = search['rx_ring_max'] * \
        search['rx_ring_high_level'] / 100
    search['rx_ring_low_level'] = search['rx_ring_max'] * \
        search['rx_ring_low_level'] / 100

    vi = vi_alloc(**attr)
    validate_output(mon_get_objs(obj_type='Vi'), **search)
    print_passed(*attr.keys())


@test_case
def mailbox_test():
    attr = {'mailbox_min_pkts':2, 'mailbox_max_nanos':1000,
            'mailbox_recv_max_pkts':1000}
    search = {'send_min_pkts':2, 'send_max_nanos':1000, 'recv_max_pkts':1000}

    s = sc.new_session()
    t = sc.Thread(s)
    mb = sc.Mailbox(t, attr=attr)
    s.go()
    validate_output(mon_get_objs(obj_type='Mailbox'), **search)
    print_passed(*attr.keys())


@test_case
def private_pool_test():
    # Allocate some VIs with and without private pools.  They need
    # connecting nodes or else pools are not actually created.
    sf_intfs = get_sf_intfs()
    s = sc.new_session()
    thread = sc.Thread(s)
    writer = thread.new_node('sc_writer', args={'filename':'/dev/null'})
    vi0 = sc.VI(thread, intf_or_vi_group=sf_intfs[0],
                attr={'name':'p0', 'private_pool':1})
    vi1 = sc.VI(thread, intf_or_vi_group=sf_intfs[0],
                attr={'name':'p1', 'private_pool':1})
    vi2 = sc.VI(thread, intf_or_vi_group=sf_intfs[0],
                attr={'name':'shared', 'private_pool':0})
    vi3 = sc.VI(thread, intf_or_vi_group=sf_intfs[0],
                attr={'name':'shared', 'private_pool':0})
    sc.connect(vi0, writer)
    sc.connect(vi1, writer)
    sc.connect(vi2, writer)
    sc.connect(vi3, writer)
    s.go()

    pools = [mon_get_objs(obj_type='Pool', name=n)
             for n in ['shared', 'p0', 'p1']]
    ids = set(pool[0]['id'] for pool in pools)
    if len(ids) == 3 and -1 not in ids and all([len(p) == 1 for p in pools]):
        pass
    else:
        raise TestFailure(1)
    print_passed('private_pool')


@test_case
def request_huge_pages_test():
    # Get number of huge pages currently configured so we can restore
    # at end of test
    current_hpages = get_n_hpages()

    configure_hpages(100)

    def my_vi_alloc(attr):
        sf_intfs = get_sf_intfs()
        s = sc.new_session()
        thread = sc.Thread(s)
        rand_path = tempfile.mktemp(dir='/tmp')
        writer = thread.new_node('sc_writer', args={'filename':rand_path})
        vi = sc.VI(thread, intf_or_vi_group=sf_intfs[0], attr=attr)
        sc.connect(vi, writer)
        s.go()
        return vi

    # We have huge pages, allocating with request_huge_pages=0 should
    # still give us none.
    vi0 = my_vi_alloc({'name':'hp0', 'request_huge_pages':0})
    # We have huge pages, allocating with request_huge_pages=1 should
    # give us some.
    vi1 = my_vi_alloc({'name':'hp1', 'request_huge_pages':1})

    failed = False
    try:
        if mon_get_objs(obj_type='Pool', name='hp0')[0]['huge_pages']:
            failed = True
        if not mon_get_objs(obj_type='Pool', name='hp1')[0]['huge_pages']:
            failed = True
    except Exception as e:
        print "ERROR: Unexpected failure: %s" % (e,)
        failed = True


    # Restore original huge pages
    configure_hpages(current_hpages)
    if failed:
        raise TestFailure(1)
    print_passed('request_huge_pages')


@test_case
def require_huge_pages_test():
    # Get number of huge pages currently configured so we can restore
    # at end of test
    current_hpages = get_n_hpages()

    # Configure 0 huge pages
    configure_hpages(0)

    # We don't have huge pages, allocating with require_huge_pages=1
    # should fail.
    sf_intfs = get_sf_intfs()
    s = sc.new_session(attr={'log_level':0})
    thread = sc.Thread(s)
    rand_path = tempfile.mktemp(dir='/tmp')
    writer = thread.new_node('sc_writer', args={'filename':rand_path})
    vi = sc.VI(thread, intf_or_vi_group=sf_intfs[0],
               attr={'name':'hp1', 'require_huge_pages':1})
    sc.connect(vi, writer)
    try:
        s.go()
    except sc.SCError, e:
        ret = 0
    else:
        ret = 1

    # Restore original huge pages
    configure_hpages(current_hpages)
    if ret:
        raise TestFailure(ret)
    print_passed('require_huge_pages')


@test_case
def discard_mask_test():
    vi = vi_alloc(discard_mask=sc.discard_mask_list_to_int(['CSUM']))
    # We do not support capturing SC_TRUNCATED so it always gets set.
    expect_mask = sc.discard_mask_list_to_int(["CSUM", "TRUNCATED"])
    validate_output(mon_get_objs(obj_type='Vi'), discard_mask=expect_mask)
    print_passed('discard_mask')


@test_case
def log_level_test():
    # Run SC with a higher log_level and look for a random string
    # expected with higher log_level.
    cmd = [get_sc_path(), 'foo=/dev/null']
    child = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE,
                             env={'SC_ATTR':'log_level=5'})
    stderr = child.communicate()[1]
    if 'sc_session_alloc: ' in stderr:
        print_passed('log_level')
    else:
        raise TestFailure(1)


def usage():
    print 'python attr.py all # Runs all tests'
    print 'python attr.py <test> # Runs one test case'
    print
    print 'Test cases:'
    for test in ALL_TESTS:
        print " ",test
    sys.exit(1)


def main():
    if len(sys.argv) != 2:
        usage()

    # Run all tests but in separate processes so no cleanup needed.
    if sys.argv[1] == 'all':
        failures = []
        for test in ALL_TESTS:
            (out, rc) = run_cmd([sys.argv[0], test], want_rc=1)
            if rc:
                failures.append(test)
            print out,
        if failures:
            print '%d tests failed (%s)' % (len(failures), ' '.join(failures))
        else:
            print 'All tests passed'
        sys.exit(len(failures))
    else:
        test_fn = globals()[sys.argv[1]]
        test_fn()


if __name__ == '__main__':
    main()
