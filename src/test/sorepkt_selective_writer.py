#!/usr/bin/python2
'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''


###############################################################################

# Author:  Alex G. Rakowski
# Version: 3.6.19

###############################################################################

# Description

'''
Intent:     Monitor bidirectional traffic through a SC middle-box.

Behaviour:  Captures the start of the stream, along with a latter section,
            as determined by control signals piped to a specified file.

            The packets captured during this period will be piped to a
            pcap output file and thereafter the SolarCapture instances
            will be halted.
'''

###############################################################################

# Imports and paths

import sys, os, signal, time, argparse, datetime, atexit

top = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), '..', '..'))
sys.path.append(os.path.join(top, 'src', 'python'))

import solar_capture as sc

os.putenv('SC_NODE_PATH', os.path.join(top, 'src', 'test', 'nodes'))

###############################################################################

# Global constants

S_PASS_NAME         = 'pass'
S_EXIT_NAME         = 'exit'
S_DROP_NAME         = 'drop'
S_DELY_NAME         = 'delay'
S_JITT_NAME         = 'jitter'
S_WRTR_NAME         = 'writer'
S_GEN_NAME          = 'general'
S_FRDR_NAME         = 'file_reader'
DEFAULT_EXIT_SCOPE  = 'process'
DEFAULT_CTL_FILE    = '/tmp/sorepkt/control_capture'
DEFAULT_PCAP_FILE   = '/tmp/sorepkt/pcap_files/cap.pcap'

###############################################################################

# Assorted useful methods

# Method to associate a thread with a core
def get_thread(tg, core):
    if not hasattr(tg, 'core2thread'):
        tg.core2thread = {}
    if not core in tg.core2thread:
        attr = {} if core < 0 else {'affinity_core':core}
        tg.core2thread[core] = tg.new_thread(attr=attr)
    return tg.core2thread[core]


# Method to print a message and cleanly exit
def exit(msg):
    assert type(msg) == str
    print >> sys.stderr, 'sorepkt: ERROR: ' + msg
    sys.exit(1)


def warning(msg):
    assert type(msg) == str
    print >> sys.stderr, 'sorepkt: WARNING: ' + msg


# Method used internally by maybe_create_file and make_fifo
# Note use of os.makedirs() would also work, but appears to be
# unavailable
def create_path(filename):
    exists_path = os.path.dirname(filename)
    non_path = []
    while not os.path.exists(exists_path):
        non_path.append(os.path.basename(exists_path))
        exists_path = os.path.dirname(exists_path)
    while non_path:
        next_part = non_path.pop()
        exists_path = os.path.join(exists_path, next_part)
        os.mkdir(exists_path)


# Method to check if a file exists and if not, then to create it
def maybe_create_file(filename):
    if os.path.exists(filename):
        if os.path.isfile(filename):
            return
        else:
            exit('File %s shares name with an existing directory' % filename)
    else:
        create_path(filename)
        f = open(filename, 'w').close()


# Method to create a fresh named FIFO
def make_fifo(fifo_name):
    if os.path.exists(fifo_name):
        os.remove(fifo_name)
    create_path(fifo_name)
    fifo = os.mkfifo(fifo_name)


# Method to create a filename from the current date-time
def dttofn():
    sep = '_'
    dt = str(datetime.datetime.now()).replace(' ', sep).\
                                      replace(':', sep).\
                                      replace('-', sep).\
                                      replace('.', sep)
    base_path = os.path.dirname(DEFAULT_PCAP_FILE)
    filename  = os.path.join(base_path, dt + '.pcap')
    maybe_create_file(filename)
    return filename


# Method to handle SIGTERM or other such signals
def signal_handler(sig, frame):
    sys.exit(128 + sig)

###############################################################################

# Parse inputs

def parse():
    ap = argparse.ArgumentParser(description = 'Set up transparent ' + \
                                               'capture/monitoring node')
    subs = ap.add_subparsers(dest='subp_name')

    s_drop = subs.add_parser(S_DROP_NAME,
                             description='Settings for dropping packets')
    s_dely = subs.add_parser(S_DELY_NAME,
                             description='Settings for delaying packets')
    s_jitt = subs.add_parser(S_JITT_NAME,
                             description='Settings for jittering packets')
    s_pass = subs.add_parser(S_PASS_NAME,
                             description='Settings for how many to capture')
    s_exit = subs.add_parser(S_EXIT_NAME,
                             description='Settings for exiting')
    s_wrtr = subs.add_parser(S_WRTR_NAME,
                             description='Settings for writing captured ' + \
                                         'packets to file')
    s_frdr = subs.add_parser(S_FRDR_NAME,
                             description='Settings for reading from file')
    s_gen  = subs.add_parser(S_GEN_NAME,
                             description='General settings')

    # Arguments for subparsers
    # General args
    s_gen.add_argument('-r', '--rx_intf',
                       dest='rx_intf',
                       required=True,
                       help='Interface on which to receive packets')
    s_gen.add_argument('-t', '--tx_intf',
                       dest='tx_intf',
                       required=True,
                       help='Interace on which to transmit packets')
    s_gen.add_argument('--capture',
                       dest='capture',
                       required=True,
                       choices=['on', 'off'],
                       help='Whether or not to capture packets for analysis')
    # Drop node args
    s_drop.add_argument('-b', '--bmode',
                       dest='bmode',
                       default='s',
                       choices=['b', 's'],
                       help='Single drop, or burst drop mode')
    s_drop.add_argument('-a', '--btime',
                       dest='btime',
                       required=False,
                       default='0',
                       type=int,
                       help='Burst time for dropping packets')
    s_drop.add_argument('-d', '--dist',
                        dest='dist',
                        required=False,
                        default='constant',
                        choices=['exp', 'normal', 'uniform', 'constant'],
                        help='Distribution of packet drops')
    s_drop.add_argument('-n',
                        dest='drop_n',
                        required=False,
                        default=0,
                        type=int,
                        help='Drop every <n>th packet')
    s_drop.add_argument('-l', '--lambda',
                        dest='exp_lambda',
                        default=1,
                        type=float,
                        help='Parameter to exponential distribution')
    s_drop.add_argument('-u', '--mean',
                        dest='mean',
                        required=False,
                        default=0.0,
                        type=float,
                        help='Normal distribution mean')
    s_drop.add_argument('-o', '--sdev',
                        dest='sdev',
                        required=False,
                        default=0.0,
                        type=float,
                        help='Normal distribution standard deviation')
    s_drop.add_argument('-f', '--uniform_min',
                        dest='umin',
                        required=False,
                        default=0,
                        type=int,
                        help='Lower bound for uniform distribution')
    s_drop.add_argument('-g', '--uniform_max',
                        dest='umax',
                        required=False,
                        default=0,
                        type=int,
                        help='Higher bound for uniform distribution')
    # Jitter args
    s_jitt.add_argument('-j', '--jitter_dist_type',
                        dest='jitter',
                        required=False,
                        default='none',
                        choices=['constant', 'uniform', 'exp', 'normal',
                                 'none'],
                        help='Statistical dist. used to add jitter')
    # Delay args
    s_dely.add_argument('-m', '--min_delay',
                        dest='min',
                        required=False,
                        default=0,
                        type=int,
                        help='Minimum time (ms) to delay a packet')
    s_dely.add_argument('-M', '--max_delay',
                        dest='max',
                        required=False,
                        type=int,
                        help='Maximum time (ms) to delay a packet by')
    s_dely.add_argument('-c', '--num_cons',
                        dest='num_lines',
                        required=False,
                        default=1,
                        type=int,
                        help='Number of delay lines between endpoints')
    # Pass_n args
    s_pass.add_argument('-p', '--pass_n',
                        dest='pass_n',
                        required=False,
                        default=10000,
                        type=int,
                        help='How many packets to capture for the pcap file')
    # Exit args
    s_exit.add_argument('-s', '--exit_scope',
                        dest='exit_scope',
                        required=False,
                        default=DEFAULT_EXIT_SCOPE,
                        type=str,
                        choices=['process', 'session', 'none'],
                        help='Scope for exiting once packets have been ' + \
                             'captured; set to "none" to not exit')
    # Writer args
    s_wrtr.add_argument('--output_file',
                        dest='output_file',
                        required=False,
                        default=DEFAULT_PCAP_FILE,
                        type=str,
                        help='Name for file in which to save pcap data')
    s_wrtr.add_argument('--output_format',
                        dest='output_format',
                        required=False,
                        default='pcap',
                        type=str,
                        choices=['pcap', 'pcap-ns'],
                        help='File format in which to save pcap output')
    s_wrtr.add_argument('-e', '--error_handling',
                        dest='on_error',
                        required=False,
                        default='message',
                        type=str,
                        choices=['silent', 'message', 'exit', 'abort'],
                        help='How to behave if an error is encountered ' + \
                             'when writing the output pcap file')
    s_wrtr.add_argument('--snap',
                        dest='snap',
                        required=False,
                        default=80,
                        type=int,
                        help='Max number of bytes to write to file from ' + \
                             'any captured file')
    # FD reader args
    s_frdr.add_argument('-i', '--input_file',
                        dest='input_file',
                        required=False,
                        default=DEFAULT_CTL_FILE,
                        type=str,
                        help='File to which to send control signals, ' + \
                             'such as turning SolarCapture on/off')

    # Return the parser with its arguments
    return ap

###############################################################################

# Extract values from inputs

def extract(ap):
    args_list = []
    args, rest = ap.parse_known_args()
    args_list.append(args)
    while rest:
        args, rest = ap.parse_known_args(rest)
        args_list.append(args)

    node_args_names = [
                        S_DELY_NAME,
                        S_DROP_NAME,
                        S_EXIT_NAME,
                        S_FRDR_NAME,
                        S_GEN_NAME,
                        S_JITT_NAME,
                        S_PASS_NAME,
                        S_WRTR_NAME,
                       ]
    node_args = {}

    # Currently all argument groups are in an unordered mess together.
    # Extract them one at a time by matching on subparser name.
    # Do in one pass, as O(mn).
    for name in node_args_names:
        match = None
        for args in args_list:
            if args.subp_name == name:
                match = args_list.pop(args_list.index(args))
                break
        node_args[name] = match
    # If args_list still exists after extracting all desired data,
    # then something went wrong and too much data was entered
    if args_list: exit('too many arguments provided')

    # Argument checking
    if node_args[S_DELY_NAME]:
        if node_args[S_DELY_NAME].min < 0 or \
                node_args[S_DELY_NAME].min > sys.maxint:
            exit('Minimum outside allowed range')
        if node_args[S_DELY_NAME].max and \
                (node_args[S_DELY_NAME].max < node_args[S_DELY_NAME].min or \
                node_args[S_DELY_NAME].max > sys.maxint):
            exit('Maximum outside allowed range')
        if node_args[S_DELY_NAME].max and \
                node_args[S_DELY_NAME].num_lines == 1:
            exit('Usage: delay range requires -c is given a value > 1.')
        if not node_args[S_DELY_NAME].max and \
                node_args[S_DELY_NAME].num_lines != 1:
            exit('Usage: delay range requires -c is set to 1')

    if node_args[S_DROP_NAME]:
        if node_args[S_DROP_NAME].btime < 0 or \
                node_args[S_DROP_NAME].btime > sys.maxint:
            exit('Burst time outside allowed range')
        if node_args[S_DROP_NAME].drop_n < 0 or \
                node_args[S_DROP_NAME].drop_n > sys.maxint:
            exit('N outside allowed range')
        if node_args[S_DROP_NAME].exp_lambda < 0 or \
                node_args[S_DROP_NAME].exp_lambda > sys.maxint:
            exit('Lambda outside allowed range')
        if node_args[S_DROP_NAME].mean < 0 \
                or node_args[S_DROP_NAME].mean > sys.maxint:
            exit('Mean outside allowed range')
        if node_args[S_DROP_NAME].sdev < 0 or \
                node_args[S_DROP_NAME].sdev > node_args[S_DROP_NAME].mean:
            exit('Standard deviation outside allowed range')
        if node_args[S_DROP_NAME].umin < 0 or \
                node_args[S_DROP_NAME].umin > sys.maxint:
            exit('Uniform min outside allowed range')
        if node_args[S_DROP_NAME].umax < node_args[S_DROP_NAME].umin or \
                node_args[S_DROP_NAME].umax > sys.maxint:
            exit('Uniform max outside allowed range')

    if node_args[S_PASS_NAME]:
        if not node_args[S_PASS_NAME].pass_n:
            exit('Not capturing any packets - unnecessary test; exiting')
        elif node_args[S_PASS_NAME].pass_n < 0 or \
                node_args[S_PASS_NAME].pass_n > sys.maxint:
            exit('Pass value n outside allowed range')

    if node_args[S_FRDR_NAME]:
        make_fifo(node_args[S_FRDR_NAME].input_file)

    if node_args[S_WRTR_NAME]:
        if str(node_args[S_WRTR_NAME].output_file).rstrip not in ['None', '']:
            maybe_create_file(node_args[S_WRTR_NAME].output_file)
        if not node_args[S_WRTR_NAME].snap:
            exit('Not capturing any bytes - unnecessary test; exiting')
        elif node_args[S_WRTR_NAME].snap < 0 or \
                node_args[S_WRTR_NAME].snap > sys.maxint:
            exit('Snap outside allowed range')

    return node_args

###############################################################################

# Process extracted values for passing to SC nodes

def process_delay(**node_args):
    args = {}
    if node_args.has_key(S_DELY_NAME) and node_args[S_DELY_NAME]:
        args['msec'] = '%d-%d' % \
                (node_args[S_DELY_NAME].min, node_args[S_DELY_NAME].max) if \
                node_args[S_DELY_NAME].max else str(node_args[S_DELY_NAME].min)
        if node_args[S_DELY_NAME].num_lines:
            args['num_lines'] = node_args[S_DELY_NAME].num_lines
        else:
            args['num_lines'] = 2 if node_args[S_DELY_NAME].max else 1
    else:
        args['msec']      = '0'
        args['num_lines'] = 1
    return args


def process_drop(**node_args):
    args = {}
    if node_args.has_key(S_DROP_NAME) and node_args[S_DROP_NAME]:
        dist = node_args[S_DROP_NAME].dist
        args['dist'] = dist
        if dist == 'constant':
            args['drop_n'] = node_args[S_DROP_NAME].drop_n
        elif dist == 'uniform':
            args['min'] = node_args[S_DROP_NAME].umin
            args['max'] = node_args[S_DROP_NAME].umax
        elif dist == 'exp':
            args['lambda'] = node_args[S_DROP_NAME].exp_lambda
        elif dist == 'normal':
            args['mean'] = node_args[S_DROP_NAME].mean
            args['sdev'] = node_args[S_DROP_NAME].sdev
        else:
            exit('Distribution not recognised')
        if node_args[S_DROP_NAME].bmode:
            if node_args[S_DROP_NAME].bmode == 'b':
                args['use_burst'] = 1
                if node_args[S_DROP_NAME].btime:
                    args['burst_time'] = node_args[S_DROP_NAME].btime
                else:
                    exit('Using zero-length bursts; please use "s"')
            else:
                args['use_burst'] = 0
    else:
        args['dist']      = 'constant'
        args['drop_n']    = 0
        args['use_burst'] = 0
    return args


def process_exit(**node_args):
    if node_args.has_key(S_EXIT_NAME) and node_args[S_EXIT_NAME]:
        return dict(scope = node_args[S_EXIT_NAME].exit_scope)
    else:
        return dict(scope = DEFAULT_EXIT_SCOPE)


def process_f_reader(**node_args):
    args = {}
    if node_args.has_key(S_FRDR_NAME) and node_args[S_FRDR_NAME]:
        args['filename'] = node_args[S_FRDR_NAME].input_file
    else:
        fname = DEFAULT_CTL_FILE
        make_fifo(fname)
        args['filename'] = fname
    args['signal_eof']             = 1
    args['close_on_eof']           = 1
    return args


def process_general(**node_args):
    args = {}
    if node_args.has_key(S_GEN_NAME)  and node_args[S_GEN_NAME]:
        args['rx_intf'] = node_args[S_GEN_NAME].rx_intf
        args['tx_intf'] = node_args[S_GEN_NAME].tx_intf
        args['capture'] = node_args[S_GEN_NAME].capture
        if args['capture'] == 'off':
            warning('Parameter `capture` set to `off`; ' \
                    'ignoring all parameters for capturing packets')
    else:
        exit('Must supply tx and rx interfaces')
    return args


def process_jitter(**node_args):
    return dict(dist = node_args[S_JITT_NAME].jitter) if \
            node_args.has_key(S_JITT_NAME) and node_args[S_JITT_NAME] else None


def process_pass(**node_args):
    args = {}
    if node_args.has_key(S_PASS_NAME) and node_args[S_PASS_NAME]:
        args['n'] = node_args[S_PASS_NAME].pass_n
    else:
        args['n'] = 1000
    return args


def process_pass_start(**node_args):
    args = dict(
                n                   = 10
                )
    return args


def process_writer(**node_args):
    args = {}
    if node_args.has_key(S_WRTR_NAME) and node_args[S_WRTR_NAME]:
        args['snap']     = node_args[S_WRTR_NAME].snap          if \
                node_args[S_WRTR_NAME].snap          else 60
        args['on_error'] = node_args[S_WRTR_NAME].on_error      if \
                node_args[S_WRTR_NAME].on_error      else 'message'
        args['format']   = node_args[S_WRTR_NAME].output_format if \
                node_args[S_WRTR_NAME].output_format else 'pcap'
        if node_args[S_WRTR_NAME].output_file and \
                os.path.basename(node_args[S_WRTR_NAME].output_file) != \
                'cap.pcap':
            args['filename'] = node_args[S_WRTR_NAME].output_file
        else:
            args['filename'] = dttofn()
    else:
        args['snap']     = 60
        args['on_error'] = 'message'
        args['format']   = 'pcap'
        args['filename'] = dttofn()
    return args


def process_injector(direction, **node_args):
    if direction == 'forward':
        return dict(interface = process_general(**node_args)['tx_intf'])
    elif direction == 'backward':
        return dict(interface = process_general(**node_args)['rx_intf'])
    else:
        exit("Injector direction not recognised")

###############################################################################

# SolarCapture setup - threads and nodes

def sc_thread_setup(thread_group):
    # Three threads = each direction has a VI, plus a writer thread
    #
    # Any program with a delay node needs force_sw_timestamps enabled
    # (set to 1) as the delay node's timestamps are done in software.
    # Without it set, the delay node will have no tangible effect.
    # With it set for only one direction, hw & sw timestamps are
    # incompatible due to non-aligned origins.
    vift = get_thread(thread_group, 2)    # VI forward thread
    vibt = get_thread(thread_group, 4)    # VI backward thread
    writ = get_thread(thread_group, 6)    # Writer thread
    return (vift, vibt, writ)


def sc_vi_setup(thread_group, fwd_thread, bkwd_thread, **general_args):
    vif = fwd_thread.new_vi(general_args['rx_intf'],
                      attr=dict(force_sw_timestamps=1))
    vib = bkwd_thread.new_vi(general_args['tx_intf'],
                      attr=dict(force_sw_timestamps=1))
    vif.add_stream(thread_group.new_stream('all'))
    vib.add_stream(thread_group.new_stream('all'))
    return (vif, vib)


def sc_affecting_node_setup(fwd_thread, bkwd_thread, **node_args):
    sorepkt_lib     = 'sct_sorepkt_burst_rand.so'
    node_delay      = fwd_thread.new_node('sc_delay_line',
                                          args=process_delay(**node_args))
    node_drop       = fwd_thread.new_node('sct_sorepkt_burst_rand_drop_n',
                                          library=sorepkt_lib,
                                          args=process_drop(**node_args))
    node_jitter     = fwd_thread.new_node('sct_jitter',
                                          args=process_jitter(**node_args)) \
                      if node_args[S_JITT_NAME].jitter != 'none' else None
    node_injector_f = fwd_thread.new_node('sc_injector',
                                          args=process_injector('forward',
                                                                **node_args))
    node_injector_b = bkwd_thread.new_node('sc_injector',
                                           args=process_injector('backward',
                                                                 **node_args))
    return (node_delay, node_drop, node_jitter, node_injector_f,
            node_injector_b)


def sc_capturing_node_setup(fwd_thread, bkwd_thread, write_thread,
                            **node_args):
    node_pass_f_1   = fwd_thread.new_node('sc_pass_n',
                                          args=process_pass_start(**node_args))
    node_pass_b_1   = bkwd_thread.new_node('sc_pass_n',
                                           args=process_pass_start(**node_args))
    node_pass_f_2   = fwd_thread.new_node('sc_pass_n',
                                          args=process_pass(**node_args))
    node_pass_b_2   = bkwd_thread.new_node('sc_pass_n',
                                           args=process_pass(**node_args))
    node_select_f   = fwd_thread.new_node('sc_link_selector',
                                          args={})
    node_select_b   = bkwd_thread.new_node('sc_link_selector',
                                           args={})
    node_f_reader   = write_thread.new_node('sc_fd_reader',
                                            args=process_f_reader(**node_args))
    node_l_reader   = write_thread.new_node('sc_line_reader',
                                            args={})
    node_writer     = write_thread.new_node('sc_writer',
                                            args=process_writer(**node_args))
    node_exit       = write_thread.new_node('sc_exit',
                                            args=process_exit(**node_args))
    return (node_pass_f_1, node_pass_b_1, node_pass_f_2, node_pass_b_2,
            node_select_f, node_select_b, node_f_reader, node_l_reader,
            node_writer, node_exit)


def sc_connect_affecting_nodes(vi_fwd, vi_bk, *nodes):
    node_delay, node_drop, node_jitter, node_injector_f, node_injector_b = \
            nodes
    # Forward nodes
    sc.connect(vi_fwd,              node_drop)
    if node_jitter:
        sc.connect(node_drop,       node_jitter)
        sc.connect(node_jitter,     node_delay)
    else:
        sc.connect(node_drop,       node_delay)
    sc.connect(node_delay,          node_injector_f)
    # Backward node(s)
    sc.connect(vi_bk,               node_injector_b)


def sc_connect_capturing_nodes(vi_f, vi_b, *nodes):
    node_injector_f, node_injector_b, \
    node_pass_f_1, node_pass_b_1, node_pass_f_2, node_pass_b_2, \
    node_select_f, node_select_b, node_f_reader, node_l_reader, \
    node_writer, node_exit = \
            nodes
    # Forward nodes
    sc.connect(node_injector_f,                 node_pass_f_1)
    sc.connect(node_pass_f_1,                   node_writer)
    sc.connect(node_pass_f_1,   'the_rest',     node_select_f)
    sc.connect(node_select_f,                   node_pass_f_2)
    sc.connect(node_pass_f_2,                   node_writer)
    # Backward nodes
    sc.connect(node_injector_b,                 node_pass_b_1)
    sc.connect(node_pass_b_1,                   node_writer)
    sc.connect(node_pass_b_1,   'the_rest',     node_select_b)
    sc.connect(node_select_b,                   node_pass_b_2)
    sc.connect(node_pass_b_2,                   node_writer)
    # Control nodes
    sc.connect(node_f_reader,                   node_l_reader)
    sc.connect(node_l_reader,                   node_select_b,  'controller')
    sc.connect(node_select_b,   'controller',   node_select_f,  'controller')
    # Exit node
    sc.connect(node_writer,                     node_exit)


def sc_setup(**node_args):
    '''

sorepkt_selective_writer connectivity digraph:

Numbers indicate node IDs, as given by solar_capture_monitor dump;
Some nodes have two numbers - the former is the main node, the
latter the internal control node.
_____        _________________         ___________
| VI | ----> | AFFECTING NODE | ----> | INJECTOR |
------       ------------------       ------------
             0 1                          |      2
                                          V
                                      _________
                                      | PASS_N |
                                      ----------
                                     /    |    4
                                    /     V
                                   /  ________________
                                  /   | LINK_SELECTOR |
                                 /    ----------------- _
                                /     8 9 |            |\
                               /          V              \
                               \      _________           \
                                \     | PASS_N |           \
                                 \    ----------            \
                                  \       |    6             \
                                   \      V                   \
                   ___________     _\|_________                \
                   ||| EXIT ||| <---- | WRITER | 18            /
                   ------------     _ ----------              /
                                    /|    ^                  /
                                   /      |                 /
                                  /   _________            /
                                 /    | PASS_N |          /
                                /     ----------         /
                               /          ^   7         /
                               \          |            /
                                \     ________________/       ______________
                                 \    | LINK_SELECTOR | <---- | LINE_READER |
                                  \   -----------------       ---------------
                                   \      ^       10 11             ^   13
                                    \     |                         |
                                     \_________               ______________
                                      | PASS_N | 5            | FILE_READER |
                                      ----------              ---------------
                                          ^                             12
                                          |
_____                                 ___________
| VI | -----------------------------> | INJECTOR | 3
------                                 ------------

    '''

    if len(node_args) != 8:
        exit("Incorrect number of argument groups provided: 8 expected, " + \
             "%d provided" % len(node_args))

    general_args        = process_general(**node_args)
    capture             = general_args['capture']

    tg = sc.new_session()
    vift, vibt, writ    = sc_thread_setup(tg)
    vif, vib            = sc_vi_setup(tg, vift, vibt, **general_args)

    # Create and connect nodes
    nodes_affecting     = sc_affecting_node_setup(vift,
                                                  vibt,
                                                  **node_args)
    sc_connect_affecting_nodes(vif, vib, *nodes_affecting)
    if capture == 'on':
        nodes_capturing = sc_capturing_node_setup(vift,
                                                  vibt,
                                                  writ,
                                                  **node_args)
        sc_connect_capturing_nodes(vif,
                                   vib,
                                   *(nodes_affecting[-2:] + nodes_capturing))
    return tg

###############################################################################

# Run SolarCapture

def sc_run(tg):
    try:
        tg.go()
        while True:
            time.sleep(10000)
    except KeyboardInterrupt:
        sys.exit(128 + signal.SIGINT)
    except:
        raise

###############################################################################

# Run script

def main():
    # Interrupts handlers
    signal.signal(signal.SIGQUIT,   signal_handler)
    signal.signal(signal.SIGHUP,    signal_handler)
    signal.signal(signal.SIGTERM,   signal_handler)
    # Run program
    sc_run(sc_setup(**extract(parse())))

###############################################################################

if __name__ == '__main__':
    main()

###############################################################################
###############################################################################
###############################################################################
