'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''

import os, re, sys, copy
import solar_capture


def int32(s):
    v = int(s)
    if not (-1 << 31) <= v < (1 << 31):
        raise ValueError("%d out of range for int32" % v)
    return v


def uint32(s):
    v = int(s)
    if not 0 <= v < (1 << 32):
        raise ValueError("%d out of range for uint32" % v)
    return v


class Arg(object):
    handler = None
    default = None
    def __init__(self, name, handler=None, default=None, usage=None,
                 repeatable=False, hidden=False):
        self.name = name
        if handler is not None:
            self.handler = handler
        self.default = default
        self.usage = usage
        self.repeatable = repeatable
        self.hidden = hidden


class Str(Arg):
    def handler(self, config, k, v):
        config.set_key(k,v)


class Float(Arg):
    def handler(self, config, k, v):
        config.set_key(k, float(v))


class Int(Arg):
    def handler(self, config, k, v):
         config.set_key(k, int32(v))


class Uint(Arg):
    def handler(self, config, k, v):
         config.set_key(k, uint32(v))


class Posint(Arg):
    def handler(self, config, k, v):
        i = uint32(v)
        if i == 0:
            raise ValueError("Value of %s must be > 0: %d" % (k, i))
        config.set_key(k, i)


class Bool(Arg):
    def handler(self, config, k, v):
        v = int(v)
        if v not in [0, 1]:
            raise ValueError("%s: expected 0 or 1" % k)
        config.set_key(k, v)


class ConfigFile(Arg):
    hidden = False
    name = 'config_file'
    usage = """  Specify a file containing a list of arguments, one per line.
  The syntax for specifying arguments is exactly the same as when
  specifying them on the command line.

  The one exception is that keys which take a semicolon-separated list
  of values may be specified multiple times; these will be merged
  together for repeats that apply to the same capture.

  When parsing the list of command line arguments, the "config_file" argument
  is replaced with the list of arguments read from the config file, and
  parsing then proceeds as normal. Thus arguments in the config file will
  obey the normal rules for precedence and global vs per-capture handling

  For example:

  sc.cfg:
    snap=60
    streams=tcp:192.168.1.1:5000
    streams=udp:127.0.0.1:8080

  ./solar_capture config_file=sc.cfg eth2=/tmp/eth2.pcap
"""

def usage_error(usage_text):
    sys.stdout.write(usage_text)
    sys.exit(1)


def err(msg):
    sys.stderr.write("ERROR: %s\n" % msg)
    sys.exit(2)


def find(arg, char):
    try: return arg.index(char)
    except ValueError: return len(arg)


def help_topic(arg):
    sys.stdout.write("%s:\n" % arg.name)
    sys.stdout.write(arg.usage)
    if type(arg.default) in [int, str, float] and "Default:" not in arg.usage:
        sys.stdout.write("\n  Default: %s\n" % arg.default)


def help_all(args):
    for name, arg in sorted(args.items()):
        if not arg.hidden:
            help_topic(arg)
            sys.stdout.write("-" * 78 + "\n")


def read_arg_file(f, known_args):
    repeatable_keys = [x.name for x in known_args.values() if x.repeatable]
    data = file(f).read()
    args = []
    arg_indexes = {} # key -> index into args
    for line in data.split('\n'):
        arg = line.split('#')[0].strip()
        if arg:
            if '=' in arg:
                k, v = arg.split('=', 1)
            else:
                k, v = arg, True
            if k in repeatable_keys and k in arg_indexes:
                # a key has been repeated, append the new value
                # to the existing one, separated by ';'
                args[arg_indexes[k]] += ';' + str(v)
            else:
                if k in known_args and k != 'interface':
                    arg_indexes[k] = len(args)
                else:
                    # Treat unknown key as interface spec. Reset known
                    # indexes as repeatable args can only be appended
                    # to within the same interface section
                    arg_indexes = {}
                args.append(arg)
    return args


class Config(object):
    def __init__(self, defaults):
        self.defaults = defaults
        self.instances = []

    def new_instance(self, **updates):
        self.instances.append(copy.deepcopy(self.defaults))
        self.instances[-1].update(updates)

    @property
    def current(self):
        return ([self.defaults] + self.instances)[-1]

    def set_key(self, k, v):
        self.current[k] = v

    def get_key(self, k):
        return self.current[k]


def iter_args(known_args, config, args, handle_unknown_arg):
    for arg in args:
        if find(arg, '=') < find(arg, ':'):
            k, v = arg.split('=', 1)
            if k == 'config_file':
                new_args = read_arg_file(v, known_args)
                iter_args(known_args, config, new_args, handle_unknown_arg)

            elif k in known_args:
                try:
                    known_args[k].handler(config, k, v)
                except (KeyError, ValueError), e:
                    err("Bad value %r for key %r" % (v, k))
            elif handle_unknown_arg:
                handle_unknown_arg(config, k, v)
            else:
                err("'%s' is not an interface or an option" % k)
        elif ':' in arg:
            node_type, opts = arg.split(':', 1)
            f = {'name': node_type, 'args': {}}
            if opts:
                for opt in opts.split(';'):
                    if '=' in opt:
                        k, v = opt.split('=', 1)
                    else:
                        k, v = opt, ''
                    f['args'][k] = v
            config.get_key('extensions').append(f)
        elif arg in config.defaults:
            config.set_key(arg, True)
        elif handle_unknown_arg:
            handle_unknown_arg(config, arg, None)
        else:
            err("Unparsable argument %r" % arg)


def parse_args(args, known_args, usage_text, handle_unknown_arg=None):
    if (not args) or '-h' in args or '--help' in args:
        sys.stdout.write(usage_text)
        sys.exit(0)

    if '-v' in args or '--version' in args:
        sys.stdout.write("%s\n" % solar_capture.SC_VER)
        sys.exit(0)

    if 'help' in args:
        known_args['config_file'] = ConfigFile
        i = args.index('help')
        if i + 1 == len(args):
            usage_error(usage_text)
        option = args[i + 1]
        if option == 'all':
            help_all(known_args)
        elif option in known_args and not known_args[option].hidden:
            help_topic(known_args[option])
        else:
            err("Unknown help topic %r" % option)
        sys.exit(1)

    if '-v' in args or '--version' in args:
        sys.stdout.write("%s\n" % solar_capture.SC_VER)
        sys.exit(0)

    defaults = dict((a.name, a.default) for a in known_args.values())
    defaults.setdefault('extensions', [])
    config = Config(defaults)

    iter_args(known_args, config, args, handle_unknown_arg)

    return config.instances
