'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''

from . import solar_capture_c
from . import cli
import os, stat, socket, re, types


class Error(Exception):
    """Base class for exceptions in this module."""
    def __init__(self, msg=''):
        self.msg = msg
    def __str__(self):
        return self.msg


class NodeFactoryLookupError(Error): pass


class SCError(Error):
    def __init__(self, err_msg='', err_func=None, err_file=None,
                 err_line=None, err_errno=None):
        self.msg = err_msg
        self.func = err_func
        self.file = err_file
        self.line = err_line
        self.errno = err_errno
        if 'ERROR:' not in self.msg:
            self.msg = 'ERROR: ' + self.msg
        self.msg = self.msg.rstrip('\n')

    def detail(self):
        if self.func:
            return 'File "%s", line %d, in %s:\n%s (errno=%d)' % (
                self.file, self.line, self.func, self.msg, self.errno)
        else:
            return self.msg


# The solar_capture_c module defines a low-level exception class.
# Wrap all calls into the module and replace any exceptions with
# more user-friendly ones
class SCMeta(type):
    def __getattr__(self, name):
        c_obj = getattr(solar_capture_c, name)
        if callable(c_obj):
            def f(*args, **kwargs):
                if len(args)>0 and type(args[0]) == bytes:
                  args = (str(args[0],'utf-8'),) + args[1:]
                try:
                    return c_obj(*args, **kwargs)
                except solar_capture_c.SCError as e:
                    raise SCError(*e.args)
            return f
        else:
            return c_obj

# And apply that to the sc class that we export. In python 3 we use metaclass.
class sc(metaclass=SCMeta):
    pass

discard_opts = {
    'NONE'            : 0,
    'CSUM'            : sc.SC_CSUM_ERROR,
    'CRC'             : sc.SC_CRC_ERROR,
    'TRUNCATED'       : sc.SC_TRUNCATED,
    'MCAST_MISMATCH'  : sc.SC_MCAST_MISMATCH,
    'UCAST_MISMATCH'  : sc.SC_UCAST_MISMATCH,
}

SC_VER = sc.SC_VER

VLAN_PROCFILE = '/proc/net/vlan/config'
def get_vlan_list():
    if os.path.isfile(VLAN_PROCFILE):
        for line in file(VLAN_PROCFILE):
            spl = map(str.strip, line.split('|'))
            if len(spl) == 3 and spl[1].isdigit():
                yield spl


def discard_mask_list_to_int(list):
    """Raises KeyError if list contains any invalid strings."""
    mask = 0
    for d in list:
        mask |= discard_opts[d.upper()]
    return mask


def discard_mask_int_to_list(val, ignore_bad=True):
    """Raises IndexError if val is invalid."""
    list = []
    bi = 0
    val_in = val
    while val:
        if val & 1:
            match = [k for k,v in discard_opts.items() if v == (1 << bi)]
            if match:
                list.append(match[0])
            elif not ignore_bad:
                raise IndexError("Bad discard mask '%x'" % val_in)
        val >>= 1
        bi += 1
    return list


class Thread(object):
    def __init__(self, session, end_of_pa=None, attr={}):
        assert end_of_pa is None
        self.__thread_index__ = sc.thread_alloc(attr, session)
        self.session = session

    def new_vi_from_group(self, vi_group, end_of_pa=None, attr={}):
        assert end_of_pa is None
        assert type(vi_group) is ViGroup
        return VI(thread=self, intf_or_vi_group=vi_group, attr=attr)

    def new_vi(self, layer_2_interface, end_of_pa=None, attr={}):
        assert end_of_pa is None
        assert isinstance(layer_2_interface, str)
        return VI(thread=self, layer_2_interface=layer_2_interface, attr=attr)

    def new_node(self, name=None, end_of_pa=None, factory=None,
                 library='', args={}, attr={}):
        assert end_of_pa is None
        if factory is None:
            assert isinstance(name, str)
            factory = NodeFactory(name=name, library=library)
        else:
            assert not library
        return Node(thread=self, node_factory=factory, args=args, attr=attr)

    def new_node_from_str(self, node_spec, end_of_pa=None, attr={}):
        assert end_of_pa is None
        assert isinstance(node_spec, str)
        return Node(thread=self, node_factory=None, attr=attr,
                    node_spec=node_spec)

    def new_mailbox(self, name=None, end_of_pa=None, attr={}):
        assert end_of_pa is None
        return Mailbox(thread=self, attr=attr)


class Session(object):
    def __init__(self, end_of_pa=None, attr={}):
        assert end_of_pa is None
        # Ensure __session_index__ exists in case session_alloc raises
        # an exception (in which case __del__ is still called).
        self.__session_index__ = None
        self.__session_index__ = sc.session_alloc(attr)

    def __del__(self):
        if self.__session_index__ is not None:
            sc.session_destroy(self)

    def new_thread(self, end_of_pa=None, attr={}):
        assert end_of_pa is None
        return Thread(self, attr=attr)

    def new_vi_group(self, layer_2_interface, num_vis, end_of_pa=None, attr={}):
        assert end_of_pa is None
        return ViGroup(session=self, layer_2_interface=layer_2_interface,
                       n_vis=num_vis, attr=attr)

    def new_stream(self, str=None, end_of_pa=None, attr={}):
        assert end_of_pa is None
        return Stream(str, attr=attr)

    def prepare(self):
        sc.session_prepare(self)

    def go(self):
        sc.session_go(self)

    def run(self):
        return sc.session_run(self)

    def pause(self):
        sc.session_pause(self)

    def stop(self, exit_code=0):
        sc.session_stop(self, exit_code)

    def join_multicast_groups(self, def_intf, groups):
        assert isinstance(def_intf, str)
        if not isinstance(groups, list):
            groups = [groups]
        def_vlan = None
        for csl in groups:
            assert isinstance(csl, str)
            intf = def_intf
            vlan = def_vlan
            group = None
            for bit in csl.split(','):
                mo = re.match(r'vid=([0-9]+)$|intf=([^,]+)$|([^=]+)$', bit)
                if not mo:
                    raise ValueError("Unable to parse mcast group '%s'" % csl)
                v, i, g = mo.groups()
                if v is not None:
                    vlan = v
                elif i is not None:
                    intf = i
                else:
                    group = g
            if group is None:
                def_intf = intf
                def_vlan = vlan
                continue
            if vlan:
                for vlan_intf, vlan_id, base_intf in get_vlan_list():
                    if base_intf == intf and vlan_id == vlan:
                        intf = vlan_intf
                        break
                else:
                    raise SCError("Interface %s has no VLAN with ID %s" %
                                  (intf, vlan) )
            sc.join_mcast_group(self, intf, group)


def new_session(end_of_pa=None, attr={}):
    assert end_of_pa is None
    return Session(attr=attr)


def get_mcast_group(session, stream, attr={}):
    if isinstance(stream, Stream):
        stream = stream.get_str()
    return sc.sc_stream_get_mcast_group(attr, session, stream)


class ViGroup(object):
    def __init__(self, session, layer_2_interface, n_vis,
                 end_of_pa=None, attr={}):
        assert end_of_pa is None
        assert isinstance(session, Session)
        assert isinstance(layer_2_interface, str)
        assert isinstance(n_vis, int)
        self.interface = layer_2_interface
        self.session = session
        self.__vigroup_index__ = sc.vi_group_alloc(attr, session,
                                                   layer_2_interface, n_vis)
    def add_stream(self, stream):
        sc.vi_group_add_stream(self, stream.get_str(), stream.get_attr())


class VI(object):
    def __init__(self, thread, intf_or_vi_group=None, end_of_pa=None,
                 layer_2_interface=None, vi_group=None, attr={}):
        assert end_of_pa is None
        assert isinstance(thread, Thread)
        if layer_2_interface:
            assert isinstance(layer_2_interface, str)
            assert intf_or_vi_group is None
            assert vi_group is None
            intf_or_vi_group = layer_2_interface
        if vi_group:
            assert isinstance(vi_group, ViGroup)
            assert intf_or_vi_group is None
            assert layer_2_interface is None
            intf_or_vi_group = vi_group
        self.thread = thread
        if isinstance(intf_or_vi_group, str):
            self.interface = intf_or_vi_group
            self.__vi_index__ = sc.vi_alloc(attr, thread, self.interface)
        else:
            assert isinstance(intf_or_vi_group, ViGroup)
            vi_group = intf_or_vi_group
            self.interface = vi_group.interface
            self.__vi_index__ = sc.vi_alloc_from_group(thread, attr, vi_group)
    def set_recv_node(self, node, name=None):
        assert isinstance(node, Node)
        assert name is None or isinstance(name, str)
        sc.vi_set_recv_node(self, node, name)
    def add_stream(self, stream):
        sc.vi_add_stream(self, stream.get_str(), stream.get_attr())
    def connect(self, *args, **kwargs):
        return connect(self, *args, **kwargs)
    def get_interface_name(self):
        return sc.vi_get_interface_name(self)


class NodeFactory(object):
    def __init__(self, name, library=None):
        assert type(name) is str
        assert isinstance(library, str) or library is None
        if library is None:
            library = ''
        self.factory_name = name
        self.library_name = library


class Node(object):
    def __init__(self, thread, node_factory, end_of_pa=None, args={}, attr={},
                 node_spec=None):
        assert end_of_pa is None
        assert isinstance(thread, Thread)
        if node_spec is not None:
            assert node_factory is None
            assert isinstance(node_spec, str)
            ret = sc.node_alloc_from_str(attr, thread, node_spec)
        else:
            assert isinstance(node_factory, NodeFactory)
            assert isinstance(args, dict)
            for val in args.values():
                assert isinstance(val, (int,str,float))
            ret = sc.node_alloc(attr, thread, node_factory.factory_name,
                                node_factory.library_name, args)
        if type(ret) is str:
            raise NodeFactoryLookupError(ret)
        self.__node_index__ = ret
        assert type(self.__node_index__) is int
        self.thread = thread

    def connect(self, *args, **kwargs):
        return connect(self, *args, **kwargs)

    def add_link(self, link_name, to_node, to_name=None):
        assert isinstance(link_name, str)
        assert isinstance(to_node, Node)
        assert isinstance(to_name, str) or to_name is None
        sc.node_add_link(self, link_name, to_node, to_name)

    def add_info(self, field_name, field_val):
        sc.node_add_info(self, field_name, field_val)


class Mailbox(Node):
    def __init__(self, thread, end_of_pa=None, attr={}):
        assert end_of_pa is None
        assert isinstance(thread, Thread)
        # In the C world, there is a different constructor for
        # mailboxes so this does not call Node's __init__ function.
        mi, ni = sc.mailbox_alloc(attr, thread)
        self.__node_index__ = ni
        self.__mbox_index__ = mi
        self.thread = thread
        self.peer = None
        self.recv_node = None

    def set_recv(self, node, name=None):
        assert isinstance(node, Node)
        assert node.thread == self.thread
        assert isinstance(name, str) or name is None
        sc.mailbox_set_recv(self, node, name)
        self.recv_node = node

def validate_mac(mac):
    try:
        assert type(mac) is str
        assert len(mac.split(':')) == 6
        foo = [int(m, 16) for m in mac.split(':')]
        assert 0 <= min(foo) <= max(foo) <= 255
    except:
        raise ValueError("Badly formed MAC address %r" % (mac,) )


class Stream(object):
    def __init__(self, str=None, end_of_pa=None, attr={}):
        assert end_of_pa is None
        self.__attr = attr.copy()
        self.__str = str

    def get_str(self):
        return self.__str

    def get_attr(self):
        return self.__attr


class Writer(Node):
    def __init__(self, thread, end_of_pa=None, args={}, attr={}):
        assert end_of_pa is None
        super(Writer, self).__init__(thread, NodeFactory('sc_writer'),
                                     args=args, attr=attr)


def connect_mailboxes(s, r):
    assert isinstance(s, Mailbox)
    assert isinstance(r, Mailbox)
    assert s.thread != r.thread
    sc.mailbox_connect(s, r)
    s.peer = r
    r.peer = s
    return r


def connect(from_obj, a2=None, a3=None, a4=None, end_of_pa=None, attr={},
            to_interface=None):
    """Convenience function to connect objects.  The objects may be any
    combination of Nodes, VIs or Mailboxes.  The objects can be in the same
    or different threads.  If in different threads, then mailboxes are
    automatically setup to join them.

    Usage:
      connect(from_obj, [link_name,] to_obj [, to_name])
      connect(from_obj, [link_name,] to_interface=<interface-name>)
    """

    assert end_of_pa is None

    if to_interface is not None:
        # connect(from_obj, [link_name,] to_interface=)
        assert isinstance(to_interface, str)
        assert a3 is None
        assert a4 is None
        args = dict(interface=to_interface)
        inj = from_obj.thread.new_node('sc_injector', args=args, attr=attr)
        if isinstance(a2, str):
            a3 = inj
        else:
            a2 = inj

    if isinstance(a2, str):
        # connect(from_obj, link_name, to_obj [, to_name])
        link_name = a2
        to_obj = a3
        if isinstance(a4, str):
            to_name = a4
        else:
            to_name = None
    else:
        # connect(from_obj, to_obj [, to_name])
        assert a2 is not None
        link_name = ''
        to_obj = a2
        if isinstance(a3, str):
            to_name = a3
        else:
            to_name = None
        assert a4 is None

    if isinstance(from_obj, Mailbox) and isinstance(to_obj, Mailbox) and \
            from_obj.peer is None and to_obj.peer is None:
        assert from_obj.thread != to_obj.thread
        return connect_mailboxes(from_obj, to_obj)

    if from_obj.thread != to_obj.thread:
        # Idea: We could remember mailboxes we've made here so we can make
        # use of the reverse path in another call.
        fmb = from_obj.thread.new_mailbox(attr=attr)
        tmb = to_obj.thread.new_mailbox(attr=attr)
        connect_mailboxes(fmb, tmb)
        connect(from_obj, link_name, fmb)
        return connect(tmb, '', to_obj, to_name)

    if isinstance(to_obj, VI):
        args = dict(interface=to_obj.get_interface_name())
        to_obj = to_obj.thread.new_node('sc_injector', args=args, attr=attr)

    if isinstance(from_obj, Mailbox):
        from_obj.set_recv(to_obj, to_name)
    elif isinstance(from_obj, Node):
        from_obj.add_link(link_name, to_obj, to_name)
    elif isinstance(from_obj, VI):
        from_obj.set_recv_node(to_obj, to_name)
    else:
        assert False, "Bad from_obj '%s'" % repr(from_obj)

    return to_obj


def initgroups(username, gid):
    assert isinstance(username, str)
    assert isinstance(gid, int)
    sc.sc_initgroups(username, gid)
