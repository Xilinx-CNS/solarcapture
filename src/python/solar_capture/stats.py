'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''

import os, sys, errno, pwd, re
import solar_capture.shm as shm


class InstanceBase(shm.CompoundInstance):
    # Base class for the types that we know about.
    def __init__(self, type_name, obj_id, main_obj, obj_name, session):
        super(InstanceBase, self).__init__(obj_id, [main_obj])
        self.name = obj_name
        self.type_name = type_name
        self.session = session

    def __getattr__(self, name):
        try:
            return super(InstanceBase, self).__getattr__(name)
        except AttributeError, e:
            # The code here allows us to write things like "vi.pool.n_bufs".
            # If we are accessing field 'foo', and the object has a field
            # called 'foo_id', then we return the appropriate object.
            if name.endswith('_id'):
                raise e
            try:
                id = getattr(self, name + '_id')
            except:
                raise e
            if name.endswith('thread'):
                type = Thread
            elif name.endswith('mailbox'):
                type = Mailbox
            elif name.endswith('node'):
                type = Node
            elif name.endswith('vi'):
                type = Vi
            elif name.endswith('pool'):
                type = Pool
            else:
                raise e
            objs = self.session.object_list
            objs = [o for o in objs if isinstance(o, type) and o.id == id]
            if len(objs) == 1:
                return objs[0]
            else:
                raise e

    def __str__(self):
        return "%s(%s)" % (self.type_name, self.obj_id)


class Thread(InstanceBase):
    def __init__(self, *args):
        super(Thread, self).__init__("Thread", *args)
        # Next line ensures all objects have a thread_id attribute.
        self.thread_id = self.id
        self.type_order = 0


class Mailbox(InstanceBase):
    def __init__(self, *args):
        super(Mailbox, self).__init__("Mailbox", *args)
        self.type_order = 3


class Node(InstanceBase):
    def __init__(self, *args):
        super(Node, self).__init__("Node", *args)
        self.type_order = 2
        self.links = []


class Vi(InstanceBase):
    def __init__(self, *args):
        super(Vi, self).__init__("Vi", *args)
        self.type_order = 1


class Pool(InstanceBase):
    def __init__(self, *args):
        super(Pool, self).__init__("Pool", *args)
        self.type_order = 4


type_name_to_class = {
    'sc_thread_stats'  : Thread,
    'sc_mailbox_stats' : Mailbox,
    'sc_vi_stats'      : Vi,
    'sc_node_stats'    : Node,
    'sc_pool_stats'    : Pool,
    }


class Session(object):

    def __init__(self, session_dir):
        self.dir = session_dir
        self.__field_names = []
        self.thread_id = -1
        self.type_name = 'Session'
        self.__thread_mmaps = dict()
        self.__load_types()
        self.__load_objects()
        self.session = self
        self.obj_id = "s%s" % self.id

    def __load_types(self):
        sc_types_f = os.path.join(self.dir, 'sc_types')
        globals = dict(sw=shm)
        self.type_map = dict()
        execfile(sc_types_f, globals, self.type_map)  # ?? fixme: insecure

    def __sc_info_line(self, line, sc_info_f):
        fs = line.split()
        if fs[0] == 'info:':
            setattr(self, fs[1], ' '.join(fs[2:]))
            self.__field_names.append(fs[1])
        elif fs[0] == 'obj:':
            type_name, obj_id, obj_name, thread_id, offset, size = fs[1:]
            offset = int(offset)
            size = int(size)
            obj = self.__load_object(type_name, obj_id, thread_id, offset, size)
            self.__add_object(obj, obj_name)
        elif fs[0] == 'objinfo:':
            objinfo, obj_id, info_type, key_val = line.split(None, 3)
            key_val = key_val.split(None, 1)
            key = key_val[0]
            if len(key_val) == 1:
                val = ""
            else:
                val = key_val[1]
            obj = self.object_map[obj_id]
            if info_type == 'int':
                obj.add_static_field(key, int(val))
            elif info_type == 'str':
                obj.add_static_field(key, str(val).strip())
            elif info_type == 'intlist':
                if not hasattr(obj, key):
                    obj.add_static_field(key, [])
                getattr(obj, key).append(int(val))
            else:
                # Perhaps better to warn and continue?
                raise AssertionError("Bad objinfo type '%s'" % info_type)
        elif fs[0] == 'nodelink:':
            mo = re.match(r'nodelink: (n[0-9]+) (n[0-9]+) "([^"]*)" (.*)', line)
            from_id, to_id, link_name, to_name = mo.groups()
            if to_name == 'NULL':
                to_name = None
            else:
                to_name = to_name[1:-1]
            from_node = self.object_map[from_id]
            to_node = self.object_map[to_id]
            from_node.links.append((link_name, to_node, to_name))
        else:
            raise AssertionError("Bad sc_info entry '%s'" % fs[0])

    def __load_objects(self):
        sc_info_f = os.path.join(self.dir, 'sc_info')
        self.object_map = dict(s=self)
        self.object_list = [self]
        for line in open(sc_info_f).readlines():
            try:
                self.__sc_info_line(line, sc_info_f)
            except:
                sys.stderr.write("ERROR: in %s\n" % sc_info_f)
                sys.stderr.write("ERROR: unexpected: %s\n" % line)
                raise

    def __thread_mmap(self, thread_id):
        thread_id = int(thread_id)
        if thread_id not in self.__thread_mmaps:
            f = os.path.join(self.dir, 'sc_thread%d.tss' % thread_id)
            self.__thread_mmaps[thread_id] = shm.MmapFile(f)
        return self.__thread_mmaps[thread_id]

    def __load_object(self, type_name, obj_id, thread_id, offset, size):
        type = self.type_map[type_name]
        assert type.bytes == size, "%d %d" % (type.bytes, size)
        mmap = self.__thread_mmap(thread_id)
        obj = type.instantiate(obj_id, mmap, offset)
        return obj

    def __add_object(self, obj, obj_name):
        if obj.type.name in type_name_to_class:
            assert obj.obj_id not in self.object_map
            custom_type = type_name_to_class[obj.type.name]
            obj = custom_type(obj.obj_id, obj, obj_name, self)
            self.object_map[obj.obj_id] = obj
            self.object_list.append(obj)
        else:
            if obj.obj_id in self.object_map:
                assert isinstance(self.object_map[obj.obj_id], \
                                      shm.CompoundInstance)
                self.object_map[obj.obj_id].add_sub_instance(obj)
            else:
                self.object_map[obj.obj_id] = obj
                self.object_list.append(obj)

    def field_names(self):
        return self.__field_names

    def is_running(self):
        """Returns True if this session is running, else False.  Raises an
           OSError exception if we can't tell because the process is
           running as a different user."""
        p1 = os.path.join('/proc', str(self.pid), 'fd', str(self.sc_info_fd))
        p2 = os.path.join(self.dir, 'sc_info')
        try:
            return os.path.samefile(p1, p2)
        except OSError:
            e = sys.exc_info()[1]
            if e.errno == errno.ENOENT:
                return False
            elif e.errno == errno.EACCES:
                raise
            else:
                sys.stderr.write("UNEXPECTED: errno=%d for %s or %s\n" % \
                                     (e.errno, p1, p2))
                raise

    def known_running(self):
        """Returns True if this session is running, else False if not
           running or we can't tell."""
        try:
            return self.is_running()
        except:
            return False


def looks_like_session_dir(session_dir):
    return os.path.isfile(os.path.join(session_dir, 'sc_info'))


def get_session_info(session_dir):
    info = dict(dir=session_dir)
    for line in open(os.path.join(session_dir, 'sc_info')).readlines():
        fs = line.split()
        if fs[0] == 'info:':
            info[fs[1]] = ' '.join(fs[2:])
    if not('pid' in info and 'sc_info_fd' in info):
        raise Exception("%s/sc_info is corrupt" % (session_dir,) )
    return info

def get_session_infos(session_dirs):
    infos = []
    bad_dirs = []
    for sd in session_dirs:
        try:
            infos.append(get_session_info(sd))
        except:
            bad_dirs.append(sd)
    return infos, bad_dirs


def uid_can_access_session_dir(sd, uid):
    try:
        return uid is None or \
            os.stat(os.path.join(sd, 'sc_types')).st_uid == int(uid)
    except:
        return False


def __find_session_dirs_in(in_dir, prefix=None):
    session_dirs = []
    for d in os.listdir(in_dir):
        dir = os.path.join(in_dir, d)
        if prefix and prefix not in dir:
            continue
        if looks_like_session_dir(dir):
            session_dirs.append(dir)
        elif os.path.isdir(dir):
            # NB. Do not propagate prefix!
            session_dirs += __find_session_dirs_in(dir)
    session_dirs.sort()
    return session_dirs


def find_session_dirs_for_process(pid):
    """DEPRECATED, use find_session_dirs instead."""
    return find_session_dirs(pid=pid, running=True)


def find_session_dirs(base_dir=None, pid=None, session_id=None, running=None,
                      uid=None):
    if not base_dir:
        base_dir = '/var/tmp'
        prefix = 'solar_capture_'
    else:
        prefix = None
    session_dirs = __find_session_dirs_in(base_dir, prefix=prefix)
    session_dirs = [sd for sd in session_dirs \
                    if uid_can_access_session_dir(sd, uid)]
    if pid is not None or session_id is not None or running is not None:
        infos, bad = get_session_infos(session_dirs)
        if pid is not None:
            infos = [i for i in infos if int(i['pid']) == int(pid)]
        if session_id is not None:
            infos = [i for i in infos if int(i['id']) == int(session_id)]
        if running is not None:
            assert running in [True, False], repr(running)
            infos = [i for i in infos if running == is_running(i)]
        session_dirs = [i['dir'] for i in infos]
    return session_dirs


def is_running(info):
    p1 = os.path.join('/proc', str(info['pid']), 'fd', str(info['sc_info_fd']))
    p2 = os.path.join(info['dir'], 'sc_info')
    try:
        if os.path.samefile(p1, p2):
            return 1
        else:
            return 0
    except OSError:
        e = sys.exc_info()[1]
        if e.errno == errno.ENOENT:
            return 0
        elif e.errno == errno.EACCES:
            return -1
        else:
            sys.stderr.write("UNEXPECTED: errno=%d for %s or %s\n" % \
                                 (e.errno, p1, p2))
            return -1


def group_sessions(sessions):
    """Group the given sessions into those that are running, stopped and
    those for which we can't tell.  Returns a 3-tuple of lists: (running,
    stopped, unknown)."""
    running = []
    stopped = []
    unknown = []
    for s in sessions:
        try:
            if s.is_running():
                running.append(s)
            else:
                stopped.append(s)
        except:
            unknown.append(s)
    return (running, stopped, unknown)


letter_to_type = dict(t=Thread,
                      m=Mailbox,
                      n=Node,
                      v=Vi,
                      p=Pool)

name_to_type = dict(Thread=Thread,
                    Mailbox=Mailbox,
                    Node=Node,
                    Vi=Vi,
                    Pool=Pool)


def find_objs(objs, obj_type=None, obj_id=None, node_type=None, fields=[],
              obj_type_or_node_type_or_name=None):
    if obj_type_or_node_type_or_name is not None:
        mo = re.match(r'([a-z])(\d+)$', obj_type_or_node_type_or_name)
        if mo and mo.group(1) in letter_to_type:
            obj_id = obj_type_or_node_type_or_name
            obj_type_or_node_type_or_name = None
    def is_stats_type(o, type_name):
        return type_name in name_to_type and \
            isinstance(o, name_to_type[type_name])
    def accept(o):
        if obj_type_or_node_type_or_name is not None:
            otnton = obj_type_or_node_type_or_name
            ok = isinstance(o, Node) and o.node_type_name == otnton
            ok = ok or is_stats_type(o, otnton)
            ok = ok or o.name == otnton
            if 'group_name' in o.field_names():
                ok = ok or o.group_name == otnton
            ok = ok or o.obj_id == otnton
            if not ok:
                return False
        if obj_type is not None and not isinstance(o, obj_type):
            return False
        if obj_id is not None and o.obj_id != obj_id:
            return False
        if node_type is not None:
            if not isinstance(o, Node) or o.node_type_name != node_type:
                return False
        for f in fields:
            if type(f) is str:
                if f not in o.field_names():
                    return False
            elif type(f) is tuple and len(f) == 2:
                if f[0] not in o.field_names() or getattr(o, f[0]) != f[1]:
                    return False
            else:
                raise TypeError("bad field '%s'" % repr(f))
        return True
    return [o for o in objs if accept(o)]


def sessions_find_objs(sessions, **kwargs):
    objs = []
    for session in sessions:
        objs += find_objs(session.object_list, **kwargs)
    return objs
