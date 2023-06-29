'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''

import struct, mmap

class OffsetMismatch(Exception):
    """Offset unknown due to padding"""
    pass
#####################################################################
def strip_nuls(str):
    idx = str.find(b'\0')
    if idx >= 0:
        str = str[:idx]
    return str

######################################################################

class TypeBase(object):
    pass


class InstanceBase(object):
    def __init__(self, id):
        self.obj_id = id

######################################################################

class StructType(TypeBase):
    def __init__(self, name, fields=None):
        super(StructType, self).__init__()
        self.__offset_counter = 0
        self.name = name
        self.__fields = []
        self.field_names = []
        self.struct_format = ""
        self.field_offset = dict()
        self.field_type = dict()
        if fields:
            for fld in fields:
                self.add_field(name=fld[0], type=fld[1], meta=fld[2:])
            self.done()

    def add_field(self, name, type, meta):
        field_size = struct.calcsize(type)
        if type[-1] not in 'spPx':
            # Assume primitives are naturally aligned.
            self.__offset_counter = self.__offset_counter + field_size - 1
            self.__offset_counter &= ~(field_size - 1)
        self.field_offset[name] = self.__offset_counter
        self.field_type[name] = type
        self.__offset_counter += field_size
        self.struct_format += type
        self.__fields.append((name, type, meta))
        self.field_names.append(name)

    def done(self):
        self.bytes = struct.calcsize(self.struct_format)
        if self.bytes != self.__offset_counter:
            for k in self.field_offset.iterkeys():
                self.field_offset[k] = None
        self.str_fields = []
        for i, (fname, ftype, meta) in enumerate(self.__fields):
            if ftype[-1] == 's':
                self.str_fields.append(self.__fields[i][0])
        self.fields = [f[0] for f in self.__fields]

    def instantiate(self, id, mem, offset):
        return StructInstance(self, id, mem, offset)


class StructInstance(InstanceBase):
    def __init__(self, itype, id, mem, offset):
        super(StructInstance, self).__init__(id)
        self.type = itype
        #??self.type_name = itype.name
        self.__mem = mem
        self.__offset = offset
        self.update_fields()

    def update_fields(self):
        end = self.__offset + self.type.bytes
        fields = struct.unpack(self.type.struct_format,
                               self.__mem.buf[self.__offset:end])
        kv = [(self.type.field_names[i], f) for i, f in enumerate(fields)]
        self.__fields = dict(kv)
        for fn in self.type.str_fields:
            self.__fields[fn] = strip_nuls(self.__fields[fn])

    def field_names(self):
        return self.type.field_names

    @property
    def offset(self):
        return self.__offset

    def __getattr__(self, name):
        if name in self.__fields:
            return self.__fields[name]
        raise AttributeError()

    def poke(self, field_name, val):
        type = self.type.field_type[field_name]
        if type == 'i' or type == 'Q':
            val = int(val)
        elif type == 'd':
            val = float(val)
        else:
            raise TypeError("Cannot poke %s.%s of type %s" %
                            (self.obj_id, field_name, type))
        val = struct.pack(type, val)
        off = self.__offset + self.type.field_offset[field_name]
        end = off + struct.calcsize(type)
        self.__mem.buf[off:end] = val

    def __str__(self):
        return "%s: %s %s" % \
            (self.obj_id, self.type.name, str(self.__fields))

######################################################################

class CompoundInstance(InstanceBase):
    def __init__(self, id, sub_instances=[]):
        super(CompoundInstance, self).__init__(id)
        self.__field_map = dict()
        self.__field_names = []
        self.__instances = []
        for si in sub_instances:
            self.add_sub_instance(si)

    def add_sub_instance(self, i):
        self.__instances.append(i)
        i_fields = i.field_names()
        self.__field_names += i_fields
        for fn in i_fields:
            assert fn not in self.__field_map, '%s duplicated' % str(fn)
            self.__field_map[fn] = i

    def update_fields(self):
        for i in self.__instances:
            i.update_fields()

    def field_names(self):
        return self.__field_names

    def get_all_fields(self):
        return [(fn, getattr(self, fn)) for fn in self.__field_names]

    def get_offset(self, field_name):
        if self.__field_map[field_name].type.field_offset[field_name] == None:
            raise OffsetMismatch(self.obj_id, field_name)
        return (self.__field_map[field_name].offset +
                    self.__field_map[field_name].type.field_offset[field_name])

    def add_static_field(self, field_name, field_val):
        if field_name not in self.__field_names:
            self.__field_names.append(field_name)
        setattr(self, field_name, field_val)

    def __getattr__(self, name):
        if name not in self.__field_map:
            msg = "CompoundInstance(%s) obj_id=%s has no field '%s'" % \
                (repr(self), self.obj_id, name)
            raise AttributeError(msg)
        return getattr(self.__field_map[name], name)

    def poke(self, name, val):
        if name not in self.__field_map:
            msg = "CompoundInstance(%s) obj_id=%s has no field '%s'" % \
                (repr(self), self.obj_id, name)
            raise AttributeError(msg)
        self.__field_map[name].poke(name, val)

    def __str__(self):
        return "%s: %s" % (self.obj_id, str(self.get_all_fields()))

######################################################################

class MmapFile(object):
    def __init__(self, fname_or_file):
        if type(fname_or_file) is str:
            self.file = open(fname_or_file, 'r+')
        else:
            self.file = fname_or_file
        self.file.seek(0, 2)
        self.file_len = self.file.tell()
        self.buf = mmap.mmap(self.file.fileno(), self.file_len,
                             mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
