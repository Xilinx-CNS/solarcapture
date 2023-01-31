'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''

import solar_capture.stats as stats


def session_to_dot(session, emit,
                   show_mailboxes=False, show_free_path=False):

    def node_is_mb(n):
        return n.node_type_name == 'sc_mailbox_node'

    def node_is_wanted(n):
        return not n.is_free_path or show_free_path

    def mb_is_wanted(mb):
        if not show_mailboxes:
            return False
        if show_free_path:
            return True
        if mb.send_node.is_free_path and hasattr(mb, 'peer_mailbox') and \
           mb.peer_mailbox.send_node.is_free_path:
            return False
        return True

    def add_link(frm, to, opts=''):
        if not show_mailboxes:
            while isinstance(to, stats.Node) and node_is_mb(to):
                mb = to.mailbox
                if not hasattr(mb, 'peer_mailbox'):
                    return
                rmb = mb.peer_mailbox
                if rmb.recv_node_id < 0:
                    return
                to = rmb.recv_node
        assert not isinstance(to, stats.Mailbox)
        assert not isinstance(frm, stats.Mailbox)
        frm_str = frm.obj_id
        if isinstance(frm, stats.Node):
            if not node_is_wanted(frm):
                return
            if node_is_mb(frm):
                frm_str = "%s:in" % frm.obj_id
        to_str = to.obj_id
        if isinstance(to, stats.Node):
            if not node_is_wanted(to):
                return
            if node_is_mb(to):
                to_str = "%s:out" % to.obj_id
        emit('  %s -> %s%s;' % (frm_str, to_str, opts))

    emit('digraph sc {')
    for t in stats.find_objs(session.object_list, obj_type=stats.Thread):
        emit('  subgraph cluster%d {' % t.id)
        emit('    label = "thread %s";' % t.name)

        vis = stats.find_objs(session.object_list, obj_type=stats.Vi,
                              fields=[("thread_id", t.id)])
        for vi in vis:
            emit('    v%d [shape=octagon, label="%s\n%s"];' %
                 (vi.id, vi.obj_id, vi.name))

        nodes = stats.find_objs(session.object_list, obj_type=stats.Node,
                                fields=[("thread_id", t.id)])
        for n in nodes:
            if node_is_mb(n):
                mb = n.mailbox
                if mb_is_wanted(mb):
                    if not hasattr(mb, 'peer_mailbox') or \
                       mb.id > mb.peer_mailbox.id:
                        in_out = "<out>|<in>"
                    else:
                        in_out = "<in>|<out>"
                    emit('    n%d [shape=Mrecord, label="%s"];' %
                         (n.id, in_out))
            elif not node_is_wanted(n):
                continue
            else:
                emit('    n%s [label="%s\n%s\n%s"];' %
                     (n.id, n.obj_id, n.node_type_name, n.name))

        pools = stats.find_objs(session.object_list, obj_type=stats.Pool,
                                fields=[("thread_id", t.id)])
        for pool in pools:
            emit('    p%d [shape=box];' % pool.id)
        emit('  }')

    nodes = stats.find_objs(session.object_list, obj_type=stats.Node)
    for n in nodes:
        if not node_is_wanted(n):
            continue
        for link_name, to_n, to_name in n.links:
            add_link(n, to_n)
        if hasattr(n, 'pools'):
            for pp_id in n.pools:
                add_link(session.object_map['p%d' % pp_id], n,
                         ' [style=dashed]')
        if n.node_type_name == 'sc_injector':
            add_link(n, n.vi)

    mboxes = stats.find_objs(session.object_list, obj_type=stats.Mailbox)
    for mb in mboxes:
        if not show_mailboxes:
            continue
        if mb.recv_node_id >= 0 and node_is_wanted(mb.recv_node):
            emit('  n%s:in -> n%s;' %
                 (mb.send_node_id, mb.recv_node_id))
        if hasattr(mb, 'peer_mailbox'):
            emit('  n%d:out -> n%d:in;' %
                 (mb.send_node_id, mb.peer_mailbox.send_node_id))

    vis = stats.find_objs(session.object_list, obj_type=stats.Vi)
    for vi in vis:
        if vi.pool_id >= 0:
            add_link(vi.pool, vi, ' [style=dashed]')
            if hasattr(vi, 'packed_stream_pool_id') and \
               vi.packed_stream_pool_id >= 0:
                add_link(vi.packed_stream_pool, vi, ' [style=dashed]')
        if vi.recv_node_id >= 0:
            add_link(vi, vi.recv_node)

    pools = stats.find_objs(session.object_list, obj_type=stats.Pool)
    for pool in pools:
        add_link(pool.refill_node, pool)

    emit('}')
