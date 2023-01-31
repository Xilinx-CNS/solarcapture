#!/bin/python2
'''
SPDX-License-Identifier: MIT
X-SPDX-Copyright-Text: Copyright (C) 2022, Advanced Micro Devices, Inc.
'''


import solar_capture.stats as stats
import argparse
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.font_manager import FontProperties
from matplotlib.patches import Patch


def get_parent_node(node):
    while(True):
        try:
            node.parent_node_id
        except AttributeError:
            return node
        node = stats.find_objs(session.object_list, obj_type=stats.Node,
                               fields=[("id", node.parent_node_id)])[0]


def generate_graph(session, include_subnodes=False, include_free=False):
    G = nx.DiGraph()
    for t in stats.find_objs(session.object_list, obj_type=stats.Thread):
        vis = stats.find_objs(session.object_list, obj_type=stats.Vi,
                              fields=[("thread_id", t.id)])
        for vi in vis:
            G.add_node(vi.id, thread_id=t.id, pkts_in=0, pkts_out=vi.pkts_out, sc_node=vi)

        nodes = stats.find_objs(session.object_list, obj_type=stats.Node,
                                fields=[("thread_id", t.id)])
        for n in nodes:
            if 'sc_free_demux' in n.name and not include_free:
                continue
            try:
                parent_id = n.parent_node_id
            except AttributeError:
                parent_id = None
            if include_subnodes or parent_id is None:
                G.add_node(n.id, thread_id=t.id, legend_string=n.name, sc_node=[n])
            else:
                G.node[get_parent_node(n).id]['sc_node'].append(n)

    for node_name, node in G.node.iteritems():
        for n in node['sc_node']:
            frm = node_name
            for link in n.links:
                to = link[1].id if include_subnodes else get_parent_node(link[1]).id
                if to not in G.node:
                    continue
                G.add_edge(frm, to)
    return G


def create_node_legend(G, session):
    legend = {}
    for key, node in G.node.iteritems():
        pkts_in = 0
        pkts_out = 0
        for n in node['sc_node']:
            n.update_fields()
            try:
                pkts_in += n.pkts_in
            except Exception:
                pass
            try:
                pkts_out += n.pkts_out
            except:
                pass
        legend[key] = {'label': '%d. %s pkts_in: %d pkts_out: %d' % (key, node['legend_string'], pkts_in, pkts_out),
                       'patch': Patch(visible=False)}
    return legend


def plot_graph(G, session, interval, layout_prog='dot'):
    layout = nx.graphviz_layout(G, prog=layout_prog)
    plt.ion()
    f = plt.figure(1)
    ax = f.add_axes([0.1, 0.25, 0.75, 0.75])
    fontP = FontProperties()
    fontP.set_size('small')

    while True:
        plt.cla()
        legend = create_node_legend(G, session)

        nx.draw(G, pos=layout, node_size=600, with_labels=True,
                scale=2, edge_color='#D8D8D8', ax=ax)

        plt.axis('off')
        f.set_facecolor('w')
        plt.legend([item['patch'] for item in legend.values()],
                   [item['label'] for item in legend.values()],
                   borderaxespad=0., loc='upper center',
                   prop=fontP, ncol=3, bbox_to_anchor=(0.5, -0.05),
                   fancybox=True)
        plt.draw()
        plt.pause(interval)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(usage="create a live network plot of a running solar_capture process")
    parser.add_argument('--base-dir', default=None,
                        help='Location of stats directory')
    parser.add_argument('--interval', default=1, help='Seconds between refresh', type=int)
    parser.add_argument('--include-subnodes', default=0, help='Turns on/off the plotting of subnodes', type=int)
    parser.add_argument('--graphviz-layout-prog', default='dot', help='The graphviz layout program that should be used')
    parser.add_argument('--include_free', default=0, help='Include the free demux node', type=int)
    parser.add_argument('session_pid', type=int)
    args = parser.parse_args()
    sessiondir = stats.find_session_dirs(base_dir=args.base_dir, pid=args.session_pid)
    assert len(sessiondir) == 1
    session = stats.Session(sessiondir[0])
    G = generate_graph(session, args.include_subnodes, args.include_free)
    plot_graph(G, session, args.interval, args.graphviz_layout_prog)
