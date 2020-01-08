#!/usr/bin/python -t
###########################################################################
# Author    : Anh Quach (aquach1@binghamton.edu)
#
# Generate a function and object dependency graph from call graph generated
# by idapro
# Input: call graph in gdl
# Output: binname_dep.pkl
###########################################################################

import sys
import os
import networkx as nx
import pickle
import pygraphviz as pgv
import re
import subprocess

# Maps a data or function head to a set of heads that it depends on
dep_graph = dict()

func_data = dict()
data_dep = dict()

id_name = {}
name_id = {}

basename = os.path.basename(sys.argv[1])
bin_name = basename[:basename.find('.gdl.dot')]

# Load data_dep pickle
if os.path.exists(bin_name + '_data.pkl'):
    f = open(bin_name + '_data.pkl')
else:
    print "No data for " + bin_name
    sys.exit(1)

data_dep = pickle.load(f)
global_fn_ptrs = pickle.load(f)
name_addr = pickle.load(f)
addr_name = pickle.load(f)
fn_ptrs = pickle.load(f)
f.close()

if os.path.exists(bin_name + '_info.pkl'):
    f = open(bin_name + '_info.pkl')
else:
    print "No _info for " + bin_name
    sys.exit(1)

entry_point_ea = pickle.load(f)
text_start_ea = pickle.load(f)
text_end_ea = pickle.load(f)
f.close()

# Read call graph
G = pgv.AGraph(sys.argv[1])
call_graph = nx.DiGraph(G)

labels_dict = dict()
for node_id in call_graph.nodes():
    labels_dict[str(node_id)] = call_graph._node[node_id]["label"]

# Update label in call graph from numeric names to actual function name
call_graph = nx.relabel_nodes(call_graph, labels_dict)

# Add function fall through information to call graph
fn_flow_info = {}
if os.path.isfile(bin_name + "_fn_flow.pkl"):
    fn_flow_info = pickle.load(open(bin_name + "_fn_flow.pkl"))
else:
    print "No fn_flow for " + bin_name
    sys.exit(1)
for caller in fn_flow_info:
    callee = fn_flow_info[caller]
    call_graph.add_edge(caller, callee)

# Update label from name to addr
name_addr_label = {}
addr_name_label = {}
for name in name_addr:
    addr = name_addr[name][0]
    name_addr_label[name] = addr
    addr_name_label[addr] = name
call_graph = nx.relabel_nodes(call_graph, name_addr_label)

# Add fn_ptrs to call graph
for fn_addr in fn_ptrs:
    for target_addr in fn_ptrs[fn_addr]:
        call_graph.add_edge(fn_addr, target_addr)

# Create dep graph
for node in call_graph.nodes():
    temp = nx.dfs_tree(call_graph, node)
    lst = list(temp.nodes())
    dep_graph[node] = set(temp.nodes())

# Add dependency for exported data for true dependency analysis
# which is a list of functions that reference data
for head in data_dep:
    if head not in dep_graph:
        dep_graph[head] = set()
    for dep_head in data_dep[head]:
        dep_graph[head].add(dep_head)
        if dep_head in dep_graph:
            dep_graph[head] = dep_graph[head].union(dep_graph[dep_head])


pickle.dump(dep_graph, open(basename[:basename.find('.gdl.dot')] + '_dep.pkl', 'wb'))
