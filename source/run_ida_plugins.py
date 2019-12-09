#!/usr/bin/python

import os
import glob
import pickle
import sys

prog_name = sys.argv[1]
f = open(prog_name + "_load.pkl")
program = pickle.load(f)
file_list = set(pickle.load(f))
f.close()

for f in file_list:
    f_short_name = os.path.basename(f)

    if not os.path.exists(f_short_name):
        os.system("cp " + f + " .")

    if not os.path.exists(f_short_name + ".gdl"):
        print 'Call graph'
        os.system('ida64 -A -S../source/gen_call_graph.py ' + f_short_name)
    if not os.path.exists(f_short_name + "_data.pkl"):
        print 'Data dep'
        os.system('ida64 -A -S../source/gen_data_dep.py ' + f_short_name)
    if not os.path.exists(f_short_name + "_nbyte.pkl"):
        print 'Instr count'
        os.system('ida64 -A -S../source/ins_count.py ' + f_short_name)

    if not os.path.exists(f_short_name + "_info.pkl"):
        print 'Other information'
        os.system('ida64 -A -S../source/extract_info_elf.py ' + f_short_name)
        os.system("../source/entry_info.py " + f_short_name)

for p in program:
    os.system('ida64 -A -S../source/extract_info_elf.py ' + p)

