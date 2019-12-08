#!/usr/bin/python -t
###########################################################################
# Author    : Anh Quach (aquach1@binghamton.edu)
# Date      : 08/2017
#
# Count the number of instructions in each function using idapro
# Input: prog_name
# Output: <prog_name>_ins.pkl
###########################################################################

from idaapi import *
import idautils
import idc
import os
try:
    import cPickle as pickle
except:
    import pickle

# Wait for auto-analysis to finish before running script
idaapi.autoWait()

ins_count = {}
byte_count = {}

for fn_saddr in idautils.Functions():
    if fn_saddr not in ins_count:
        ins_count[fn_saddr] = 0
        byte_count[fn_saddr] = 0

    # Add size for each chunk
    chunks = list(Chunks(fn_saddr))
    for chunk in chunks:
        start_ea = chunk[0]
        end_ea = chunk[1]
        byte_count[start_ea] = end_ea - start_ea
        ins_count[start_ea] = len(list(Heads(start_ea, end_ea)))

mod_name = GetInputFile()

# Dump ins_count
outfile = open(mod_name + '_ins.pkl', 'wb')
pickle.dump(ins_count, outfile)
outfile.close()

# Dump byte_count
outfile = open(mod_name + '_nbyte.pkl', 'wb')
pickle.dump(byte_count, outfile)
outfile.close()

idc.Exit(0)
