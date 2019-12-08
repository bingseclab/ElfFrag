from idaapi import *
import idautils
import idc
import struct
import os
try:
    import cPickle as pickle
except:
    import pickle
fn_cnt = 0

# Wait for auto-analysis to finish before running script
idaapi.autoWait()

for func in idautils.Functions():
    fn_cnt += 1

current_file = idaapi.get_root_filename()

cur = idc.MinEA()
end = idc.MaxEA()

path = idaapi.get_input_file_path() + '.gdl'
print path
idc.GenCallGdl(path, 'Call Gdl', idc.CHART_GEN_GDL)

# Generate patch to dep graph for fall-through function call
fn_flow = {}

for fn_addr in Functions():
    for xref in XrefsTo(fn_addr):
        if XrefTypeName(xref.type) == "Ordinary_Flow":
            caller = get_func(xref.frm)
            if not caller:
                continue
            caller_addr = caller.startEA
            fn_flow[Name(caller_addr)] = Name(fn_addr)

pickle.dump(fn_flow, open(idaapi.get_input_file_path() + "_fn_flow.pkl", "w"))


idc.Exit(0)
