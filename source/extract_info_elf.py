###########################################################################
# Author    : Anh Quach (aquach1@binghamton.edu)
#
###########################################################################
import os
import struct
from idaapi import *
import idautils
import idc
import ida_loader
try:
    import cPickle as pickle
except:
    import pickle

# Wait for auto-analysis to finish before running script
idaapi.autoWait()

entries = []

# Read import tables

# Maps mod_name: list of fn names or ords
import_table = {}

# Maps name or ord or both to address in import table
import_table_info = {}

text = get_segm_by_name('.text')
plt = get_segm_by_name('.plt')
pltgot = get_segm_by_name('.plt.got')
extern = get_segm_by_name('extern')

def is_import_or_lib_func(ea):
    return GetFunctionFlags(ea) & (idaapi.FUNC_LIB | idaapi.FUNC_THUNK) 
    
def check_import_entry(ea, name, ordinal):
    if name:
        import_table[name] = ""
        demangled_name = Demangle(name, GetLongPrm(INF_SHORT_DN))

        if demangled_name:
            demangled_name = demangled_name[:demangled_name.find("(")]
            import_table[demangled_name] = ""

    import_table_info[ea] = name
    # Check which function uses this import entry
    for xref in XrefsTo(ea):
        ref_addr = xref.frm 


    return True

for i in range(idaapi.get_import_module_qty()):
    idaapi.enum_import_names(i, check_import_entry)

print "Writing import table to file ", GetInputFile() + "_import_name.pkl"
pickle.dump(import_table, open(GetInputFile() + "_import_name.pkl", "w"))
pickle.dump(import_table_info, open(GetInputFile() + "_import_info.pkl", "w"))

## Process exports
export_name_addr = {}
export_addr_name = {}

for entry in Entries():
    fn_name = entry[3]
    fn_addr = entry[1]
    export_name_addr[fn_name] = fn_addr
    export_addr_name[fn_addr] = fn_name

export_file = GetInputFile() + "_export_name.pkl"
print "Writing export name info to file ", export_file
pickle.dump(export_name_addr, open(export_file, "w"))

# Extract other basic information: entry point, text start and end ea
entry_point_ea = BeginEA()
print "Writing binary info to file ", GetInputFile() + "_info.pkl"
f = open(GetInputFile() + "_info.pkl", "w")
pickle.dump(entry_point_ea, f)
pickle.dump(text.startEA, f)
pickle.dump(text.endEA, f)
pickle.dump(plt.startEA, f)
pickle.dump(plt.endEA, f)
if pltgot:
    pickle.dump(pltgot.startEA, f)
    pickle.dump(pltgot.endEA, f)
else:
    pickle.dump(0, f)
    pickle.dump(0, f)
if extern:
    pickle.dump(extern.startEA, f)
    pickle.dump(extern.endEA, f)
else:
    pickle.dump(0, f)
    pickle.dump(0, f)
f.close()

# Generate a list of thunks and imported function entries that are mislabeled as
# regular functions
lib_or_thunks = set()
for fn_addr in Functions():
    if is_import_or_lib_func(fn_addr):
        lib_or_thunks.add(fn_addr)
lib_or_thunk_file = GetInputFile() + "_lib_or_thunk.pkl"
print "Writing thunk info to file ", lib_or_thunk_file
pickle.dump(lib_or_thunks, open(lib_or_thunk_file, "w"))

idc.Exit(0)
