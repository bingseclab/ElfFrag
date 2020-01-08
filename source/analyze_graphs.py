#!/usr/bin/python
####################################################################################
# Author: Anh Quach (aquach1@binghamton.edu)
#
# Usage: get_import_list.py <program_name>
#####################################################################################

import pickle
import os
import sys
import subprocess
import ntpath
from collections import deque

lib_infos = {}

## Load information
prog_name = sys.argv[1]
f = open(prog_name + "_load.pkl")
prog_list = pickle.load(f)
lib_list = pickle.load(f)
f.close()

bindings = {}
if os.path.exists(prog_name + "_bindings.pkl"):
    bindings = pickle.load(open(prog_name + "_bindings.pkl"))
else:
    print "Missing bindings file"
    sys.exit(1)

class ModInfo:
    def load_export_info(self):

        export_name_addr_file = self.mod_name + "_export_name.pkl"

        # Check if export exists
        if os.path.exists(export_name_addr_file):
            self.export_name_addr = pickle.load(open(export_name_addr_file))
        else:
            raise Exception("No export file ", export_name_addr_file)

    def load_import_info(self):

        import_name_file = self.mod_name + "_import_name.pkl"
        # Check if export exists
        if os.path.exists(import_name_file):
            self.import_names = pickle.load(open(import_name_file))
        else:
            raise Exception("No import file ", import_name_file)

        import_info_file = self.mod_name + "_import_info.pkl"
        # Check if export exists
        if os.path.exists(import_info_file):
            self.import_info = pickle.load(open(import_info_file))
        else:
            raise Exception("No import info file ", import_info_file)

    def load_dep_graph(self):

        dep_graph_file = self.mod_name + "_dep.pkl"
        # Check if export exists
        if os.path.exists(dep_graph_file):
            self.dep_graph = pickle.load(open(dep_graph_file))
        else:
            print "No dep graph ", dep_graph_file

    def load_lib_info(self):
        lib_info_file = self.mod_name + "_info.pkl"
        f = open(lib_info_file)
        self.entry_point = pickle.load(f)
        self.text_start = pickle.load(f)
        self.text_end = pickle.load(f)
        self.plt_start = pickle.load(f)
        self.plt_end = pickle.load(f)
        self.pltgot_start = pickle.load(f)
        self.pltgot_end = pickle.load(f)
        self.extern_start = pickle.load(f)
        self.extern_end = pickle.load(f)
        f.close()

    def load_lib_data(self):
        data_file = self.mod_name + "_data.pkl"
        if os.path.exists(data_file):
            f = open(data_file)
            temp = pickle.load(f)
            self.global_fn_ptrs = pickle.load(f)
            self.name_addr = pickle.load(f)
            self.addr_name = pickle.load(f)
            f.close()
        else:
            print "No data ", data_file

        data_file = self.mod_name + "_nbyte.pkl"
        f = open(data_file)
        self.name_addr.update(pickle.load(f))
        self.addr_name.update(pickle.load(f))
        f.close()

    def __init__(self, mod_name):
        self.mod_name = mod_name
        self.import_names = {}
        self.import_info = {}
        self.export_name_addr = {}
        self.dep_graph = {}
        self.entry_point = 0
        self.text_start = 0
        self.text_end = 0
        self.plt_start = 0
        self.plt_end = 0
        self.pltgot_start = 0
        self.pltgot_end = 0
        self.extern_start = 0
        self.extern_end = 0
        self.name_addr = {}
        self.addr_name = {}
        self.global_fn_ptrs = {}

        self.load_lib_info()
        self.load_import_info()
        self.load_export_info()
        self.load_dep_graph()
        self.load_lib_data()


# Load import and export info for each mod
for name in lib_list:
    lib = os.path.basename(name)
    if lib in lib_infos:
        continue
    lib_infos[lib] = ModInfo(lib)

# Imported functions for whole program
prog_lib_imports = {}

for lib in lib_list:
    prog_lib_imports[lib] = set()

# List of import (lib_name,fn_addr) to be processed
import_queue = deque()

# Set of tuples (lib_name, fn_addr) that contains all functions
# in the program's dependency
complete_import = set()

# List of library names from which we count everything as dependency
whole_lib_import = set()

# Read main program's import list
prog_import_name = pickle.load(open(prog_name + "_import_name.pkl"))

imported_list = {}

# Add entry points
def add_entry_point(lib_name):

    # Look up fn name from its address
    # Add entry point functions. They can call imported functions
    import_lib_info = lib_infos[lib_name]
    entry_point = import_lib_info.entry_point
    import_queue.append((lib_name, entry_point, 0))
    complete_import.add((lib_name, entry_point))

## Traverse list of exported functions from all libraries 
## to find an imported function
def find_fn_addr(fn_name, from_lib=""):
    global imported_list

    if fn_name in imported_list:
        return None

    lib_name = ""
    version = ""

    if "@@" in fn_name:
        version = fn_name[fn_name.find("@@")+2:]
        fn_name = fn_name[:fn_name.find("@@")]
    
    if fn_name in bindings:
        for bd_info in bindings[fn_name]:
            caller_name = os.path.basename(bd_info[2])
            lib_name = os.path.basename(bd_info[0])

            if lib_name != "" and caller_name != from_lib: continue

            version = bd_info[1]
            if "ld-linux" in lib_name:
                return None
    elif "GLIBC" in fn_name:
        version = fn_name[fn_name.find("@@")+2:]
        fn_name = fn_name[:fn_name.find("@@")]
        lib_name = "libc.so.6"
    
    
    # elif from_lib and fn_name in lib_infos[from_lib].name_addr:
        # lib_name = from_lib

    if lib_name in lib_infos:
        if fn_name in lib_infos[lib_name].name_addr:
            lib_info = lib_infos[lib_name]
            imported_list[fn_name] = (lib_info.mod_name, lib_info.name_addr[fn_name][0])
            return (lib_info.mod_name, lib_info.name_addr[fn_name][0])
    else:
        return None

def get_import_info(lib_name, ea):

    if lib_name in whole_lib_import:
        return None

    # Read import names and lib names from import addresses
    lib_info = lib_infos[lib_name]

    # Get fn_name from plt entry
    import_fn_name = lib_info.import_info[ea]
    
    import_fn_info = find_fn_addr(import_fn_name, lib_name)
    if import_fn_info == None:
        return

    import_lib_name = import_fn_info[0]
    import_fn_addr = import_fn_info[1]
    item = (import_lib_name, import_fn_addr)
    if item not in complete_import:
        complete_import.add(item)
        import_queue.append(item)
    return


def process_all_imports(lib_name):
    if lib_name in whole_lib_import:
        return

    whole_lib_import.add(lib_name)
    lib_info = lib_infos[lib_name]

    for import_fn_name in lib_info.import_names: 
        import_fn_info = find_fn_addr(import_fn_name)
        if import_fn_info == None: 
            continue
        src_lib = import_fn_info[0]
        fn_addr = import_fn_info[1]
        if (src_lib, fn_addr) not in complete_import:
            item = (src_lib, fn_addr, 0)
            import_queue.append(item)
            item = (src_lib, fn_addr)
            complete_import.add(item)

def is_imported_func(ea, lib_name):
    global lib_infos

    lib_info = lib_infos[lib_name]
    return ea in range(lib_info.extern_start, lib_info.extern_end)

def process_import_fn(lib_name, fn_addr):
    # Read dep_graph to find all import addresses
    lib_info = lib_infos[lib_name]
    dg = lib_info.dep_graph
    if len(dg) == 0:
        process_all_imports(lib_name)
        return

    if fn_addr in range(lib_info.plt_start, lib_info.plt_end) or fn_addr in range(lib_info.pltgot_start, lib_info.pltgot_end):
        return
    if fn_addr in dg:
        for ea in dg[fn_addr]:
            # Function at fn_addr imports function from another module
            if is_imported_func(ea, lib_name):
                # Add new imports to queue
                get_import_info(lib_name, ea)
                continue
            complete_import.add((lib_name, ea))
    else:
        pass

def add_init(lib_name):
    global lib_infos
    global import_queue, complete_import

    # Read output from readelf
    init = filter(lambda x: '(INIT)' in x, subprocess.check_output(
        'readelf -d ' + lib_name, shell=True).split('\n'))
    if len(init) == 1:
        init = init[0]
        cols = filter(lambda x: len(x) > 0, init.split(' '))
        init_addr = int(cols[2], 16)
        import_queue.append((lib_name, init_addr))
        complete_import.add((lib_name, init_addr))

def add_ifunc(lib_name):
    global import_queue, complete_import

    baselib = os.path.basename(lib_name)
    try:
        lines = filter(lambda x: 'IFUNC' in x, subprocess.check_output(
            'readelf -s ' + lib_name, shell=True).split('\n'))
    except:
        return
    for line in lines:
        cols = filter(lambda x: len(x) > 0, line.split(' '))
        import_queue.append((lib_name,int(cols[1], 16)))
        complete_import.add((lib_name, int(cols[1], 16)))


def add_global_fn_ptrs(lib_name):
    global lib_infos
    global import_queue, complete_imports

    if lib_name not in lib_infos:
        return
    lib_info = lib_infos[lib_name]

    # Add all global address-taken functions
    global_fn_ptrs = lib_info.global_fn_ptrs
    for fn_addr in global_fn_ptrs:
        import_queue.append((lib_name, fn_addr))
        complete_import.add((lib_name, fn_addr))

def scan_self_imports(lib_name):
    global lib_infos, bindings,complete_import, import_queue

    for sym in bindings:
        for bd_info in bindings[sym]:
            dest_lib = os.path.basename(bd_info[2])
            if "ld-linux" in dest_lib: continue
            src_lib = os.path.basename(bd_info[0])
            if bd_info[2] in prog_list or bd_info[0] in prog_list: continue
            if dest_lib == src_lib and lib_infos[dest_lib].name_addr and sym in lib_infos[dest_lib].name_addr:
                complete_import.add((dest_lib, lib_infos[dest_lib].name_addr[sym][0]))
                import_queue.append((dest_lib, lib_infos[dest_lib].name_addr[sym][0]))


# Add direct imports from main program to queue
for import_fn_name in prog_import_name:
    fn_info = find_fn_addr(import_fn_name, prog_name)
    if fn_info is None: continue
    lib_name = fn_info[0]
    fn_addr = fn_info[1]
    import_queue.append((lib_name, fn_addr))
    complete_import.add((lib_name, fn_addr))

for lib_name in lib_infos:
    add_entry_point(lib_name)
    add_init(lib_name)
    add_ifunc(lib_name)
    add_global_fn_ptrs(lib_name)
scan_self_imports(lib_name)

while len(import_queue) > 0:
    item = import_queue.popleft()
    lib_name = item[0]
    fn_addr = item[1]

    # Check if entire modile has been imported
    if lib_name in whole_lib_import:
        continue

    process_import_fn(lib_name, fn_addr)

prog_lib_imports = {}
for item in complete_import:
    lib_name = item[0]
    fn_addr = item[1]

    if lib_name not in prog_lib_imports:
        prog_lib_imports[lib_name] = set()
    prog_lib_imports[lib_name].add(fn_addr)


pickle.dump(prog_lib_imports, open(prog_name + "_lib_bindings.pkl", "w"))
