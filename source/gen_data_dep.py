#!/usr/bin/python -t
###########################################################################
# Author    : Anh Quach (aquach1@binghamton.edu)
#
###########################################################################

from idaapi import *
import idautils
import idc
import struct
import os
try:
    import cPickle as pickle
except:
    import pickle
import sys

is_64bits = sys.maxsize > 2**32

# List of global variables
data_head = []

# Maps a data addr to a set of function addresses that reference it
data_ref = {}

# Set of address-taken functions including both direct and indirect references
# found in read-only data sections
global_fn_ptrs = set()

# Map a function to a set of function pointers
fn_ptrs = dict()

# List of function addresses in current module
fn_list = []

text = get_segm_by_name('.text')
plt = get_segm_by_name('.plt')
got = get_segm_by_name('.got')
pltgot = get_segm_by_name('.pltgot')
extern = get_segm_by_name('extern')
ro_sections = ['.rodata', '.init', '.init_array', '__libc_subfreeres',
               '__libc_atexit', '.__libc_thread_subfreeres', '.data.rel.ro']

# Maps address to name
addr_name = {}

# Maps name to a tuple of address and size
name_addr = {}

# Maps head chunk with tail chunks.
fn_chunk = {}

arch_info = idaapi.get_inf_structure()
bin_name = GetInputFile()
header = get_segm_by_name("HEADER")


def get_pointer_size():
    global arch_info

    if arch_info.is_64bit():
        return 8
    else:
        return 4

def is_fn_ptr(ea):
    return ea in range(text.startEA, text.endEA) and isCode(get_flags_novalue(ea))

def is_code_pointer(ea):
    return ea in range(text.startEA, text.endEA) and isCode(get_flags_novalue(ea))

def get_demangled_name(name):
    demangled_name = Demangle(name, GetLongPrm(INF_SHORT_DN))
    if demangled_name:
        demangled_name = demangled_name[:demangled_name.find("(")]
        return demangled_name
    else:
        return name

def is_imported(ea):
    if plt and ea in range(plt.startEA, plt.endEA):
        return True
    if got and ea in range(got.startEA, got.endEA):
        return True
    if pltgot and ea in range(pltgot.startEA, pltgot.endEA):
        return True

def init():
    global fn_list
    global data_ref
    global data_head
    global fn_chunk

    heads = idautils.Heads()
    for ea in heads:
        # Ignore data in .dep section
        # if dep and ea in range(dep.startEA, dep.endEA): continue
        flags = get_flags_novalue(ea)
        
        if isData(flags):
            data_head.append(ea)
            data_ref[ea] = set()

    function_list = list(Functions())
    for fn_ea in Functions():
        name = GetFunctionName(fn_ea)
        fn = get_func(fn_ea)
        if fn is None:
            continue
        name_addr[name] = (fn.startEA, fn.endEA-fn.startEA, 'code')
        # Add demangled name
        demangled_name = Demangle(name, GetLongPrm(INF_SHORT_DN))
        if demangled_name:
            demangled_name = demangled_name[:demangled_name.find("(")]
            name_addr[demangled_name] = (fn.startEA, fn.endEA-fn.startEA, 'code')
            addr_name[fn.startEA] = (demangled_name, fn.endEA - fn.startEA, 'code')
        else:
            addr_name[fn.startEA] = (name, fn.endEA - fn.startEA, 'code')

    for tup in Names():
        name = tup[1]
        addr = tup[0]
        flags = get_flags_novalue(addr)
        if isData(flags):
            # Data head
            if getseg(NextHead(addr)) is None:
                continue
            size = NextHead(addr) - addr

            segm = getseg(addr)
            if segm is not None and segm.perm & SEGPERM_WRITE:
                name_addr[name] = (addr, size, 'data', 1)
                addr_name[addr] = (get_demangled_name(name), size, 'data', 1)
            else:
                name_addr[name] = (addr, size, 'data', 0)
                addr_name[addr] = (get_demangled_name(name), size, 'data', 0)

        else:
            pass

    # Read export table
    for entry in Entries():
        name = entry[3]
        addr = entry[2]
        size = entry[0]
        demangled_name = get_demangled_name(name)

        if isCode(get_flags_novalue(addr)):
            name_addr[name] = (addr, size, "code")
            name_addr[demangled_name] = (addr, size, "code")

            if demangled_name:
                name_addr[demangled_name] = (addr, size, "code")
                if "(" in demangled_name:
                    demangled_name = demangled_name[:demangled_name.find("(")]
                name_addr[demangled_name] = (addr, size, "code")


def analyze_data_dep():
    global data_ref
    global data_head

    # List of functions and data that reference a global variable
    for ea in data_head:
        # Check functions that directly reference this data
        refs = idautils.XrefsTo(ea)
        for ref in refs:
            flags = get_flags_novalue(ref.frm)
            if isCode(flags):
                fn = get_func(ref.frm)
                if fn is not None:
                    data_ref[ea].add(fn.startEA)
            if isData(flags):
                if not isHead(flags):
                    ref_addr = PrevHead(ref.frm)
                else:
                    ref_addr = ref.frm
                data_ref[ea].add(ref_addr)

        # Check if data contains valid code pointer
        if NextHead(ea) - ea == get_pointer_size():
            byte_chunk = GetManyBytes(ea, get_pointer_size())
            if byte_chunk is None:
                continue
            if get_pointer_size() == 8:
                addr = struct.unpack("<LL", byte_chunk)[0]
            else:
                addr = struct.unpack("<L", byte_chunk)[0]
            if is_code_pointer(addr):
                fn = get_func(addr)
                if fn is not None:
                    data_ref[ea].add(fn.startEA)


ptrs_dict = {}
ptr_array_map = {}

def collect_self_imports(ea):
    if ea in range(text.startEA, text.endEA):
        return ea
    if ea in range(extern.startEA, extern.endEA):
        return None
    for ref in XrefsFrom(ea):
        return collect_self_imports(ref.to)

def collect_pointers_from_array(ea):
    ptrs = set()

    while isData(get_flags_novalue(ea)):
        # Check if ea contains code pointer
        byte_chunk = GetManyBytes(ea, get_pointer_size())
        if byte_chunk is None:
            continue
        try:
            addr = struct.unpack("<L", byte_chunk)[0]
        except:
            continue
        # Found a function pointer
        if is_fn_ptr(addr):
            fn = get_func(addr)
            if fn:
                ptrs.add(fn.startEA)
        if is_import_ptr(addr):
            ptrs.add(addr)

        # Check if ea references code
        xrefs = XrefsFrom(ea)
        for xref in xrefs:
            ref_addr = xref.to
            if is_fn_ptr(ref_addr):
                fn = get_func(ref_addr)
                if fn:
                    ptrs.add(fn.startEA)
            if is_import_ptr(ref_addr):
                ptrs.add(ref_addr)

        ea += get_pointer_size()

    return ptrs


def collect_pointers_from_struct(ea):
    ptrs = set()

    for xref in XrefsFrom(ea):
        addr = xref.to
        if is_code_pointer(addr):
            fn = get_func(addr)
            if fn:
                ptrs.add(fn.startEA)

    return ptrs


def extract_code_ptr_from_code():
    global fn_ptrs
    global text

    # Extract code reference from each instruction
    for fn_ea in Functions():
        for ins_ea in FuncItems(fn_ea):
            # Go through each operand, check if valid code pointer
            decode_insn(ins_ea)

            if ins_ea != int("8161f", 16):
                continue

            # Check code reference with lea
            if GetMnem(ins_ea) == 'lea':
                i = 0
                while cmd.Operands[i].type != o_void:
                    if GetOpType(ins_ea, i) == o_mem:
                        ref_addr = GetOperandValue(ins_ea, i)
                        if is_code_pointer(ref_addr):
                            flags = get_flags_novalue(ref_addr)
                            if isCode(flags):
                                fn = get_func(ref_addr)
                                if fn is not None:
                                    # Found indirect function ref
                                    if fn_ea not in fn_ptrs:
                                        fn_ptrs[fn_ea] = set()

                                    fn_ptrs[fn_ea].add(fn.startEA)
                                else:
                                    if fn_ea not in fn_ptrs:
                                        fn_ptrs[fn_ea] = set()
                                    fn_ptrs[fn_ea].add(ref_addr)
                    i += 1

            # Check reference to code pointer table
            xrefs = XrefsFrom(ins_ea)
            for xref in xrefs:
                ref_addr = xref.to

                if is_imported(ref_addr):
                    addr = collect_self_imports(ref_addr) 
                    if addr:
                        if fn_ea not in fn_ptrs:
                            fn_ptrs[fn_ea] = set()
                        fn_ptrs[fn_ea].add(addr)
                if ref_addr not in range(text.startEA, text.endEA):
                    continue

                # Check processed ref_addr:
                if ref_addr in ptrs_dict:
                    if fn_ea not in fn_ptrs:
                        fn_ptrs[fn_ea] = set()
                    fn_ptrs[fn_ea] = fn_ptrs[fn_ea].union(ptrs_dict[ref_addr])
                    continue

                ptrs_dict[ref_addr] = set()

                flags = get_flags_novalue(ref_addr)
                
                if isStruct(flags):
                    ptrs = collect_pointers_from_struct(ref_addr)
                    if fn_ea not in fn_ptrs:
                        fn_ptrs[fn_ea] = set()
                    fn_ptrs[fn_ea] = fn_ptrs[fn_ea].union(ptrs)
                    ptrs_dict[ref_addr] = ptrs

                elif isData(flags):
                    ptrs = collect_pointers_from_array(ref_addr)
                    if fn_ea not in fn_ptrs:
                        fn_ptrs[fn_ea] = set()
                    fn_ptrs[fn_ea] = fn_ptrs[fn_ea].union(ptrs)
                    ptrs_dict[ref_addr] = ptrs

                else:
                    # Example: push    offset sub_1A48C760
                    # Ignore Ordinary_flow
                    if "Ordinary_Flow" in XrefTypeName(xref.type):
                        continue
                    ref_addr = xref.to
                    to_fn = get_func(ref_addr)
                    if to_fn is None:
                        continue
                    if fn_ea not in fn_ptrs:
                        fn_ptrs[fn_ea] = set()
                    fn_ptrs[fn_ea].add(to_fn.startEA)
                    ptrs_dict[ref_addr].add(to_fn.startEA)



def extract_code_ptr_from_ro_sections():
    global ro_sections
    global global_fn_ptrs

    # Extract code pointers from data sections
    for section_name in ro_sections:
        seg = get_segm_by_name(section_name)
        if seg is not None:
            ea = seg.startEA
            while ea <= seg.endEA+get_pointer_size():
                byte_chunk = GetManyBytes(ea, get_pointer_size())
                if byte_chunk is not None:
                    if get_pointer_size() == 8:
                        found_addr = struct.unpack("<LL", byte_chunk)[0]
                    else:
                        found_addr = struct.unpack("<L", byte_chunk)[0]
                    if is_code_pointer(found_addr) and isHead(GetFlags(found_addr)):
                        global_fn_ptrs.add(found_addr)
                    else:
                        fn = get_func(found_addr)
                        if fn is not None:
                            global_fn_ptrs.add(fn.startEA)
                ea += get_pointer_size()


def dump_result():
    global data_ref
    global fn_ptrs
    global name_addr
    global addr_name
    global fn_chunk

    outfile_name = GetInputFile().lower() + '_data.pkl'
    print 'Writing output to ' + outfile_name

    outfile = open(outfile_name, 'wb')
    pickle.dump(data_ref, outfile)
    pickle.dump(global_fn_ptrs, outfile)
    pickle.dump(name_addr, outfile)
    pickle.dump(addr_name, outfile)
    pickle.dump(fn_ptrs, outfile)
    outfile.close()


def main():
    # Wait for auto-analysis to finish before running script
    idaapi.autoWait()

    if os.path.exists(GetInputFile() + '_data.pkl'):
        idc.Exit(0)

    print "Initialize databse"
    init()

    print "Analyze data dependency"
    analyze_data_dep()

    print "Extracting code pointers"
    extract_code_ptr_from_code()
    extract_code_ptr_from_ro_sections()

    dump_result()

    idc.Exit(0)


main()

