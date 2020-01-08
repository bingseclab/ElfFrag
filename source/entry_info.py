#!/usr/bin/python -t
###########################################################################
# Author    : Anh Quach (aquach1@binghamton.edu)
###########################################################################

import pickle
import sys
import csv
import os
import glob
import re
import subprocess

name_addr = {}
addr_name = {}

# Map symbol name to a dict that maps version to addr
sym_ver = {}


def add_entry_size(cols, entry_type):
    global entry_size
    global name_addr
    global addr_name
    global sym_ver

    size = int(cols[2])
    # Keep version number in symbol name
    if '@' in cols[7]:
        name = cols[7][:cols[7].find('@')]
    else:
        name = cols[7]
    addr = long(cols[1], 16)
    if '@' in cols[7]:
        ver = cols[7][cols[7].rfind('@')+1:]
    else:
        ver = None

    # Manual fix for readelf output of libc symbol __key_encryptsession_pk_LOCAL
    if os.path.basename(sys.argv[1]) == 'libc.so.6':
        if '__key_encryptsession_pk' in name:
            name = '__key_encryptsession_pk_LOCAL'
        if '__key_decryptsession_pk' in name:
            name = '__key_decryptsession_pk_LOCAL'
        if 'program_invocation_short' in name:
            name = 'program_invocation_short_name'
        if 'obstack_alloc_failed' in name:
            name = 'obstack_alloc_failed_handler'
        if '__libc_current_sigrtmax' in name:
            name = '__libc_current_sigrtmax_private'
        if '__libc_allocate_rtsig_pri' in name:
            name = '__libc_allocate_rtsig_private'
        if '__libc_current_sigrtmin' in name:
            name = '__libc_current_sigrtmin_private'

    if entry_type == 'code':
        name_addr[name] = (addr, size, entry_type)
        addr_name[addr] = (name, size, entry_type)
    else:
        name_addr[name] = (addr, size, entry_type, 0)
        addr_name[addr] = (name, size, entry_type, 0)

    if name not in sym_ver and ver is not None:
        sym_ver[name] = dict()
    if ver is not None:
        sym_ver[name][ver] = addr


def add_entry_size_from_objdump(cols, entry_type):
    global entry_size
    global name_addr
    global addr_name
    global sym_ver

    name = cols[-1]
    ver = cols[-2].lstrip('(').strip(')')
    addr = int(cols[0], 16)
    size = int(cols[3].split('\t')[1], 16)

    if entry_type == 'code':
        name_addr[name] = (addr, size, entry_type)
        addr_name[addr] = (name, size, entry_type)
    else:
        name_addr[name] = (addr, size, entry_type, 0)
        addr_name[addr] = (name, size, entry_type, 0)

    if name not in sym_ver and ver is not None:
        sym_ver[name] = dict()
    if ver is not None:
        sym_ver[name][ver] = addr


def main(argv):
    global entry_size
    global name_addr
    global addr_name
    global sym_ver

    if(sys.argv < 2):
        print 'USAGE: ./entry_size_readelf.py bin_name'
        return

    basename = os.path.basename(sys.argv[1])

    # Use readelf
    lines = subprocess.check_output('readelf -s ' + sys.argv[1], shell=True).split("\n")
    for line in lines:
        cols = filter(lambda x: len(x) > 0,line.split(' '))
        if len(cols) < 8: 
          continue
        # Library /usr/lib/x86_64-linux-gnu/libopcodes-2.26.1-system.so has symbol at idx 29 with 
        # unsual format. Ignore this
        if 'x' in cols[2]: continue
        if 'FUNC' in cols[3] and cols[6] is not 'UND':
          add_entry_size(cols, 'code')
        elif 'OBJECT' in cols[3] and cols[6] is not 'UND' and int(cols[2]) != 0:
          add_entry_size(cols, 'data')
        else:
          pass

    print 'Generating entry_size for ' + basename
    outfile = open(basename + '_nbyte.pkl', 'w')
    pickle.dump(name_addr, outfile)
    pickle.dump(addr_name, outfile)
    outfile.close()

    outfile = open(basename + '_symver.pkl', 'w')
    pickle.dump(sym_ver, outfile)
    outfile.close()


if __name__ == '__main__':
    main(sys.argv)
