#!/usr/bin/python3 -t
###########################################################################
# Author    : Anh Quach (aquach1@binghamton.edu)
# Date      : 
#
# Generate a fragment of library given a list of functions to retain
# Input: program name
# Output: a shared library containing functions found in binding pkl file.
###########################################################################

import pickle
import sys
import csv
import os
import glob
import re
import subprocess

class ModInfo:
    def load_data(self):
        # Load fn list
        data_file_name = self.mod_name + "_data.pkl"
        if os.path.exists(data_file_name):
            f = open(data_file_name, "rb")
            pickle.load(f)
            pickle.load(f)
            pickle.load(f)
            self.fn_list = pickle.load(f)
            f.close()
        else:
            print("No data file", self.mod_name, " .No fragment created.")
            sys.exit(1)

        # Load text info
        info_file_name = self.mod_name + "_info.pkl"
        if os.path.exists(info_file_name):
            f = open(info_file_name, "rb")
            pickle.load(f)
            self.text_start = pickle.load(f)
            self.text_end = pickle.load(f)
            f.close()
        else:
            print("No info file", self.mod_name, " .No fragment created.")
            sys.exit(1)

    def __init__(self, mod_name):
        self.mod_name = mod_name
        self.fn_list = {}
        self.text_start = 0
        self.text_end = 0
        self.load_data()

def is_valid_fn_addr(lib_info, addr, nbytes):
    text_start = lib_info.text_start
    text_end = lib_info.text_end
    if addr not in range(text_start, text_end+1) or addr+nbytes not in range(text_start, text_end):
        return False

    return lib_info.fn_list[addr][2] == 'code'

def prepare_bytes(nbytes):
    data = bytearray()
    for i in range(0, nbytes):
        data.append(0xd6)
    return data

def create_lib_frag(lib_info, fn_included):

    lib_name = lib_info.mod_name
    os.system('cp ' + lib_name + ' ../result/' + lib_name)
    lib_frag = open('../result/' + lib_name, 'r+b')
    for fn_addr in lib_info.fn_list:
        if lib_info.fn_list[fn_addr][2] != "code": continue
        if fn_addr not in fn_included:
            # Remove function not in included list
            nbytes = lib_info.fn_list[fn_addr][1]
            if not is_valid_fn_addr(lib_info, fn_addr, nbytes):
                continue
            data = prepare_bytes(nbytes)
            # Check fn_addr and size within .text
            lib_frag.seek(fn_addr)
            lib_frag.write(data)
    lib_frag.close()


def main(argv):
    global main_app

    if(len(argv) < 2):
        print("USAGE: ./gen_lib_frag.py <prog_name>")
        return

    app_name = sys.argv[1]
    bd_file = open(app_name + '_lib_bindings.pkl', 'rb')
    bd = pickle.load(bd_file)
    bd_file.close()

    for lib in bd:
        if 'libc.so.6' in lib:
            fn_included = bd[lib]
            lib_info = ModInfo(lib)
            errno = create_lib_frag(lib_info, fn_included)

if __name__ == '__main__':
    main(sys.argv)
