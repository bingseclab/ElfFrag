#!/usr/bin/python -t
###########################################################################
# Author    : Anh Quach (aquach1@binghamton.edu)
#
# Generate symbol binding informations
###########################################################################

import pickle
import sys
import csv
import os
import glob
import re
import subprocess

def main(argv):
    # maps app to lib to set of funcs
    # app : {lib : set(funcs)}
    bindings = {}

    bind_pattern_ver = re.compile(
        ".*binding\sfile\s(?P<caller_lib>[^\s]*).*to\s(?P<callee_lib>[^\s]*)\s.*symbol\s`(?P<sym>.*)'\s\[(?P<version>.*)\].*")
    bind_pattern = re.compile(
        ".*binding\sfile\s(?P<caller_lib>[^\s]*).*to\s(?P<callee_lib>[^\s]*)\s.*symbol\s`(?P<sym>.*)'")

    bindings = {}
    app = os.path.basename(sys.argv[1])
    print "Processing " + app

    files = glob.glob(app + '.syms.*')
    for file in files:
        print file
        lines = [line.strip('\n') for line in open(file).readlines()]
        for line in lines:
            if len(line) == 0:
                continue
            version = ''
            if line[-1] == ']':
                m = bind_pattern_ver.match(line)
                if m is None:
                    continue
                version = m.group('version')
            else:
                m = bind_pattern.match(line)
                if m is None:
                    continue
            callee_lib = m.group('callee_lib')
            sym = m.group('sym')
            caller_lib = m.group("caller_lib")
            baselib = os.path.basename(callee_lib)
            if 'vdso' in callee_lib or '/' not in callee_lib:
                    continue
            if sym not in bindings:
                bindings[sym] = set()
            bindings[sym].add((callee_lib, version, caller_lib))

        pickle.dump(bindings, open(app + '_bindings.pkl', 'w'))

if __name__ == '__main__':
    main(sys.argv)
