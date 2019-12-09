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
        ".*binding\sfile\s(?P<source_lib>[^\s]*).*to\s(?P<lib_name>[^\s]*)\s.*symbol\s`(?P<sym>.*)'\s\[(?P<version>.*)\].*")
    bind_pattern = re.compile(
        ".*binding\sfile\s(?P<source_lib>[^\s]*).*to\s(?P<lib_name>[^\s]*)\s.*symbol\s`(?P<sym>.*)'")

    bindings = {}
    app = os.path.basename(sys.argv[1])
    print "Processing " + app

    files = glob.glob(app + '.syms.*')
    for file in files:
        print file
        lines = [line.strip('\n') for line in open(file).readlines()]
        for line in lines:
            # line with symbol version
            lib_name = ''
            sym = ''
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
            lib_name = m.group('lib_name')
            sym = m.group('sym')
            source_lib = m.group("source_lib")
            baselib = os.path.basename(lib_name)
            if 'vdso' in lib_name or '/' not in lib_name:
                    continue

            bindings[sym] = (lib_name, version, source_lib)
        pickle.dump(bindings, open(app + '_bindings.pkl', 'w'))

if __name__ == '__main__':
    main(sys.argv)
