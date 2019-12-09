#!/usr/bin/python -t

###########################################################################
# Author    : Anh Quach (aquach1@binghamton.edu)
#
# Parse output of loader
# Input: name of program
# Output: pickle file contain 2 sets, exec and loaded binaries
###########################################################################

import os
import pickle
import sys
import glob

exec_targets = set()
loaded_mods = set()
prog_name = sys.argv[1]

def add_mod(line):
    global loaded_mods

    pos = line.find("calling init: ") + len("calling init: ")
    loaded_mods.add(line[pos:])

def add_exec(line):
    global exec_targets

    pos = line.find("initialize program: ") + len("initialize program: ")
    exec_targets.add(line[pos:])

def dump_result():
    global exec_targets, loaded_mods
    f = open(prog_name + "_load.pkl", "w")
    pickle.dump(exec_targets, f)
    pickle.dump(loaded_mods, f)
    f.close()

def main():
  for f in glob.glob("*.syms.*"):
    print f
    lines = [line.strip("\n") for line in open(f, "r").readlines()]
    for line in lines:
        if "ld-linux" in line:
            continue
        if "calling init" in line:
            # Add loaded shared library
            add_mod(line)
        elif "initialize program" in line:
            # Add exec targets
            add_exec(line)
        else:
            continue

    dump_result()

if __name__ == '__main__':
    main()
