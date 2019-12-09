#!/usr/bin/python
####################################################################################
# Author: Anh Quach
#
# This script accepts a program, and extracts the list of libraries the executable depends on.
# Finally, it outputs deps.pkl, a pickle file that contains a single dictionary that
# maps executable(str) to a list of librarires([str])
# This script relies on 'find' to find executables, and 'ldd' to lookup dependencies.
#####################################################################################

import sys
import subprocess
import os
try:
    import cPickle as pickle
except:
    import pickle

# Dependency map. This is what is written to the pickle file.
dep_map = {}


def process_output(output):
    deps = []
    for l in output.split('\n'):
        if len(l) <= 1:
            continue
        x = l.split(' ')
        if len(x) == 4:
            if len(x[2]) > 0:
                deps.append(x[2])
        if len(x) == 2 and 'ld-linux' in x[0]:
            deps.append(x[0].lstrip())
    return deps


def gen_deps(app_name):
    global dep_map

    exes = [app_name]
    for exe in exes:
        if len(exe) > 1:
            if "Permission denied" in exe:
                continue
            try:
                output = subprocess.check_output(['ldd', exe])
                dep_map[exe] = process_output(output)
            except subprocess.CalledProcessError:
                print "Invalid input ", exe
                print "Skipping..."
                pass


def main(argv):
    for i in range(1, len(argv)):
        app_name = subprocess.check_output('basename ' + argv[i], shell=True).strip('\n')
        if os.path.exists("deps.pkl"):
            print "Already have module dep info", app_name
            return
        gen_deps(argv[i])

    pkl_file = "deps.pkl"
    pickle.dump(dep_map, open(pkl_file, "wb"))
    print "Dependencies for", len(dep_map.keys()), "files dumped"

if __name__ == "__main__":
    main(sys.argv)
