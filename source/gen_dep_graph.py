#!/usr/bin/python
###########################################################################
# Author    : Anh Quach (aquach1@binghamton.edu)
#
###########################################################################

import os
import glob
import sys

if len(sys.argv) < 2:
    print "USAGE: ./gen_dep_graph.py <dirname_with_callgraphs>"
    sys.exit(1)

if os.path.isdir(sys.argv[1]):
    os.chdir(sys.argv[1])
    for file in glob.glob('*.gdl'):
        mod_name = file[:-len(".gdl")]
        # if os.path.exists(mod_name + "_dep.pkl") or not os.path.exists(mod_name + "_data.pkl"):
        if not os.path.exists(mod_name + "_data.pkl"):
            print "Skip ", file
            continue
        print 'Generating dependency graph for ' + file
        os.system('../source/gdl_to_dot.pl ' + file)
        os.system('../source/calltodep_idapro.py ' + file + '.dot')

if os.path.isfile(sys.argv[1]):
    file = sys.argv[1]
    os.system('../source/gdl_to_dot.pl ' + file)
    os.system('../source/calltodep_idapro.py ' + file + '.dot')
