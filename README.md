# ElfFrag
Binary Debloating of ELF binaries

We are in the process of refactoring, additional patches are coming soon.

# Requirements
* python 2.7+ and python 3
* IDApro 7.2+

# Usage
## Collect a list of all binaries to analyze

* Create a directory for binaries and analysis files.
```
mkdir data
cd data
cp <program> .
```

* Collect dependent binaries using `ldd`
`../source/gen_deps.py <program>`

* For binaries that creates new processes, collect fork and exec targets and symbol binding information on a desired training set.
`LD_BIND_NOW=1 LD_DEBUG=bindings LD_DEBUG_OUTPUT=<program_name>.syms <program> <workload>`
`../source/process_loader_output.py <program_name>`
`../source/get_bindings.py <program_name>`

## Analyze each binary and generate graphs. 
These steps will produce pickle files to serialize data for distribution between different steps.  

* Use IDApro to analyze binaries
`../source/run_ida_plugins.py <program_name>`

* Generate complete graph for a binary  
`gen_dep_graph.py .`

## Analyze graphs
* Link all graphs together and create a list of retained code
`../source/get_true_bindings.py <program_name>`

## Remove unused code to generate specialized binary for a program
`../source/gen_lib_frag.py <bindings_file>`
The new fragment is located in `../result`

## Run the program with the new fragment by changing `rpath`.
```
patchelf --set-rpath <full_path> <program_name>

```