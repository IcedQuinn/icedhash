redo-ifchange icedhash_blake.nim icedhash_blake/test.nim
nim c -o:$3 icedhash_blake.nim 1>&2
prove ./$3 1>&2