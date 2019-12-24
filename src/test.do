redo-ifchange icedhash_blake.nim icedhash_blake/test.nim icedhash_blake/blake2b.nim icedhash_blake/blake2s.nim
nim c -o:$3 icedhash_blake.nim 1>&2
#./$3 1>&2
prove ./$3 1>&2
