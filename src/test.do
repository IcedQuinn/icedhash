redo-ifchange icedhash.nim icedhash/test.nim icedhash/blake2b.nim icedhash/blake2s.nim icedhash/spooky2_test
nim c -o:$3 icedhash.nim 1>&2
#./$3 1>&2
prove ./$3 1>&2
