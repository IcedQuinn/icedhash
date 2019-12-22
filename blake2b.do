redo-ifchange blake2b.nim blake2b_test.nim bintext
nim c -o:$3 blake2b.nim 1>&2
prove ./$3 1>&2
