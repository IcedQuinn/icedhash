redo-ifchange bintext.nim
nim c -o:$3 bintext 1>&2
prove -v ./$3 1>&2
