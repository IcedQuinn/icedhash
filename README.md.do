redo-ifchange README.m4 `find docs/*.md | xargs`
m4 -P README.m4 | pandoc -t gfm > $3
doctoc $3 >/dev/null
