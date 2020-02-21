redo-ifchange README.m4 `find docs/*.md | xargs`
m4 -P README.m4 | pandoc -s --toc -t gfm > $3
