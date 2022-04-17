
modules:=blake2b blake2s # xxhash spooky2
tests=$(patsubst %,t/%.t,$(modules))

t/%.t: src/icedhash/%.nim
	nim c -o:t/$*.t $<

check: $(tests)
	prove

clean:
	rm -f $(tests)

push:
	git push github

README.md:
	asciidoctor -b docbook5 docs/readme-base.adoc -o docs/readme.xml
	pandoc -f docbook docs/readme.xml -t gfm -o README.md

docs: README.md

.PHONY: check clean push docs README.md


