adocs=readme-base blake xxhash spooky
adocs=${adocs:%=docs/%.adoc}

modules=blake2b blake2s xxhash spooky2
tests=${modules:%=test-%}

test-%: src/icedhash/%.nim
    nim c -o:$stem $prereq

check:QV: $tests
    echo "The tests are not actually run correctly."
    exit 1

clean:V:
    rm -f $modules

push:V:
    git push github

README.md: $adocs
    asciidoctor -b docbook5 docs/readme-base.adoc -o docs/readme-base.xml
    pandoc -f docbook docs/readme-base.xml -t gfm -o README.md

docs:V: README.md

