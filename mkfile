adocs=readme-base blake xxhash spooky
adocs=${adocs:%=docs/%.adoc}

push:V:
    git push github

README.md: $adocs
    asciidoctor -b docbook5 docs/readme-base.adoc -o docs/readme-base.xml
    pandoc -f docbook docs/readme-base.xml -t gfm -o README.md

docs:V: README.md

