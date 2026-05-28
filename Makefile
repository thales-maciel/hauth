.PHONY: build ci format format-check lint run test

build:
	cabal build all

format:
	fourmolu -i app src test

format-check:
	fourmolu --mode check app src test

lint:
	hlint app src test

run:
	cabal run exe:hauth -- serve --config config.example.json

test:
	cabal test all

ci: format-check lint build test
