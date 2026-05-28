.PHONY: build ci format format-check lint run test

build:
	cabal build all

format:
	fourmolu -i app test

format-check:
	fourmolu --mode check app test

lint:
	hlint app test

run:
	cabal run exe:hauth

test:
	cabal test all

ci: format-check lint build test
