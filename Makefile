.PHONY: build ci format format-check lint test

build:
	cabal build all

format:
	fourmolu -i app test

format-check:
	fourmolu --mode check app test

lint:
	hlint app test

test:
	cabal test all

ci: format-check lint build test
