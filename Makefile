.PHONY: build ci clean-local coverage format format-check lint rebase-check run test

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

coverage:
	cabal test all --project-file=cabal.project.ci --enable-coverage
	@find dist-newstyle -type f -path '*hpc/vanilla/html/hpc_index.html' -print

ci: format-check lint build test

clean-local:
	rm -rf dist-newstyle/build/*/ghc-*/hauth-*

rebase-check:
	@! grep -rnE '^(<<<<<<<|>>>>>>>) ' app src test 2>/dev/null || (echo "ERROR: unresolved conflict markers" >&2; exit 1)
	fourmolu --mode check app src test
	hlint app src test
