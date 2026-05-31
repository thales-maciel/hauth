.PHONY: build ci clean-local coverage e2e format format-check lint rebase-check run test

build:
	cabal build all

format:
	fourmolu -i app src test e2e

format-check:
	fourmolu --mode check app src test e2e

lint:
	hlint app src test e2e

run:
	cabal run exe:hauth -- serve --config config.example.json

test:
	cabal test hauth-test

e2e:
	cabal test hauth-e2e --project-file=cabal.project.ci

coverage:
	cabal test hauth-test --project-file=cabal.project.ci --enable-coverage
	@find dist-newstyle -type f -path '*hpc/vanilla/html/hpc_index.html' -print

ci: format-check lint build test

clean-local:
	rm -rf dist-newstyle/build/*/ghc-*/hauth-*

rebase-check:
	@! grep -rnE '^(<<<<<<<|>>>>>>>) ' app src test e2e 2>/dev/null || (echo "ERROR: unresolved conflict markers" >&2; exit 1)
	fourmolu --mode check app src test e2e
	hlint app src test e2e
