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
	HAUTH_E2E_DATABASE_URL=$${HAUTH_E2E_DATABASE_URL:-postgresql://hauth:hauth@localhost:5432/hauth_e2e} \
		cabal test hauth-e2e --project-file=cabal.project.ci --enable-coverage
	@mix_lib=$$(find dist-newstyle -type d -path '*noopt/build/extra-compilation-artifacts/hpc/vanilla/mix' | head -n 1); \
	mix_test=$$(find dist-newstyle -type d -path '*t/hauth-test/*/hpc/vanilla/mix' | head -n 1); \
	mix_e2e=$$(find dist-newstyle -type d -path '*t/hauth-e2e/*/hpc/vanilla/mix' | head -n 1); \
	tix_test=$$(find dist-newstyle -type f -path '*t/hauth-test/*/hauth-test.tix' | head -n 1); \
	tix_e2e=$$(find dist-newstyle -type f -path '*t/hauth-e2e/*/hauth-e2e.tix' | head -n 1); \
	hpc combine --union --output=combined.tix "$$tix_test" "$$tix_e2e"; \
	hpc report combined.tix --hpcdir="$$mix_lib" --hpcdir="$$mix_test" --hpcdir="$$mix_e2e"

ci: format-check lint build test

clean-local:
	rm -rf dist-newstyle/build/*/ghc-*/hauth-*

rebase-check:
	@! grep -rnE '^(<<<<<<<|>>>>>>>) ' app src test e2e 2>/dev/null || (echo "ERROR: unresolved conflict markers" >&2; exit 1)
	fourmolu --mode check app src test e2e
	hlint app src test e2e
