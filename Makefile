.PHONY: build check-derived-json check-served-stubs check-stub-senders check-workflows ci clean-local coverage e2e e2e-watch format format-check guards lint rebase-check run test

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

# Preflight Postgres so a missing DB fails in ~50ms with a clear hint instead
# of building the suite first and then erroring opaquely. withTestEnv defaults
# HAUTH_E2E_DATABASE_URL to postgresql://hauth:hauth@localhost:5432/hauth_e2e
# when unset, so the env var is optional locally.
e2e:
	@pg_isready -h localhost -p 5432 -q || { \
		echo "ERROR: Postgres not reachable at localhost:5432." >&2; \
		echo "       Start it (e.g. via your local dev compose / brew services / systemctl)" >&2; \
		echo "       and ensure DB 'hauth_e2e' + role 'hauth' exist." >&2; \
		exit 1; \
	}
	cabal test hauth-e2e --project-file=cabal.project.ci

# Fast feedback loop for e2e during development. Re-runs on file change.
# Requires `ghcid` (cabal install --installdir=$HOME/.local/bin ghcid).
e2e-watch:
	@if ! command -v ghcid >/dev/null 2>&1; then \
		echo "ghcid not installed. Install: cabal install --installdir=\$$HOME/.local/bin ghcid"; \
		exit 1; \
	fi
	@pg_isready -h localhost -p 5432 -q || { echo "ERROR: Postgres not reachable at localhost:5432." >&2; exit 1; }
	ghcid --command 'cabal repl hauth-e2e --project-file=cabal.project.ci' \
	      --test ':main' --warnings

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

ci: format-check lint guards build test

clean-local:
	rm -rf dist-newstyle/build/*/ghc-*/hauth-*

# Regression guards for issue classes that previous PRs had to fix:
#   * Hand-written JSON in API/Types (commit a166ccc); anyclass derivation
#     would silently change wire shape.
#   * notImplemented stubs in served APIs; new ones must be explicitly
#     acknowledged (bump SERVED_STUBS) so reviewers can't miss them.
#   * stubSender use in served handlers; real SMTP is not wired yet, so new
#     call sites must be reviewed instead of silently expanding the gap.
guards: check-derived-json check-served-stubs check-stub-senders

check-derived-json:
	@if grep -rnE 'deriving[[:space:]]+anyclass[[:space:]]*\(.*(FromJSON|ToJSON)' src/Hauth/API/Types.hs src/Hauth/API/Types >&2; then \
		echo "ERROR: deriving anyclass FromJSON/ToJSON detected under src/Hauth/API/Types." >&2; \
		echo "       Wire shapes are hand-written and golden-tested; add explicit instances instead." >&2; \
		exit 1; \
	fi

# Bump SERVED_STUBS when you intentionally add or remove a notImplemented
# placeholder in src/Hauth/Server.hs (and ideally implement the handler in
# the same PR).
SERVED_STUBS := 10
check-served-stubs:
	@count=$$(grep -cE '^[[:space:]]+(:<\|>[[:space:]]+)?notImplemented[0-9]+([[:space:]]|$$)' src/Hauth/Server.hs); \
	if [ "$$count" != "$(SERVED_STUBS)" ]; then \
		echo "ERROR: src/Hauth/Server.hs has $$count served notImplemented stubs; allowlist expects $(SERVED_STUBS)." >&2; \
		echo "       Implement the handler or bump SERVED_STUBS in the Makefile in the same PR." >&2; \
		grep -nE '^[[:space:]]+(:<\|>[[:space:]]+)?notImplemented[0-9]+([[:space:]]|$$)' src/Hauth/Server.hs >&2; \
		exit 1; \
	fi

# Served handlers now use the env-injected sender; this guard should stay 0.
# Bump only when intentionally adding a served path that uses stubSender.
STUB_SENDER_CALLS := 0
check-stub-senders:
	@count=$$(grep -R 'sendEmail stubSender' src/Hauth/Server | wc -l | tr -d ' '); \
	if [ "$$count" != "$(STUB_SENDER_CALLS)" ]; then \
		echo "ERROR: src/Hauth/Server has $$count stubSender send sites; allowlist expects $(STUB_SENDER_CALLS)." >&2; \
		echo "       Wire real SMTP or bump STUB_SENDER_CALLS in the same PR with a documented reason." >&2; \
		grep -Rn 'sendEmail stubSender' src/Hauth/Server >&2; \
		exit 1; \
	fi

# Local convenience: lint .github/workflows/* with actionlint.
# CI gates this via .github/workflows/lint-workflows.yml; here it just
# gives developers a fast local check. Degrades gracefully if actionlint
# isn't installed.
check-workflows:
	@if command -v actionlint >/dev/null 2>&1; then \
		actionlint .github/workflows/*.yml; \
	else \
		echo "actionlint not installed; skipping. See https://github.com/rhysd/actionlint#installation"; \
	fi

rebase-check:
	@! grep -rnE '^(<<<<<<<|>>>>>>>) ' app src test e2e docs 2>/dev/null || (echo "ERROR: unresolved conflict markers" >&2; exit 1)
	fourmolu --mode check app src test e2e
	hlint app src test e2e
