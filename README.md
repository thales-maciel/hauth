# Hauth

Postgres-native authentication service written in Haskell.

The current repository is intentionally only a scaffold. The executable exits
successfully and gives CI/CD a real package to build, lint, format-check, test,
and release.

The v0.1 Supabase compatibility target is documented in
[docs/v0.1-compatibility.md](docs/v0.1-compatibility.md).

## Development

Required tools:

- GHC 9.4.8
- Cabal 3.12.1.0
- Fourmolu 0.15.0.0
- HLint 3.8

Common commands:

```sh
make format
make lint
make test
make build
make run
```

By default, `make run` starts Hauth on `http://127.0.0.1:8080`. Override the
port with `HAUTH_PORT`, for example:

```sh
HAUTH_PORT=18080 make run
```

Health checks are available at `/healthz` and `/healthz/deep`.

Default language extensions live in `hauth.cabal` under the shared `warnings`
stanza, so future executables, test suites, and library components inherit the
same baseline.

CI runs formatting, linting, build, and tests on branch pushes and pull
requests. Pushing a tag matching `v*` builds a Linux x86_64 binary archive and
publishes it as a GitHub release asset.
