# Hauth

Postgres-native authentication service written in Haskell.

The current repository is intentionally only a scaffold. The executable exits
successfully and gives CI/CD a real package to build, lint, format-check, test,
and release.

## Development

Required tools:

- GHC 9.4.8
- Cabal 3.12.1.0
- Fourmolu
- HLint

Common commands:

```sh
make format
make lint
make test
make build
```

CI runs formatting, linting, build, and tests on branch pushes and pull
requests. Pushing a tag matching `v*` builds a Linux x86_64 binary archive and
publishes it as a GitHub release asset.
