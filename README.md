# Hauth

A Postgres-native, Supabase-Auth-compatible authentication service written in
Haskell. Active pre-1.0 — the v0.1 surface (signup, password and refresh-token
grants, recover, verify, resend, `/user`, OAuth via Google/GitHub, TOTP MFA,
admin user management, webhook delivery, sync hooks, email templates) is
implemented and exercised end-to-end. The supported wire shapes and the
endpoints intentionally deferred past v0.1 are catalogued in
[docs/v0.1-compatibility.md](docs/v0.1-compatibility.md); the OAuth surface
is narrower than the name suggests — see [docs/OAUTH.md](docs/OAUTH.md) for
which providers, scopes, and discovery features are wired today.

## Running hauth

See [docs/QUICKSTART.md](docs/QUICKSTART.md) for the operator quickstart:
download the static release binary, point it at Postgres, run `hauth migrate
up && hauth serve`, verify with curl.

hauth ships a `verify` subcommand that exercises every configured surface
(database, JWT, SMTP, OAuth) and reports specifically what's broken — run it
before going live. See `hauth verify --help`.

## Development

Required tools:

- GHC 9.4.8
- Cabal 3.12.1.0
- Fourmolu 0.15.0.0
- HLint 3.8
- mise 2026.2.3 or newer

Common commands:

```sh
mise install
mise exec -- make format
mise exec -- make lint
mise exec -- make test
mise exec -- make coverage
mise exec -- make build
mise exec -- make run
```

By default, `make run` starts `hauth serve` on `http://127.0.0.1:8080`.
It loads `config.example.json`, validates the full startup configuration, and
reports field-level errors before the HTTP server starts. Startup also builds
the shared application environment used by request handlers, including the
loaded config, a logger placeholder, and a Postgres connection pool.

Run with an explicit config path or set `HAUTH_CONFIG`:

```sh
cabal run exe:hauth -- serve --config config.example.json
HAUTH_CONFIG=config.example.json cabal run exe:hauth -- serve
```

Override the configured server port with `HAUTH_PORT` or `--port`, for example:

```sh
HAUTH_PORT=18080 cabal run exe:hauth -- serve --config config.example.json
cabal run exe:hauth -- serve --config config.example.json --port 18080
```

Health checks are available at `/healthz` and `/healthz/deep`.

The CLI exposes explicit command namespaces:

```sh
cabal run exe:hauth -- --help
cabal run exe:hauth -- serve --help
cabal run exe:hauth -- migrate --help
```

The `migrate` command applies SQL migration files compiled into the binary
(from `migrations/`) in lexicographic order and tracks them in
`auth.schema_migrations`. The runner also creates the `auth` schema if it does
not already exist.

```sh
cabal run exe:hauth -- migrate status --config config.example.json
cabal run exe:hauth -- migrate up --config config.example.json
```

Migrations are **forward-only in v0.1**: there is no `down` subcommand and no
embedded rollback. Recover by restoring a database backup or using
point-in-time recovery. Down migrations and a richer rollback story will land
in a later milestone.

Default language extensions live in `hauth.cabal` under the shared `warnings`
stanza, so future executables, test suites, and library components inherit the
same baseline.

CI runs formatting, linting, build, and tests on branch pushes and pull
requests. Each `Build and test` job emits an HPC coverage report as a
downloadable `coverage-report` artifact (open `hpc_index.html` to browse).
Pushing a tag matching `v*` builds a Linux x86_64 binary archive and
publishes it as a GitHub release asset.
