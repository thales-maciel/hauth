# Agent guide (tiny)

Ship one scoped issue. Stay in lane. No churn.

## Map

```text
app/Main.hs                 CLI dispatch
src/Hauth/CLI.hs            optparse CLI
src/Hauth/Config.hs         config JSON + validation
src/Hauth/Env.hs            AppEnv + pool/logger
src/Hauth/Migrate.hs        embedded SQL migrations
src/Hauth/API.hs            Servant API + RequireAuth
src/Hauth/Server.hs         shared handlers
src/Hauth/Server/<Area>.hs  area handlers
src/Hauth/<Domain>/         pure/domain logic
migrations/NNNN_*.sql       forward-only SQL
templates/                  embedded email templates
test/Spec/*                 unit specs, pure only
e2e/E2E/*                   DB/HTTP specs
docs/                       operator docs
```

## Tests: split matters

- `hauth-test`: pure only. CI has Postgres, but zero migrations. Any DB touch fails with `relation "auth.X" does not exist`.
- `hauth-e2e`: DB + HTTP shape. Uses migrated Postgres via `withTestEnv`; each spec takes `TestEnv`.
- Need `connectPostgreSQL`? Put test in `e2e/E2E/`, not `test/Spec/`.
- `createAppEnv` runs in unit suite before schema exists. New cache/worker/background loop must tolerate missing `auth.*` and connection failure. Catch `SqlError`; fall back no-op/retry. No crash.
- E2E mutation must clean up. `truncateAll` wipes user data, not `auth.email_templates`; clean seed rows. New `auth.*` table => add to `truncateAll`.
- Never leave `auth.schema_migrations` changed. Wrap restore in `bracket_`.

E2E helpers:

```haskell
runApp env $ jsonPost path body (Just bearer)
withDatabaseConnection (testAppEnv env) \conn -> ...
truncateAll env
```

## Postgres

- `execute_` only for no-result SQL. `SELECT` returns column, even `SELECT pg_advisory_lock(...)`; use `query_` and discard:
  ```haskell
  _ <- query_ conn "SELECT pg_advisory_lock(7401)" :: IO [Only ()]
  ```
- Use `postgresql-simple`. No ORM.
- Prod DB access goes through pool: `withDatabaseConnection appEnv \conn -> ...`. No ad-hoc prod connections.

## JSON + Servant

- Supabase-compatible wire shapes. Generic field names usually wrong.
- No `deriving anyclass (FromJSON, ToJSON)` on wire types. Write instances by hand.
- Check wire shape in e2e payloads, `docs/v0.1-compatibility.md`, or Supabase Auth.
- Auth belongs in route type: `RequireAuth 'Anonymous`, `'ValidSession`, `'ServiceRole`. Handler receives proof; no runtime re-check.
- 204 response: use `PostNoContent` / `DeleteNoContent`. `Post '[JSON] NoContent` returns 200.

## Migrations

- Name: `migrations/NNNN_short_name.sql`, zero-padded, next monotonic number.
- Forward-only. No down migrations.
- No top-level `SELECT`; runner fails. Use `DO $$ BEGIN ... END $$;` for no-op markers.
- Add filename to `test/Spec/MigrateSpec.hs` expected list.

## Conflict hotspots: merge additive

- `test/Main.hs`: add import + call.
- `e2e/Main.hs`: add import + `describe`.
- `hauth.cabal`: append `other-modules`.
- `test/Spec/MigrateSpec.hs`: keep migration names lex ordered.
- `src/Hauth/API.hs`: append route groups.
- `src/Hauth/Verify.hs::defaultChecks`: append imports/checks.
- `src/Hauth/Env.hs::AppEnv`: additive fields; update create/destroy.

Do not refactor existing module shape or public signatures. Need extra args? Keep area-local; do not change aggregator signature unless issue says so.

## Gotchas

- Outbound `http-client` tests need threaded RTS. Keep `hauth-test` and `hauth-e2e` cabal stanzas with `-threaded -rtsopts -with-rtsopts=-N`.
- Raw test INSERTs must satisfy migration `CHECK` constraints (`timeout_ms`, `hook_point`, etc.). Read migration before seeding.
- No silent-skipping tests in CI.
- No DB code in unit suite.
- No multi-paragraph comments/docstrings. One short line max, only for non-obvious WHY.
- No impossible-scenario error handling. Validate boundaries only.
- No abstraction beyond task need. Three similar lines OK.
- Squash fix-iterations before rebasing. Aim one commit per PR.

## Branch + PR

- Branch: `<theme>/<short-slug>`.
- Commit subject: imperative, <=70 chars. Body explains WHY.
- Commit trailer required:
  ```text
  Co-Authored-By: Claude Sonnet (1M context) <noreply@anthropic.com>
  ```
  Replace with actual model.
- PR title: `<scope>: <subject> (#<issue>)`.
- PR body includes `Closes #<issue>`.
- No `--no-verify`, no `--no-gpg-sign`, no bad `--amend`. Do not push other branches. No `git reset --hard`. Force push only `--force-with-lease`.

## Before push

```sh
fourmolu --mode check app src test e2e
hlint app src test e2e
cabal test hauth-test --project-file=cabal.project.ci
HAUTH_E2E_DATABASE_URL=postgresql://hauth:hauth@localhost:5432/hauth_e2e \
  cabal test hauth-e2e --project-file=cabal.project.ci
make rebase-check
```

CLI changed? Smoke-test:

```sh
cabal run -v0 exe:hauth -- <subcommand> --help
```

## Finish

Push branch. Open PR. Return only PR URL. Blocked? Return one sentence: blocker + state (pushed/not pushed/local-only).
