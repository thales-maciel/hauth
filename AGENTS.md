# Agent guide

You are an AI worker shipping a PR against this repo. The user (or an orchestrator agent) handed you a single, well-scoped GitHub issue. This file is the operational context you need to ship without churn.

Read this top-to-bottom once. Re-skim during work if you get stuck.

## Where things live

```
app/Main.hs              CLI dispatch + entry points for each subcommand
src/Hauth/CLI.hs         CLI parser (subcommand types, optparse-applicative)
src/Hauth/Config.hs      Typed config + JSON loading + validation
src/Hauth/Env.hs         AppEnv (pool, logger, etc.); createAppEnv / destroyAppEnv
src/Hauth/Migrate.hs     Migration runner (TH-embedded SQL files)
src/Hauth/API.hs         Servant API type with auth in route signatures
src/Hauth/Server.hs      Small / shared handlers
src/Hauth/Server/<Area>.hs    Per-area handlers (Admin, Mfa, OAuth, …) — see PR #58 for rationale
src/Hauth/<Domain>/      Per-domain pure logic (Auth/, OAuth/, Mfa/, Email/, …)

migrations/NNNN_*.sql    Forward-only SQL, TH-embedded by file-embed
templates/               Email templates, TH-embedded

test/Main.hs             Unit suite entry — runs each Spec module's runSpec
test/Spec/<Area>Spec.hs  Per-area unit specs (PURE; see test split below)
test/Spec/TestUtils.hs   Shared assertion helpers (assertEqual, etc.)

e2e/Main.hs              E2E suite entry — hspec + aroundAll withTestEnv
e2e/E2E/<Area>Spec.hs    Per-area e2e specs (DB-backed)
e2e/E2E/Helpers.hs       TestEnv, withTestEnv, truncateAll, runApp, jsonPost, …

docs/                    Operator-facing docs
.github/workflows/ci.yml CI pipeline
```

## The two test suites — critical

**`hauth-test` (unit suite)** runs against ZERO Postgres setup. The Postgres service is up in CI but no migrations are applied to it. **Tests that touch the database will fail with `relation "auth.X" does not exist`.** Put pure logic here: parsing, hashing, JWT crafting, type round-trips, format checks.

**`hauth-e2e` (integration suite)** runs against a live Postgres with all migrations applied via `withTestEnv`. Every test takes a `TestEnv` parameter. This is where DB-backed and HTTP-shape tests live. The harness gives you:

- `runApp env $ jsonPost path body (Just bearer)` — drive the in-process WAI app.
- `withDatabaseConnection (testAppEnv env) \conn -> …` — direct SQL.
- `truncateAll env` — wipes user-data tables between tests; `auth.email_templates` is NOT truncated (loader fallback owns it), so clean up your own seed rows with `bracket_`. When you add a new `auth.*` table, **also add it to `truncateAll`** — otherwise rows pile up across tests and assertions like "expected 0 deliveries" start counting hundreds (real bug in wave 2 with `auth.webhook_subscriptions`/`webhook_deliveries`).

**If your test needs `connectPostgreSQL`, it belongs in `e2e/E2E/`, not `test/Spec/`.** This rule has tripped multiple agents.

**`createAppEnv` is exercised by the unit suite via `Spec.ConfigSpec` against zero migrations.** Anything you add to `createAppEnv` (a cache, a worker thread, a background loop) MUST work when `auth.*` tables don't exist yet. Catch SqlError on schema-shaped queries; catch the connectPostgreSQL exception if you eagerly open connections; fall back to no-op behavior. The DB will come up later — be ready to recover via a reconnect loop. Crashing AppEnv construction breaks the entire unit suite.

**E2E tests that mutate `auth.*` MUST clean up after themselves.** `truncateAll` doesn't restore the schema migration log, and migrations are forward-only. A test that deletes from `auth.schema_migrations` (e.g. to simulate a pending migration) leaves the next `runMigrate` trying to re-apply a migration whose objects already exist — every subsequent run of the e2e suite fails until the operator drops and recreates the database. Wrap mutation tests in `bracket_` that restores the state on exit.

## Postgres gotchas

- `execute_` is for statements with no result columns (INSERT/UPDATE/DELETE/DDL). It throws on column-returning statements — even `SELECT pg_advisory_lock(...)` (returns void column) or `SELECT 1`. Use `query_` and discard:
  ```haskell
  _ <- query_ conn "SELECT pg_advisory_lock(7401)" :: IO [Only ()]
  ```
- We use `postgresql-simple` directly. No ORM. The `auth` schema is inspectable as plain SQL on purpose.
- Connections come from the pool via `withDatabaseConnection appEnv \conn -> …`. Don't open ad-hoc connections in production code paths; OK in tests.

## JSON wire shapes

We're Supabase-compatible. The wire shape is what Supabase emits, which almost never matches Generic's defaults.

- **Don't `deriving anyclass (FromJSON, ToJSON)` on wire types.** Generic encodes the Haskell field name — e.g. `recoverEmail` instead of `email`. Bug from real history (#72).
- Write the `FromJSON`/`ToJSON` instances by hand:
  ```haskell
  instance FromJSON RecoverRequest where
      parseJSON = Aeson.withObject "RecoverRequest" \o ->
          RecoverRequest <$> o Aeson..: "email"
  ```
- When in doubt about the wire shape, check `e2e/E2E/<Area>Spec.hs` for the curl-style payload, or `docs/v0.1-compatibility.md`, or look up the Supabase Auth source.

## Servant routes

- Auth requirements live in the route type: `RequireAuth 'Anonymous`, `RequireAuth 'ValidSession`, `RequireAuth 'ServiceRole`. The handler receives a proof of authentication as an argument — no runtime checks needed.
- For 204 No Content responses, use `PostNoContent` / `DeleteNoContent`. **`Post '[JSON] NoContent` returns 200**, not 204 — bug from real history (#72).

## Migrations

- File name: `migrations/NNNN_short_name.sql`. NNNN zero-padded, monotonic. Pick the next free number.
- Forward-only in v0.1 — no down migrations.
- If your migration body contains a top-level `SELECT`, the runner will fail (see Postgres gotchas). Use `DO $$ BEGIN ... END $$;` for no-op markers; use DDL otherwise.
- **You must update `test/Spec/MigrateSpec.hs`** to add your filename to the expected list. This file is a known conflict point with concurrent migration PRs — accept the rebase tax.

## Known cross-PR conflict points

Multiple agents working in parallel WILL collide on these files. Resolution is always cumulative — keep both/all changes.

| File | What collides | Resolution |
|---|---|---|
| `test/Main.hs` | new `Spec.X.runSpec` import + call | append both |
| `e2e/Main.hs` | new `E2E.X.spec` import + `describe` | append both |
| `hauth.cabal` `other-modules` lists | new spec/module name | append both |
| `test/Spec/MigrateSpec.hs` | new migration filename in expected list | keep both, in lex order |
| `src/Hauth/API.hs` | new route group | append both |
| `src/Hauth/Verify.hs::defaultChecks` | new per-area check module | append both (one import + one `++`) |
| `src/Hauth/Env.hs::AppEnv` | new env field | additive; double-check `createAppEnv` and `destroyAppEnv` cover both |

If your scope is "the framework module that aggregates" (e.g. `Hauth.Verify` itself, `e2e/Main.hs` registry), expect to be the focal merge target — design the aggregation so each downstream issue is a one-line edit.

### Stay in your lane

If a module already exists in main, **work with it as-is** — don't refactor its shape, don't extract types into a new module, don't change its public signature. In v0.2 wave 2 three concurrent agents each independently decided to extract `Hauth.Verify.Types` from `Hauth.Verify`; resolving the duplicate-create conflicts cost an hour. If you genuinely need a structural change, propose it in a separate refactor PR before the issue lands, or accept the existing shape and live with it.

**Don't change an aggregator's signature even if your check needs more arguments.** One agent saw that OAuth checks need `Config` and changed `defaultChecks :: [Check]` to `defaultChecks :: Config -> [Check]`. That broke every other concurrent verify-check PR. Better: take the extra argument in YOUR per-area module (`oauthChecks :: Config -> [Check]`) and the aggregator constructs the value at the call site or routes it through a shared context. If signature changes are unavoidable, the issue body should call it out as a blocking coordination point.

### Squash your fix-iterations before re-rebasing

If your branch needs multiple CI cycles to go green (lint nit, timeout tweak, debug print, format fix), squash those into the original commit BEFORE rebasing against a moved main. In v0.2 wave 3, one PR accumulated five iterative commits while concurrent PRs landed on top of it. Each iteration touched the same handler bodies the concurrent PRs were also editing. The cumulative rebase became unsolvable — `git rebase` had to apply six separate commits against a moved tree, and the conflict resolution at each step compounded. The PR had to be closed and re-filed. `git rebase -i --autosquash`, or a `git reset --soft` + amend, prevents this. One commit per PR is the goal state at push time.

### Outbound HTTP needs the threaded RTS

If your code uses `http-client` (directly or via `http-client-tls`), the test suite that exercises it MUST be compiled with `-threaded`. Without it, `http-client`'s `responseTimeoutMicro` calls `getSystemTimerManager` which throws "the TimerManager requires linking against the threaded runtime", every HTTP request fails with `NoResponseDataReceived`, and the failure looks like the receiver isn't responding. In wave 3 this masquerade ate hours of debugging — fix the cabal file before fixing tests. Both `hauth-test` and `hauth-e2e` now carry `-threaded -rtsopts -with-rtsopts=-N`; keep them that way if you touch the cabal stanzas.

### Match the schema CHECK constraints in tests

Migration files often add CHECK constraints (timeout_ms BETWEEN 100 AND 3000, hook_point IN (...), etc.) on top of column types. If your test seeds a row by raw INSERT, **read the migration's CHECK clause and stay inside it**. An agent used `timeout_ms = 50` and `5000` in the verify-attempt hook tests — both violate the `100..3000` range from the schema. CI surfaced this as `violates check constraint "hooks_timeout_ms_check"`; the fix wasn't the test logic, it was the value. Same story for the `hook_point` enum: only the four canonical names work.

## Branch + PR conventions

- **Branch**: `<theme>/<short-slug>` (e.g. `webhooks/schema-migrations`, `verify/framework`).
- **Commit message**: imperative subject (`Add X`, not `Adding X` or `Added X`), ≤ 70 chars. Body explains WHY, not WHAT — the diff shows WHAT.
- **Co-author trailer** (required):
  ```
  Co-Authored-By: Claude Sonnet (1M context) <noreply@anthropic.com>
  ```
  Replace with your actual model.
- **PR title**: `<scope>: <subject> (#<issue>)`. Example: `webhooks: schema migrations (subscriptions + deliveries) (#80)`.
- **PR body**: MUST contain a line `Closes #<issue>`. Otherwise the issue won't auto-close on merge and someone has to clean it up.
- **No `--no-verify`**, no `--no-gpg-sign`, no `--amend` after a hook failure (the commit didn't happen; amend would mutate the previous one).

## Pre-push checklist

Run all of these locally before `git push`:

```sh
# Format + lint (CI fails on any non-zero)
fourmolu --mode check app src test e2e
hlint app src test e2e

# Unit suite
cabal test hauth-test --project-file=cabal.project.ci

# E2E suite (needs local Postgres + hauth_e2e database — see QUICKSTART)
HAUTH_E2E_DATABASE_URL=postgresql://hauth:hauth@localhost:5432/hauth_e2e \
  cabal test hauth-e2e --project-file=cabal.project.ci

# Conflict-marker + format gate
make rebase-check
```

If you touched the binary's surface (CLI, flags, exit codes), smoke-test it:

```sh
cabal run -v0 exe:hauth -- <your subcommand> --help
```

## Don'ts

- **Don't add tests that silently skip in CI.** If `lookupEnv "MY_DB_URL"` is `Nothing` and the test exits with a "skipping" log, your "test" is never running. Either guarantee the env var is set in CI or move the test to e2e where setup is real.
- **Don't put DB-touching code in the unit suite.** See the test split above.
- **Don't write `deriving anyclass (FromJSON, ToJSON)` on a wire type.** See JSON shapes above.
- **Don't write multi-paragraph comments or docstrings.** One short line max, only when the WHY is non-obvious.
- **Don't add error handling for impossible scenarios.** Trust internal code and framework guarantees; only validate at boundaries.
- **Don't introduce abstractions beyond what the task requires.** Three similar lines is better than a premature abstraction.
- **Don't push to other branches.** Your worktree's branch only.
- **Don't `git reset --hard` or `git push --force` without `--force-with-lease`.**

## When you finish

Push your branch, open the PR with `gh pr create`, and return **only the PR URL** to whoever spawned you. No prose summary, no list of files changed, no "I did X then Y then Z" — the diff and PR body have all that. One URL.

If something blocked you and you couldn't ship, return a single sentence describing the blocker, then the partial state (branch pushed? not pushed? local-only?). Don't pretend success.
