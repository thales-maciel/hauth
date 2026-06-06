## v0.2.0 — 2026-06-XX

First release of the v0.2 surface. Builds on the Supabase-compatible wire
shapes frozen in v0.1 (see `docs/v0.1-compatibility.md`) and adds the surface
operators actually need to run hauth in production: webhooks, sync hooks,
email templates, OAuth (Google, GitHub), TOTP MFA, the `verify` subcommand,
and a hardened auth core.

### Added

- **Webhooks.** Subscription CRUD API, background delivery worker with
  at-least-once semantics, HMAC-signed payloads using the Standard Webhooks
  convention, delivery log + manual retry API, events emitted from auth, MFA,
  and admin handlers. Operator docs in `docs/WEBHOOKS.md`. (#80, #81, #82,
  #83, #84, #85, #86, #87, #88, #134, #140)
- **Sync hooks.** Fixed set of synchronous hook points with strict timeouts:
  `before-user-created`, `custom-access-token`, `password-verification-attempt`,
  `mfa-verification-attempt`. CRUD API for hook configurations, signed
  request headers, shared HTTP manager. Operator docs in `docs/HOOKS.md`.
  (#89, #90, #91, #92, #94, #95, #136, #138, #139, #172)
- **Email templates.** Schema + seed, CRUD API under `/admin/email-templates`,
  hot reload via Postgres `LISTEN/NOTIFY`. Operator docs in `docs/EMAIL.md`.
  (#96, #97, #98, #99, #109, #117, #123, #130)
- **Real SMTP delivery** wired into signup, recover, and resend flows.
  (#177, #190)
- **TOTP MFA** documentation. Enrollment, challenge, verify, unenroll, and
  AAL escalation flows in `docs/MFA.md`. (#101, #106)
- **OAuth provider setup** guide for Google and GitHub in `docs/OAUTH.md`,
  aligned with the implemented authorization-code flow with compiled-in
  endpoints. (#100, #104, #159, #169, #176)
- **`verify` subcommand.** Exercises database (`config.parse`, `db.connect`,
  `db.migrations`), JWT + site URL identity, SMTP TCP + EHLO handshake, and
  per-provider OAuth discovery. Reports specifically what is broken in text
  or JSON. (#74, #75, #76, #77, #78, #79, #107, #113, #114, #115, #116, #127)
- **Production hardening guide** in `docs/PRODUCTION.md` covering TLS
  termination, process supervision, database configuration, secret
  management, backups, and monitoring. (#102, #105)
- **AGENTS.md operator guide** for AI subagents. (#110, #184)

### Changed

- **Refactor.** `Hauth.Server` split into composition + per-surface
  domain handlers (`Server.Auth`, `Server.Admin`, …) and `API/Types`
  split by surface. (#144, #163, #175)
- **Startup lifecycle.** `serve` now distinguishes required vs degraded
  background services and surfaces startup failures instead of silently
  swallowing them. `createAppEnv` + `startBackgroundServices` are now
  separate. `TemplateCache` owns its listener thread and connection.
  `verify` and the e2e harness are bracket-wrapped for deterministic
  teardown. (#141, #145, #150, #161, #165, #173, #174)
- **JWT.** HS256 sign/verify migrated to `jose` with property tests.
  HS256 verifier hardened — constant-time signature comparison, header
  policy, integral claim validation. `unsafePerformIO` removed from
  webhook signature verification. (#142, #146, #151)
- **Wire shape stability.** Every API type now has a hand-written JSON
  instance with a golden test guarding the wire shape; CI guards against
  three recurring regression classes (JSON drift, served `notImplemented`
  stubs, format/lint drift). Unit harness converted to Hspec. (#147, #152,
  #153)
- **Hooks/webhooks secrets** are now write-only on the admin API; secret
  fields are redacted from `Show` output for config types. (#162, #171,
  #198)

### Security

- **Outbound destination policy** for hook + webhook URLs (deny internal
  network ranges by default, configurable allow/deny lists). (#192, #200)
- **Service-role JWTs.** User-session JWTs can no longer carry the
  `service_role` claim. (#158, #168)
- **Refresh-token rotation** is now serialized under concurrent requests;
  webhook delivery is claimed atomically with `UPDATE ... RETURNING`.
  (#166, #157, #167)
- **OAuth identity creation** is deterministic on the no-email path.
  Provider exchanges are injectable, with e2e coverage. (#179, #180, #188,
  #189)
- **Logout scope semantics** match the documented behavior. (#178, #186)
- **Constant-time comparison** for webhook signatures and HS256
  signatures. (#182, #185, #142)
- **Migrations** detect drift between applied content and the embedded
  source via content hashes. (#181, #187)

### Operator notes

- Cabal package version is now `0.2.0.0`. The Supabase-compatibility
  contract from v0.1 still holds — see `docs/v0.1-compatibility.md`.
- New required tooling: nothing. The release artifact is still a single
  static musl-linked Linux x86_64 binary.
- Schema changes in this release: webhook subscriptions + deliveries,
  email templates, sync hook configurations. Run `hauth migrate up`.

## v0.1.1 — 2026-06-01

Patch release. See the GitHub release notes for v0.1.1 / v0.1.0.

## v0.1.0 — 2026-06-01

Initial public release. Supabase-compatible wire shapes for signup,
password and refresh-token grants, recover, verify, resend, `/user`,
admin user management. See `docs/v0.1-compatibility.md` for the full
contract.
