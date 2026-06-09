# Hauth - North Star

Open-source, Postgres-native authentication service written in Haskell.*

## Vision

An authentication backend that ops teams actually want to self-host. Drop-in compatible with Supabase Auth's database schema and JWT shape so existing Postgres RLS policies and PostgREST integrations keep working unchanged. Differentiated by operator experience and the correctness guarantees a strongly-typed implementation can offer.

## The problem

The Postgres-native auth pattern — Row-Level Security plus signed JWT claims read by PostgREST — is excellent. The open-source operator experience around it is not. GoTrue, the service powering Supabase Auth, is functional but hostile to self-host: roughly a hundred unvalidated environment variables, no built-in admin UI, opaque webhook delivery, configuration mistakes that surface as runtime 500s, and no built-in way to verify that a deployment actually works end-to-end. Operators who want the Supabase data model without the Supabase platform are stuck.

## What we're building

A single static binary that:

- Implements the Supabase Auth HTTP API and JWT contract closely enough to be a drop-in replacement for most deployments.
- Owns an `auth` schema in the operator's own Postgres database.
- Ships with validated config, a built-in admin UI, deep health checks, and inspectable webhook delivery in the same binary.
- Encodes auth state machines in the type system via Servant, so whole classes of auth bugs do not compile.

## Differentiation — why this should exist

Two things, in order of importance:

**1. Self-hosting UX.** The concrete bets:

- Typed config file with startup-time validation and clear, line-located error messages — not env-var soup.
- Live reload of OAuth providers and email templates from Postgres without restart.
- Built-in admin UI in the same binary: users, identities, providers, email templates, audit log, webhook delivery log.
- `verify` subcommand and `/healthz/deep` endpoint that actually exercise signup, password reset email delivery, and each configured OAuth provider's discovery endpoint — reporting specifically what is broken.
- Static musl-linked binary with no runtime dependencies. `./auth serve` and you are up.
- Migrations as a subcommand with a documented rollback story.

**2. Correctness via types.** Endpoint authorization requirements (`anonymous`, `valid-session`, `service-role`) live in Servant route signatures and are enforced at compile time across every handler. Token, session, and MFA state transitions are total functions over sum types. This is hard to do convincingly in Go or TypeScript and is the honest reason to choose Haskell here.

Drop-in Supabase compatibility is the *wedge* — the reason someone bothers to try this. UX and correctness are the reasons they stay.

## Non-goals

- **Hosted SaaS.** The product is the binary. Commercial offerings, if any, come later and built on top.
- **Database-agnostic.** Postgres only. RLS-aware JWT issuance is the entire point.
- **ORM layer.** Direct SQL via postgresql-simple. We want control over query shape and we want the `auth` schema to be inspectable as plain SQL.
- **Reinventing OAuth.** Supported providers are Google and GitHub via the OAuth 2.0 authorization-code flow with compiled-in token and userinfo endpoints; arbitrary OIDC providers via runtime discovery are a v0.4 conversation. See [docs/OAUTH.md](docs/OAUTH.md) for what is and isn't covered today. No exotic flows.
- **Multi-tenancy in v1.** Single project per deployment. Multi-project is a v2 conversation.
- **Reshaping the Supabase JWT.** We may add fields, never move or rename existing claims.

## Architecture at a glance

- **HTTP layer:** Servant. Auth requirements expressed in route types.
- **Database:** Postgres only, `auth` schema, postgresql-simple for queries, sqitch or dbmate for migrations run via a subcommand.
- **Crypto:** jose for JWT (ES256 default, HS256 supported for compatibility), Argon2id for passwords via libsodium bindings.
- **Outbound:** http-client for OAuth providers, pluggable email backend (SMTP, Resend, Postmark, SES), pluggable SMS backend (Twilio first).
- **Build and distribution:** Static musl binary via Nix or ghc-musl. Subcommands: `serve`, `verify`, `migrate`, `admin`.

## Hook model

A small fixed set of **synchronous** hook points with strict 2–3 second timeouts that can reject or modify the outcome of an auth event:

- `before-user-created`
- `custom-access-token`
- `mfa-verification-attempt`
- `password-verification-attempt`

Separately, **asynchronous** webhooks for events (`user.signed_up`, `password.changed`, `session.revoked`, etc.) with at-least-once delivery, exponential backoff, and a delivery log inspectable from the admin UI. The inspectable log is itself part of the self-hosting UX bet — debugging webhook delivery in GoTrue today is genuinely painful.

## Compatibility contract

We commit to matching, where reasonable:

- The `auth.users`, `auth.identities`, `auth.sessions`, `auth.refresh_tokens`, `auth.mfa_factors` table shapes.
- JWT claim names and positions (`sub`, `role`, `aud`, `email`, `app_metadata`, `user_metadata`, `aal`, `amr`).
- Core REST endpoint paths and request/response shapes (`/signup`, `/token`, `/user`, `/recover`, `/verify`, `/logout`, admin endpoints under `/admin/`).

We do not commit to:

- Internal helper function names or SQL trigger names.
- Behavior on Supabase-proprietary extensions outside the public auth API.
- Bug-for-bug compatibility. Known GoTrue bugs we will fix and document.

## Open questions

- **Admin UI implementation.** Haskell-rendered templates for single-binary simplicity.
- **MFA scope for v0.1.** TOTP. WebAuthn likely v0.5.
- **SAML / SSO.** v0.5 at earliest, more likely later.

## Roadmap shape

Sequence, not dates.

- **v0.1 — Core flows.** Email/password signup and login, password reset, email verification, OAuth (Google and GitHub), JWT with refresh rotation, sessions, basic admin API. Config file with validation. Static binary. `migrate` and `healthz`. *Shipped.*
- **v0.2 — Operator experience.** Webhook delivery log. Synchronous hooks. `verify` subcommand. Hot-reloaded email templates. `/healthz/deep`. TOTP MFA. *Shipped.*
- **v0.3 — Admin UI.** Admin UI (deferred from v0.2). Audit log surfaced in admin UI. Additional first-party OAuth providers (Microsoft, GitLab, Apple, Discord).
- **v0.4 — Parity push.** Magic links. Phone/SMS OTP. Anonymous users. Config-only OIDC OAuth provider. MFA recovery codes. Webhook secret rotation. Structured JSON logging. Container deployment guides (Docker Compose, Kubernetes). Additional email template variables.
- **v0.5+** — WebAuthn, SAML/SSO, captcha integrations, anything else needed for serious enterprise self-hosting.

## How we will know it is working

Three tests, in roughly increasing order of difficulty:

1. An existing Supabase project can swap to this service by changing one DNS record and zero RLS policies.
2. A first-time operator can go from `docker run` to a working signup-and-login flow without reading documentation beyond `--help`.
3. Someone who knows Haskell but has never seen this codebase can add a new OAuth provider in under a day.
