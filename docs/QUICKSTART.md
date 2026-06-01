# Quickstart

Go from zero to a running hauth with signup and login in about ten minutes.
This guide targets operators self-hosting hauth against their own Postgres on
Linux. For OAuth provider setup see [`docs/OAUTH.md`](OAUTH.md); for MFA (TOTP)
enrollment and verification see [`docs/MFA.md`](MFA.md); for production
hardening see [`docs/PRODUCTION.md`](PRODUCTION.md).

## Prerequisites

- **Linux x86_64** host (any distro — the binary is fully static, no glibc).
- **Postgres 13 or newer** reachable from the host. You need permission to
  create a database and a role.
- **`curl`**, **`psql`**, and **`jq`** on the host. The smoke test pipes
  through `jq`; `psql` is whatever your distro packages as
  `postgresql-client`.
- **`sudo`** (or write access to `/usr/local/bin`) so the install step can
  drop the binary somewhere on `PATH`.
- **An SMTP target** for outbound email. For a local trial run you can use
  MailHog — `docker run -d -p 1025:1025 -p 8025:8025 mailhog/mailhog` brings
  up an SMTP server on `:1025` and a web inbox on `http://localhost:8025`. For
  the smoke test below we skip email entirely by flipping the confirmation
  flag in SQL. If SMTP is unreachable, signup still returns 200 — the
  confirmation email just never arrives.

No language tooling required.

## 1. Install

Grab the static release binary from the
[Releases page](https://github.com/thales-maciel/hauth/releases). Pick the
latest tag, then:

```sh
VERSION=v0.1.1  # replace with the latest release tag
ARCH=linux-x86_64

curl -LO "https://github.com/thales-maciel/hauth/releases/download/${VERSION}/hauth-${VERSION}-${ARCH}.tar.gz"
curl -LO "https://github.com/thales-maciel/hauth/releases/download/${VERSION}/hauth-${VERSION}-${ARCH}.tar.gz.sha256"
sha256sum -c "hauth-${VERSION}-${ARCH}.tar.gz.sha256"

tar -xzf "hauth-${VERSION}-${ARCH}.tar.gz"
sudo install -m 0755 "hauth-${VERSION}-${ARCH}" /usr/local/bin/hauth

hauth --help
```

## 2. Create the database

```sql
-- Skip the first two lines if this is a genuinely fresh Postgres.
DROP DATABASE IF EXISTS hauth;
DROP ROLE     IF EXISTS hauth;

CREATE ROLE hauth LOGIN PASSWORD 'change-me';
CREATE DATABASE hauth OWNER hauth;
```

hauth owns and manages the `auth` schema inside this database. The migration
runner creates the schema on first run; the `hauth` role needs `CREATE` on
the database, which the ownership above grants.

## 3. Write `config.json`

Minimal config to get running:

```json
{
  "database": {
    "url": "postgresql://hauth:change-me@localhost:5432/hauth",
    "pool_size": 5
  },
  "jwt": {
    "secret": "REPLACE-WITH-32-RANDOM-BYTES-HEX",
    "issuer": "hauth",
    "audience": "authenticated",
    "access_token_ttl_seconds": 3600,
    "refresh_token_ttl_seconds": 2592000
  },
  "site": {
    "url": "http://localhost:3000",
    "allowed_redirect_urls": ["http://localhost:3000/auth/callback"]
  },
  "email": {
    "from": "noreply@example.com",
    "smtp_host": "localhost",
    "smtp_port": 1025
  },
  "oauth": { "providers": [] },
  "server": { "host": "127.0.0.1", "port": 8080 }
}
```

The three fields you **must** change before exposing this to anything beyond
`localhost`:

- `database.url` — point at your real Postgres.
- `jwt.secret` — generate fresh entropy (`openssl rand -hex 32`). Tokens are
  signed with this; rotating it invalidates every issued session.
- `site.url` and `site.allowed_redirect_urls` — your frontend's origin and
  the redirect URLs you trust for email/OAuth callbacks.

See [`config.example.json`](../config.example.json) for the full schema,
including OAuth provider blocks.

## 4. Migrate and serve

```sh
hauth migrate up   --config config.json
hauth serve        --config config.json
```

`hauth serve` doesn't print a startup banner — it just blocks. Hit
`http://127.0.0.1:8080/healthz` from another shell to confirm it's up; that
returns `{"status":"ok"}`. The deeper check at
`http://127.0.0.1:8080/healthz/deep` returns `{"status":"ok", "checks":
[...]}` once Postgres is reachable from the process.

If `8080` is already taken on your host, override it: either set
`server.port` in `config.json`, pass `--port 18080`, or set `HAUTH_PORT=18080`.
Then update every URL below to match.

## 5. Verify the configuration (recommended)

Before exposing the service, run:

```sh
hauth verify --config config.json
```

This exercises every configured surface — database, JWT, SMTP, OAuth
providers — and reports specifically what's broken. A passing report is
the precondition for the smoke test below.

```sh
hauth verify --config config.json --format json | jq
```

## 6. Smoke test

In a second shell, with `hauth serve` still running:

```sh
# Sign a user up. Returns the new user; no session yet (email unconfirmed).
curl -sS -X POST http://127.0.0.1:8080/signup \
  -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com","password":"correct horse battery staple"}'

# Confirm the email by hand (skips needing real SMTP for this trial).
# In real use the user clicks the verification link emailed via your SMTP.
psql "postgresql://hauth:change-me@localhost:5432/hauth" \
  -c "UPDATE auth.users SET email_confirmed_at = now(), confirmation_token = NULL WHERE email = 'alice@example.com';"

# Log in. Returns access_token + refresh_token + user.
ACCESS=$(curl -sS -X POST 'http://127.0.0.1:8080/token?grant_type=password' \
  -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com","password":"correct horse battery staple"}' \
  | jq -r .access_token)

# Read the authenticated user with the bearer token.
curl -sS http://127.0.0.1:8080/user -H "Authorization: Bearer ${ACCESS}"
```

The last call should return JSON for `alice@example.com` with `aud:
"authenticated"` and `email_confirmed_at` populated. If that works, the
service is running end-to-end against your Postgres.

## Next steps

- [`docs/PRODUCTION.md`](PRODUCTION.md) — production hardening: TLS
  termination (Caddy config), systemd unit file, Postgres pool sizing, secret
  rotation, backups, and a hardening checklist. Read this before accepting
  real traffic.
- [`docs/v0.1-compatibility.md`](v0.1-compatibility.md) — the Supabase-compat
  contract: which endpoints exist, which fields are emitted, and which v0.1
  intentionally omits.
- [`PROJECT.md`](../PROJECT.md) — product direction, milestone scope, and
  what's deferred to v0.2 and beyond.
- [Open issues](https://github.com/thales-maciel/hauth/issues) — per-feature
  docs and roadmap items.

- [`docs/OAUTH.md`](OAUTH.md) — OAuth provider setup: configuring Google and
  GitHub, the exact redirect URI to register with each provider, and common
  errors.
- [`docs/MFA.md`](MFA.md) — MFA (TOTP) enrollment and verification, AAL2
  semantics, and recovery limitations.

Webhook delivery is implemented but not covered here — it will get a dedicated
doc in a future release.
