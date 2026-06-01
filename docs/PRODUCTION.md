# Production Hardening Guide

This guide picks up where [QUICKSTART.md](QUICKSTART.md) leaves off. It assumes
hauth is already running against a Postgres instance and you want to harden it
for production traffic: TLS, process supervision, database configuration, secret
management, backups, and monitoring.

---

## 1. TLS Termination

hauth does not terminate TLS. This is intentional: a single static binary has
no place managing certificate lifecycle, ACME renewals, or cipher-suite policy.
Put a reverse proxy in front and let hauth listen only on `127.0.0.1`.

### Caddy (recommended)

Caddy handles ACME certificate issuance and renewal automatically. Install from
[caddyserver.com](https://caddyserver.com/docs/install), then write a
`Caddyfile`:

```caddy
auth.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

That is the entire config for HTTPS with auto-renewal. Caddy listens on `:80`
and `:443`, redirects HTTP to HTTPS, obtains a Let's Encrypt certificate for
`auth.example.com`, and forwards all traffic to hauth.

Start and enable:

```sh
sudo systemctl enable --now caddy
```

Verify it is working:

```sh
curl -sS https://auth.example.com/healthz
# {"status":"ok"}
```

### nginx (alternative)

If you prefer nginx, a minimal snippet using Certbot-managed certificates:

```nginx
server {
    listen 443 ssl http2;
    server_name auth.example.com;

    ssl_certificate     /etc/letsencrypt/live/auth.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/auth.example.com/privkey.pem;

    location / {
        proxy_pass         http://127.0.0.1:8080;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }
}

server {
    listen 80;
    server_name auth.example.com;
    return 301 https://$host$request_uri;
}
```

> **Important**: update `server.host` in your config to `"127.0.0.1"` so hauth
> binds only to loopback and is not reachable directly from the network:
>
> ```json
> "server": { "host": "127.0.0.1", "port": 8080 }
> ```

---

## 2. Running Under systemd

systemd keeps hauth running across reboots and restarts it on failure.

### Create the system user

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin hauth
```

### Write the config file

Store the config at `/etc/hauth/config.json` (owned by root, readable by
`hauth`):

```sh
sudo mkdir -p /etc/hauth
sudo cp config.json /etc/hauth/config.json
sudo chown root:hauth /etc/hauth/config.json
sudo chmod 640 /etc/hauth/config.json
```

### Optional: environment file

If you want to override the config path or port via environment variables
without editing the unit, write `/etc/hauth/env`:

```sh
# /etc/hauth/env
HAUTH_CONFIG=/etc/hauth/config.json
```

Secure it:

```sh
sudo chown root:hauth /etc/hauth/env
sudo chmod 640 /etc/hauth/env
```

### Unit file

Write `/etc/systemd/system/hauth.service`:

```ini
[Unit]
Description=hauth authentication service
Documentation=https://github.com/thales-maciel/hauth
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
User=hauth
Group=hauth

EnvironmentFile=/etc/hauth/env
ExecStart=/usr/local/bin/hauth serve --config /etc/hauth/config.json

Restart=on-failure
RestartSec=5s

# Send stdout/stderr to the journal
StandardOutput=journal
StandardError=journal
SyslogIdentifier=hauth

# Harden the process
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=

[Install]
WantedBy=multi-user.target
```

Enable and start:

```sh
sudo systemctl daemon-reload
sudo systemctl enable hauth
sudo systemctl start hauth
sudo systemctl status hauth
```

Check logs:

```sh
sudo journalctl -u hauth -f
```

A successful startup line looks like:

```
[info] hauth listening on http://127.0.0.1:8080
```

### Verify it restarts on failure

```sh
sudo kill -9 $(systemctl show -p MainPID --value hauth)
# Wait ~5 seconds
sudo systemctl is-active hauth   # should print "active"
```

---

## 3. Postgres Production Setup

### Permissions

hauth needs one role that owns the database. The migration runner creates and
manages the `auth` schema; no SUPERUSER privileges are required.

```sql
CREATE ROLE hauth LOGIN PASSWORD 'strong-random-password';
CREATE DATABASE hauth OWNER hauth;
```

The role needs `CREATE` on the database (granted implicitly by ownership). It
does not need `SUPERUSER`, `REPLICATION`, or access to any other database on
the server.

### Connection pool sizing

The default `pool_size` in the Quickstart is `5`. That is intentionally
conservative for a local trial. For a production deployment, `20` is a
reasonable starting point for a single hauth instance:

```json
"database": {
  "url": "postgresql://hauth:...",
  "pool_size": 20
}
```

**Sizing math**: Postgres has a global `max_connections` (default `100`). Subtract
connections for superuser headroom (typically 3) and any admin/migration tooling
you run. Divide the remainder by the number of hauth instances you plan to run.
For a single instance on a shared server with default Postgres settings a pool
of 20 is safe; on a dedicated Postgres server with `max_connections = 200` you
can go higher.

Connections in the pool are idle after `30 seconds` and are returned to
Postgres. The pool never grows beyond `pool_size`.

### pgBouncer is not recommended in v0.2

hauth uses `postgresql-simple`, which issues prepared statements. pgBouncer in
transaction-pooling mode is incompatible with prepared statements. If you place
pgBouncer in front of hauth in transaction mode, queries will fail. Session
pooling mode works but provides no benefit over hauth's built-in pool.

Do not use pgBouncer in front of hauth in v0.2. This constraint may be revisited
in v0.3 if named prepared-statement support is added.

---

## 4. Secret Rotation

### `jwt.secret`

**What it protects**: every issued access token and refresh token is signed with
this key. Anyone who obtains the secret can forge tokens for any user.

**Blast radius of rotation**: rotating the secret immediately invalidates every
active access token and every refresh token. Users will be logged out and must
re-authenticate.

**Rotation procedure**:

1. Set a short `access_token_ttl_seconds` (e.g. `900` = 15 minutes) before
   the rotation window. This shrinks the number of live tokens at rotation time.
2. Generate a new secret:
   ```sh
   openssl rand -hex 32
   ```
3. Update `jwt.secret` in `/etc/hauth/config.json`.
4. Restart hauth at an off-peak time:
   ```sh
   sudo systemctl restart hauth
   ```
5. All existing tokens are immediately invalid. Users will get a 401 on their
   next request and must re-authenticate. Clients that handle 401 by
   re-logging in (standard OAuth behaviour) will recover automatically.

There is no dual-key / zero-downtime rotation in v0.2. Plan for a brief forced
re-login window.

### OAuth `client_secret`

**What it protects**: hauth uses the client secret to exchange OAuth codes for
tokens at the provider. A compromised client secret can be used to impersonate
hauth at the provider.

**Blast radius of rotation**: no active user sessions are affected. Users
who are mid-OAuth-flow at the exact moment of rotation will see an error and
need to restart the OAuth flow.

**Rotation procedure**:

1. Rotate the client secret at the OAuth provider (Google, GitHub, etc.).
2. Update `oauth.providers[*].client_secret` in `/etc/hauth/config.json`.
3. Restart hauth:
   ```sh
   sudo systemctl restart hauth
   ```

### Webhook secrets

**What it protects**: hauth signs webhook payloads with a per-subscription
secret. Receivers use the signature to verify that the payload came from hauth.
A leaked secret allows an attacker to forge webhook payloads.

**Rotation procedure**: rotate per subscription via the admin API:

```sh
curl -sS -X PUT https://auth.example.com/admin/webhooks/{id} \
  -H "Authorization: Bearer ${SERVICE_ROLE_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"secret": "new-secret-value"}'
```

Coordinate with the receiver before rotating — give them the new secret in
advance so they can accept both for a brief overlap window, then drop the old
one.

---

## 5. Backups

### What to back up

hauth stores all state in Postgres inside the `auth` schema. Back up the entire
`hauth` database. Every table matters:

| Table | Consequence of loss |
|---|---|
| `auth.users` | **Catastrophic.** All accounts gone; users cannot log in; data referencing user IDs is orphaned. |
| `auth.sessions` | Active sessions invalidated silently. Users will be forced to re-login on next request. |
| `auth.refresh_tokens` | Refresh grants fail. Access tokens remain valid until they expire. |
| `auth.identities` | OAuth linkages lost. Users cannot log in via OAuth until they re-link. |
| `auth.mfa_factors` | MFA enrollments lost. Users will need to re-enroll. |
| `auth.audit_log_entries` | Audit history lost (no active session impact). |

### `pg_dump` on a schedule

A daily logical backup with `pg_dump`:

```sh
pg_dump \
  --format=custom \
  --compress=9 \
  --file="/var/backups/hauth/hauth-$(date +%Y-%m-%d).dump" \
  "postgresql://hauth:password@localhost:5432/hauth"
```

Automate with a systemd timer or cron. Example cron entry (runs at 02:00 daily,
keeps 30 days of backups):

```cron
0 2 * * * hauth pg_dump --format=custom --compress=9 \
  --file="/var/backups/hauth/hauth-$(date +\%Y-\%m-\%d).dump" \
  "postgresql://hauth:password@localhost:5432/hauth" \
  && find /var/backups/hauth -name "*.dump" -mtime +30 -delete
```

Test that the backup directory exists and is writable by the `hauth` user:

```sh
sudo -u hauth ls /var/backups/hauth
```

### Restore procedure

```sh
# 1. Stop hauth
sudo systemctl stop hauth

# 2. Drop and recreate the database
psql -U postgres -c "DROP DATABASE IF EXISTS hauth;"
psql -U postgres -c "CREATE DATABASE hauth OWNER hauth;"

# 3. Restore
pg_restore \
  --dbname="postgresql://hauth:password@localhost:5432/hauth" \
  /var/backups/hauth/hauth-2026-05-30.dump

# 4. Start hauth
sudo systemctl start hauth

# 5. Verify
curl -sS https://auth.example.com/healthz/deep
```

After a restore, users who had sessions active between the backup timestamp and
the failure time will silently be logged out on their next request.

---

## 6. Monitoring

### Health endpoints

hauth exposes two endpoints for health monitoring:

**`GET /healthz`** — liveness probe. Returns `200` with `{"status":"ok"}` as
long as the process is running and the HTTP server is accepting requests.
Use this as a systemd readiness check or load-balancer liveness probe.

```sh
curl -sS https://auth.example.com/healthz
# 200 {"status":"ok"}
```

**`GET /healthz/deep`** — readiness probe (v0.1.1+). Runs three internal
checks: process (always passes), config (validates that key config fields are
non-empty), and Postgres (issues `SELECT 1` with a 2-second timeout). Returns
`200` with `{"status":"ok","checks":[...]}` if all checks pass; returns `503`
with `{"status":"unhealthy","checks":[...]}` if any check fails.

```sh
curl -sS https://auth.example.com/healthz/deep
# 200 {"status":"ok","checks":[
#   {"name":"process","outcome":"ok"},
#   {"name":"config","outcome":"ok"},
#   {"name":"postgres","outcome":"ok","latency_ms":1}
# ]}
```

Use `/healthz/deep` for external uptime monitors (UptimeRobot, Datadog, etc.)
and alert on `503` responses or on the `postgres` check failing.

### Log format

hauth currently logs to stdout/stderr in a human-readable text format:

```
[info] hauth listening on http://127.0.0.1:8080
[warn] recoverHandler: email send failed: ...
[error] ...
```

Logs are collected by the journal when running under systemd. Query them with:

```sh
sudo journalctl -u hauth --since "1 hour ago"
sudo journalctl -u hauth -p err   # errors only
```

Structured JSON log output is planned for v0.3. For now, use `journalctl`'s
`-o json` flag if you need to forward logs to a log aggregator:

```sh
sudo journalctl -u hauth -o json-pretty | head -20
```

---

## 7. Hardening Checklist

Every item below is testable. Work through it before accepting production
traffic.

- [ ] **TLS in front.** Verify: `curl -v https://auth.example.com/healthz` shows
  `TLSv1.2` or `TLSv1.3` in the handshake output. `curl http://auth.example.com/healthz`
  should redirect to HTTPS (3xx) or return a connection error, not plaintext.

- [ ] **hauth binds to loopback only.** Verify: from a remote host,
  `curl http://<server-ip>:8080/healthz` should time out or be refused. The
  service must not be directly reachable from the internet.

- [ ] **Strong `jwt.secret` (32+ bytes).** hauth rejects secrets shorter than
  32 characters at startup. Verify the value is random entropy, not a
  human-readable passphrase: `openssl rand -hex 32` produces the right format.
  Check your config: the secret field must be at least 32 characters long (the
  hex string above is 64 characters, which is fine).

- [ ] **`site.allowed_redirect_urls` is the actual production list, not
  localhost.** Verify: attempt an OAuth or email-confirmation redirect to a URL
  not in the list — hauth must return an error. Remove `http://localhost:*` entries
  before go-live.

- [ ] **SMTP credentials valid and tested.** Send a test signup and confirm the
  confirmation email arrives. Check hauth logs for any `email send failed`
  warnings.

- [ ] **OAuth client secrets valid.** Attempt a complete OAuth login flow for
  each configured provider. A misconfigured client secret fails at the callback
  step with a provider error.

- [ ] **Webhook subscriptions point at HTTPS receivers.** Inspect configured
  subscriptions via `GET /admin/webhooks` and confirm all `url` fields use
  `https://`. HTTP webhook targets leak payload data in transit.

- [ ] **systemd unit with auto-restart is active.**
  ```sh
  sudo systemctl is-enabled hauth    # should print "enabled"
  sudo systemctl is-active hauth     # should print "active"
  ```

- [ ] **Database backups are scheduled and verified.** Confirm the backup job
  ran: `ls -lh /var/backups/hauth/`. Do a test restore to a scratch database to
  verify the dump is not corrupt.

- [ ] **`/healthz/deep` polled by an external monitor.** Configure your
  uptime monitor to `GET https://auth.example.com/healthz/deep` and alert on
  non-200 or on body containing `"status":"unhealthy"`.

---

## 8. What Is Not Covered in v0.2

These topics are out of scope for v0.2 and will be addressed in later milestones:

- **Secret encryption at rest** — the `config.json` file is plaintext. Protect
  it with filesystem permissions (`chmod 640`, owned by root/hauth group) for
  now. Vault/KMS integration is not yet available.

- **Audit log** — hauth does not yet expose a queryable audit trail of
  authentication events. This is planned for v0.3.

- **Structured / JSON logs** — log output is human-readable text. JSON log
  format is planned for v0.3.

- **Multi-region replication and HA failover** — hauth is a single-instance
  service in v0.2. For high availability, run it behind a load balancer with
  shared Postgres (Patroni, RDS Multi-AZ, etc.) and run multiple hauth
  instances pointing at the same database.

- **Container deploys** — Kubernetes and Docker Compose examples are deferred
  to v0.3. This guide covers the binary + systemd path only.

- **Cloud-vendor-specific guides** — AWS RDS, GCP Cloud SQL, Azure Database for
  PostgreSQL each have quirks (IAM auth, SSL cert pinning, etc.) not covered
  here.
