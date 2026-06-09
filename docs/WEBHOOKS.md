# Webhooks

hauth emits HTTP webhook deliveries for auth-state changes — signup, login,
session revoke, MFA enrollment, admin user CRUD, and so on. The bus is the
**outbox pattern**: every domain mutation writes a row to
`auth.webhook_deliveries` inside the same transaction; a background worker
inside `hauth serve` polls that table and dispatches each delivery with
HMAC-signed headers. There is no external queue — everything is inspectable
from `psql`.

## Subscribing

Create a subscription via the service-role-gated admin API:

```sh
curl -sS -X POST https://your-hauth/admin/webhooks \
  -H "Authorization: Bearer $SERVICE_ROLE_JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://your-receiver.example.com/hauth",
    "secret": "your-shared-secret",
    "events": []
  }'
```

`events` is the filter:

- `[]` (or omitted) → subscribe to every event hauth emits.
- `["user.signed_up", "session.revoked"]` → only those two; everything else
  is skipped at the SQL `cardinality(events) = 0 OR event_type = ANY(events)`
  check.

Omit `secret` and hauth generates a 32-byte hex secret automatically.
The secret is returned **once** in the create response:

```json
{
  "id": "8f7c…",
  "url": "https://your-receiver.example.com/hauth",
  "events": [],
  "secret": "<generated-or-supplied>",
  "disabled_at": null,
  "created_at": "...",
  "updated_at": "..."
}
```

**Store the secret immediately.** All subsequent `GET` and list responses emit
`"secret": "***redacted***"`. To replace a secret, use
`POST /admin/webhooks/:id/rotate-secret` (see below).

**Encryption at rest.** Secrets are currently stored as plaintext in the
`auth.webhook_subscriptions` table. Full encryption at rest is out of scope
for this release; restrict access via Postgres role permissions on the `auth`
schema.

To pause deliveries without losing history, `PUT` `disabled_at` to a
timestamp. To delete the subscription entirely, `DELETE
/admin/webhooks/{id}` — pending deliveries cascade-delete with it.

### Rotating the signing secret

Use `POST /admin/webhooks/:id/rotate-secret` to replace the HMAC signing
secret. The new secret is returned once in the response; subsequent reads
redact it.

**Server-generated secret (recommended):**
```sh
curl -sS -X POST https://your-hauth/admin/webhooks/${SUB_ID}/rotate-secret \
  -H "Authorization: Bearer $SERVICE_ROLE_JWT" \
  -H "Content-Type: application/json" \
  -d '{}'
# Response: {"secret": "<64-char hex>"}
```

**Caller-supplied secret:**
```sh
curl -sS -X POST https://your-hauth/admin/webhooks/${SUB_ID}/rotate-secret \
  -H "Authorization: Bearer $SERVICE_ROLE_JWT" \
  -H "Content-Type: application/json" \
  -d '{"secret": "my-new-shared-secret"}'
# Response: {"secret": "my-new-shared-secret"}
```

Update the `SECRET` constant in your receiver before decommissioning the old
one. The `PUT /admin/webhooks/:id` endpoint does **not** change the secret;
pass only `url`, `events`, and `disabled_at` fields to avoid accidentally
triggering rotation.

### Migration note for existing clients

If you currently read back the `secret` field from `GET /admin/webhooks/:id`
or the list endpoint, those responses now return `"***redacted***"` instead of
the plaintext value. Store the secret from the create response or use
`/rotate-secret` to issue a new known-good secret.

## Event catalog

| `event_type` | Variant | Payload fields |
|---|---|---|
| `user.signed_up` | `UserSignedUp` | `user_id`, `email`, `created_at` |
| `user.email_confirmed` | `UserEmailConfirmed` | `user_id`, `email`, `created_at` |
| `user.recovered` | `UserRecovered` | `user_id`, `email`, `created_at` |
| `user.deleted` | `UserDeleted` | `user_id`, `email`, `created_at` |
| `user.admin_created` | `UserAdminCreated` | `user_id`, `email`, `created_at` |
| `user.admin_updated` | `UserAdminUpdated` | `user_id`, `email`, `created_at` |
| `user.password_changed` | `PasswordChanged` | `user_id`, `email`, `created_at` |
| `session.revoked` | `SessionRevoked` | `session_id`, `user_id` |
| `mfa.enrolled` | `MfaEnrolled` | `factor_id`, `user_id` |
| `mfa.verified` | `MfaVerified` | `factor_id`, `user_id` |

The wire body is always wrapped in the standard envelope:

```json
{
  "event_type": "user.signed_up",
  "delivery_id": "8f7c…",
  "issued_at": "2026-06-02T16:42:00Z",
  "payload": { "user_id": "…", "email": "alice@example.com", "created_at": "..." }
}
```

`delivery_id` matches `auth.webhook_deliveries.id` and is what you'll see
through `GET /admin/deliveries/{id}` — convenient for tracing a specific
delivery through your receiver logs.

## Signature verification

Every request carries three headers, following the
[Standard Webhooks](https://www.standardwebhooks.com/) convention:

| Header | Value |
|---|---|
| `webhook-id` | The delivery row UUID (same as `delivery_id` in the body) |
| `webhook-timestamp` | Unix seconds at sign time |
| `webhook-signature` | `v1,<base64 HMAC-SHA256(secret, "{id}.{timestamp}.{body}")>` |

The signed string is `{webhook-id}.{webhook-timestamp}.{raw_body}`. Reject
requests whose `webhook-timestamp` is more than **5 minutes** off your own
clock — that's hauth's own verifier window.

### Python receiver

```python
import hashlib
import hmac
import base64
import time

def verify(secret: bytes, wid: str, wts: str, wsig: str, body: bytes) -> bool:
    if abs(int(time.time()) - int(wts)) > 300:
        return False
    signed = f"{wid}.{wts}.".encode() + body
    expected = "v1," + base64.b64encode(hmac.new(secret, signed, hashlib.sha256).digest()).decode()
    # Tolerate multiple space-separated signatures (future secret rotation).
    return any(hmac.compare_digest(expected, candidate.strip()) for candidate in wsig.split(" "))
```

### Node receiver

```js
import crypto from "node:crypto";

function verify(secret, wid, wts, wsig, body) {
  if (Math.abs(Math.floor(Date.now() / 1000) - parseInt(wts, 10)) > 300) return false;
  const signed = Buffer.concat([Buffer.from(`${wid}.${wts}.`), body]);
  const expected = "v1," + crypto.createHmac("sha256", secret).update(signed).digest("base64");
  return wsig.split(" ").some(c => crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(c.trim())));
}
```

Both examples use a constant-time comparison so that a wrong-by-one-bit
attacker can't measure how many leading bytes matched.

## Delivery semantics

- **At-least-once.** A delivery is committed to the outbox inside the same
  transaction as its source mutation, so the event is durably persisted
  before the worker sees it. The same row can be retried after a network
  blip and arrive twice; **make your receiver idempotent on `delivery_id`**.
- **No ordering guarantee.** The worker runs single-threaded for v0.2 but
  retries skip-locked, so a failing delivery for subscription A doesn't
  block delivery to subscription B.
- **Retry schedule.** Failures (network error, non-2xx) trip an exponential
  backoff: 1m, 5m, 15m, 1h, 6h, 24h. After 6 attempts the row is marked
  `exhausted` and the worker stops touching it. HTTP timeout is 10s per
  attempt.
- **Truncation.** The response body is truncated to the first 2KB before
  being stored in `auth.webhook_deliveries.response_body`.

## Inspecting deliveries

For one subscription:

```sh
curl -sS "https://your-hauth/admin/webhooks/$SUB_ID/deliveries?limit=50" \
  -H "Authorization: Bearer $SERVICE_ROLE_JWT"
```

For a specific delivery:

```sh
curl -sS https://your-hauth/admin/deliveries/$DELIVERY_ID \
  -H "Authorization: Bearer $SERVICE_ROLE_JWT"
```

To retry a failed delivery (resets `next_attempt_at = now()` and lets the
worker pick it up; refuses with 409 if the row is already `sent`):

```sh
curl -sS -X POST https://your-hauth/admin/deliveries/$DELIVERY_ID/retry \
  -H "Authorization: Bearer $SERVICE_ROLE_JWT"
```

In `psql`:

```sql
-- Most recent failures across all subscriptions
SELECT id, event_type, attempts, response_status, last_error, next_attempt_at
FROM auth.webhook_deliveries
WHERE status IN ('failed', 'exhausted')
ORDER BY updated_at DESC
LIMIT 20;
```

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Deliveries stay `pending` forever | The worker isn't running — confirm `hauth serve` (not `migrate`) is the process; `serve` starts the worker, `migrate` does not. |
| Receiver gets `webhook-signature` mismatches | Make sure you're HMACing the **raw** body bytes — not the JSON pretty-printed by your framework's middleware. The secret field in `GET` responses is `"***redacted***"` — use the create/rotate response or query `auth.webhook_subscriptions` directly in `psql` to confirm the stored value. |
| `403`/`401` from your receiver shows up as `exhausted` after 6 attempts | hauth treats every non-2xx as failure; check the receiver's auth requirements. |
| Receiver returns 200 but your processing fails | Return non-2xx so hauth retries. 200 marks the delivery `sent` permanently. |
| `connection refused` in `last_error` | TLS issue or DNS issue at the receiver hostname; hauth doesn't proxy. |
| Two of the same event for one source action | At-least-once semantics; the receiver should dedupe on `delivery_id`. |

Webhook secrets, the subscription's `events` filter, and the retry/backoff
schedule are not yet configurable per-subscription beyond what the admin API
exposes today — that's a v0.4 enhancement.
