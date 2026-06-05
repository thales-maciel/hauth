# Sync Hooks

Sync hooks let you intercept authentication events before they complete. When a
hook is configured for a hook point, hauth calls your HTTP endpoint, waits for
a decision, and then either proceeds, modifies the outcome, or rejects the
operation — all within the same request lifecycle.

This document covers sync hooks only. For async event delivery (webhooks) see
[`docs/WEBHOOKS.md`](WEBHOOKS.md) (coming soon).

## Overview

### Sync vs. webhooks

| | Sync hooks | Webhooks |
|---|---|---|
| Execution | Inline, blocks the auth request | Async, queued after the fact |
| Can reject / modify | Yes | No |
| Delivery guarantee | At-most-once (no retry on timeout) | At-least-once (retry queue) |
| Attempt log | No — check your receiver's logs | Yes (`auth.webhook_deliveries`) |

### Failure semantics

Every hook configuration has a `fail_open` flag (default `false`):

- `fail_open = false` — if the receiver is unreachable, times out, or returns
  a non-2xx status, the auth operation is **rejected**. Use this when the hook
  enforces a security policy.
- `fail_open = true` — failures are silently ignored and the auth operation
  **proceeds** as if no hook were configured. Use this for enrichment hooks
  where availability matters more than enforcement.

### Timeout

Each hook row has a `timeout_ms` field (100–3000 ms, default 2000). hauth
waits at most that long for a response. If the receiver does not reply in time,
the failure semantics above apply.

## Configuration

Hooks are managed via the `/admin/hooks` REST API, which requires a
service-role bearer token.

### Create a hook

```sh
curl -sS -X POST http://127.0.0.1:8080/admin/hooks \
  -H "Authorization: Bearer ${SERVICE_ROLE_JWT}" \
  -H "Content-Type: application/json" \
  -d '{
    "hook_point": "before-user-created",
    "url":        "https://hooks.example.com/auth/before-user-created",
    "secret":     "32-random-bytes-hex-or-any-string",
    "timeout_ms": 2000,
    "fail_open":  false,
    "enabled":    true
  }'
```

**Fields:**

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `hook_point` | string | yes | — | One of the four hook point names (see below). |
| `url` | string | yes | — | Absolute URL. hauth POSTs the hook payload here. |
| `secret` | string | no | random 32-byte hex | Shared secret for signature verification. |
| `timeout_ms` | int | no | 2000 | Request timeout in milliseconds (100–3000). |
| `fail_open` | bool | no | false | Whether to proceed when the hook is unreachable. |
| `enabled` | bool | no | true | Toggle without deleting the row. |

Only one configuration per hook point is allowed (unique constraint). To change
a hook, update it with `PUT /admin/hooks/:id` or delete and recreate it.

**One-time secret readback.** The `secret` value is returned in full only in
the create response. All subsequent `GET` and list responses emit
`"secret": "***redacted***"`. Store the secret immediately after creation —
it cannot be retrieved again through the API. To replace a secret, use
`POST /admin/hooks/:id/rotate-secret` (see below).

**Encryption at rest.** Secrets are currently stored as plaintext in the
`auth.hooks` table. Full encryption at rest is out of scope for this release;
access should be limited via Postgres role permissions on the `auth` schema.

### List, get, update, delete

```sh
# List all configured hooks
# NOTE: "secret" is always "***redacted***" in list/get responses.
curl -sS http://127.0.0.1:8080/admin/hooks \
  -H "Authorization: Bearer ${SERVICE_ROLE_JWT}"

# Get a single hook by id
curl -sS http://127.0.0.1:8080/admin/hooks/${HOOK_ID} \
  -H "Authorization: Bearer ${SERVICE_ROLE_JWT}"

# Update (partial — only url, timeout_ms, fail_open, enabled can be changed)
# PUT does NOT change the secret. Use /rotate-secret for that.
curl -sS -X PUT http://127.0.0.1:8080/admin/hooks/${HOOK_ID} \
  -H "Authorization: Bearer ${SERVICE_ROLE_JWT}" \
  -H "Content-Type: application/json" \
  -d '{"enabled": false}'

# Delete
curl -sS -X DELETE http://127.0.0.1:8080/admin/hooks/${HOOK_ID} \
  -H "Authorization: Bearer ${SERVICE_ROLE_JWT}"
```

### Rotating the signing secret

Use `POST /admin/hooks/:id/rotate-secret` to replace the HMAC signing secret.
The new secret is returned once in the response; subsequent reads redact it.

**Server-generated secret (recommended):**
```sh
curl -sS -X POST http://127.0.0.1:8080/admin/hooks/${HOOK_ID}/rotate-secret \
  -H "Authorization: Bearer ${SERVICE_ROLE_JWT}" \
  -H "Content-Type: application/json" \
  -d '{}'
# Response: {"secret": "<64-char hex>"}
```

**Caller-supplied secret:**
```sh
curl -sS -X POST http://127.0.0.1:8080/admin/hooks/${HOOK_ID}/rotate-secret \
  -H "Authorization: Bearer ${SERVICE_ROLE_JWT}" \
  -H "Content-Type: application/json" \
  -d '{"secret": "my-new-shared-secret"}'
# Response: {"secret": "my-new-shared-secret"}
```

Update the `SECRET` constant in your receiver to the new value before the old
one is decommissioned.

## The four hook points

### `before-user-created`

Fires during `POST /signup`, after input validation, before the user row is
written to the database.

**Payload:**
```json
{
  "hook_point":   "before-user-created",
  "issued_at":    "1717372800Z",
  "payload": {
    "email":         "alice@example.com",
    "phone":         null,
    "user_metadata": { "plan": "free" },
    "ip":            null
  }
}
```

**Decisions:**

| Decision | Effect |
|---|---|
| `{"decision":"allow"}` | Signup proceeds; `user_metadata` is unchanged. |
| `{"decision":"allow_with","overlay":{"user_metadata":{...}}}` | Signup proceeds; the overlay's `user_metadata` is merged into the user row (overlay wins on key conflicts). |
| `{"decision":"reject","reason":"..."}` | Signup returns HTTP 400 `hook_rejected`; no user row is created. |

---

### `custom-access-token`

Fires inside `issueAccessToken`, called by every path that mints a new access
token (password login, refresh-token rotation, MFA verify, email verify, etc.).

**Payload:**
```json
{
  "hook_point": "custom-access-token",
  "issued_at":  "1717372800Z",
  "payload": {
    "claims": {
      "sub":           "550e8400-e29b-41d4-a716-446655440000",
      "role":          "authenticated",
      "email":         "alice@example.com",
      "aal":           "aal1",
      "session_id":    "7f3d1c2e-...",
      "app_metadata":  {},
      "user_metadata": {}
    },
    "user_id":    "550e8400-e29b-41d4-a716-446655440000",
    "session_id": "7f3d1c2e-...",
    "aal":        "aal1"
  }
}
```

**Decisions:**

| Decision | Effect |
|---|---|
| `{"decision":"allow"}` | Token signed as-is. |
| `{"decision":"allow_with","overlay":{"app_metadata":{...},"user_metadata":{...}}}` | Only `app_metadata` and `user_metadata` from the overlay are merged into the claims before signing. Security-sensitive claims (`sub`, `role`, `exp`, `iat`, etc.) are immutable. |
| `{"decision":"reject","reason":"..."}` | Token issuance fails; the auth endpoint returns HTTP 500 `token_issuance_blocked`. |

---

### `mfa-verification-attempt`

Fires inside `POST /factors/:id/verify`, before the TOTP code is checked.
Rejecting here does **not** reveal whether the submitted code would have been
correct.

**Payload:**
```json
{
  "hook_point": "mfa-verification-attempt",
  "issued_at":  "1717372800Z",
  "payload": {
    "user_id":     "550e8400-e29b-41d4-a716-446655440000",
    "factor_id":   "a1b2c3d4-...",
    "factor_type": "totp",
    "ip":          ""
  }
}
```

**Decisions:**

| Decision | Effect |
|---|---|
| `{"decision":"allow"}` or `{"decision":"allow_with",...}` | TOTP check proceeds normally. |
| `{"decision":"reject","reason":"..."}` | Returns HTTP 400 `mfa_or_password_blocked`. |

---

### `password-verification-attempt`

Fires inside `POST /token?grant_type=password`, before the password hash is
verified. Rejecting here does **not** reveal whether the password would have
been correct.

**Payload:**
```json
{
  "hook_point": "password-verification-attempt",
  "issued_at":  "1717372800Z",
  "payload": {
    "email":   "alice@example.com",
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "ip":      ""
  }
}
```

**Decisions:**

| Decision | Effect |
|---|---|
| `{"decision":"allow"}` or `{"decision":"allow_with",...}` | Password check proceeds normally. |
| `{"decision":"reject","reason":"..."}` | Returns HTTP 400 `mfa_or_password_blocked`. |

## Signature verification

Every hook request carries three headers that together form a Standard Webhooks
signature:

```
webhook-id:        <hook-config-uuid>
webhook-timestamp: <unix-epoch-seconds>
webhook-signature: v1,<base64(HMAC-SHA256(id + "." + timestamp + "." + body))>
```

The signing key is the `secret` stored in `auth.hooks`. Verify in your
receiver before trusting the payload. Multiple `v1,...` values may appear in
`webhook-signature`, space-separated (for key rotation).

See [`docs/WEBHOOKS.md`](WEBHOOKS.md) for the shared signing scheme — sync
hooks and async webhooks use identical header names and HMAC construction.

## Receiver examples

### Python (Flask)

```python
import hashlib, hmac, base64
from flask import Flask, request, jsonify, abort

app = Flask(__name__)
SECRET = b"your-hook-secret"

def verify(secret, wid, wts, wsig, body):
    msg = wid + b"." + wts + b"." + body
    expected = b"v1," + base64.b64encode(
        hmac.new(secret, msg, hashlib.sha256).digest()
    )
    return any(sig.strip() == expected for sig in wsig.split(b" "))

@app.post("/auth/before-user-created")
def before_user_created():
    wid  = request.headers.get("webhook-id",        "").encode()
    wts  = request.headers.get("webhook-timestamp", "").encode()
    wsig = request.headers.get("webhook-signature", "").encode()
    body = request.get_data()

    if not verify(SECRET, wid, wts, wsig, body):
        abort(401)

    payload = request.json["payload"]
    email = payload.get("email", "")

    # Example: block disposable email domains.
    if email.endswith("@mailinator.com"):
        return jsonify({"decision": "reject", "reason": "disposable email not allowed"})

    return jsonify({"decision": "allow"})
```

### Node.js (Express)

```js
const express = require("express");
const crypto  = require("crypto");

const app    = express();
const SECRET = Buffer.from("your-hook-secret");

app.use(express.json({ verify: (req, _res, buf) => { req.rawBody = buf; } }));

function verify(secret, wid, wts, wsig, body) {
  const msg = Buffer.concat([
    Buffer.from(wid + "." + wts + "."),
    body,
  ]);
  const expected = "v1," + crypto.createHmac("sha256", secret).update(msg).digest("base64");
  return wsig.split(" ").some((s) => s.trim() === expected);
}

app.post("/auth/password-verification-attempt", (req, res) => {
  const wid  = req.headers["webhook-id"]        ?? "";
  const wts  = req.headers["webhook-timestamp"] ?? "";
  const wsig = req.headers["webhook-signature"] ?? "";

  if (!verify(SECRET, wid, wts, wsig, req.rawBody)) {
    return res.status(401).end();
  }

  const { email } = req.body.payload;

  // Example: block a specific email.
  if (email === "banned@example.com") {
    return res.json({ decision: "reject", reason: "account suspended" });
  }

  res.json({ decision: "allow" });
});

app.listen(3000);
```

## Troubleshooting

**Hook is configured but not firing.**
Check that `enabled` is `true`. Retrieve the row with `GET /admin/hooks/:id`
and confirm `"enabled": true`.

**All hook calls fail with `hook network error`.**
hauth cannot reach the receiver URL. Verify the URL is reachable from the
hauth process, not just from your workstation. If hauth is in a container,
`http://127.0.0.1:…` points to the container's loopback, not the host.

**Hook fires but the decision is ignored (operation proceeds).**
`fail_open` is probably `true`. If the receiver is timing out or returning
non-2xx, the request silently passes through. Set `fail_open = false` for
enforcement hooks.

**Signature verification always fails.**
Check that the `secret` you verify with matches the `secret` stored in
`auth.hooks`. Secrets are stored in plaintext in the database (see the
encryption-at-rest note above) — query the `auth.hooks` table directly in
`psql` to compare. The API redacts the secret field on all read responses; to
issue a known-good secret use `POST /admin/hooks/:id/rotate-secret` with an
explicit `{"secret": "..."}` body.
Also make sure you are signing over the raw request body bytes, not a
re-serialised version.

**Sync hooks don't store attempt history.**
This is intentional — sync hooks are inline and latency-sensitive. Use your
receiver's own request logs to audit calls. If you need a durable attempt log,
use async webhooks instead.
