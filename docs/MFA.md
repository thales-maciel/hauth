# MFA (TOTP) Enrollment and Verification

This guide covers the operator perspective: what endpoints exist, what
request/response shapes to expect, and how to integrate the flow into your
frontend client. It does not cover end-user UX, specific framework SDKs, or
factor types beyond TOTP.

---

## Overview

hauth implements Time-based One-Time Password (TOTP) MFA per RFC 6238. When a
user enrolls and verifies a TOTP factor, the server elevates their session to a
higher Authenticator Assurance Level (AAL).

### AAL1 vs AAL2

| Level | Meaning | When set |
|-------|---------|----------|
| `aal1` | Password (or equivalent single-factor) only | After a normal password login |
| `aal2` | Password + a second factor | After a successful TOTP verify step |

The `aal` claim is embedded in the JWT access token. Downstream services that
need to gate features on MFA completion should check `aal == "aal2"` in the
token before granting access. hauth itself does not gate any of its own
endpoints on AAL2 — that enforcement is the downstream service's
responsibility.

### The AMR array

The `amr` (Authentication Methods References) array in the access token records
which authentication methods were used and when. After a password login the
array is:

```json
[{"method": "password", "timestamp": 1748700000}]
```

After a TOTP verify step it becomes:

```json
[
  {"method": "password", "timestamp": 1748700000},
  {"method": "totp",     "timestamp": 1748700000}
]
```

Both entries carry the same timestamp (when the token was issued), matching
the Supabase Auth v2 wire format.

---

## The Enrollment Flow

Enrollment is a three-step sequence: enroll, challenge, verify. The first
`verify` call both completes enrollment (the factor moves from `unverified` to
`verified`) and elevates the session to AAL2 in one shot.

```
Client                          hauth
  |                               |
  |-- POST /factors ------------->|  (AAL1 bearer token)
  |<- {id, totp:{secret,uri}} ----|
  |                               |
  |  [user scans QR / enters     |
  |   secret in authenticator]   |
  |                               |
  |-- POST /factors/{id}/challenge|
  |<- {id: <challenge_id>} -------|
  |                               |
  |-- POST /factors/{id}/verify --|  {challenge_id, code}
  |<- {access_token, ...} --------|  (aal:"aal2")
```

### Step 1 — Enroll: `POST /factors`

**Auth:** valid AAL1 bearer token (`Authorization: Bearer <access_token>`).

**Request body:**

```json
{
  "factor_type": "totp",
  "friendly_name": "My Phone"
}
```

| Field | Required | Notes |
|-------|----------|-------|
| `factor_type` | yes | Must be `"totp"` (only supported type in v0.1) |
| `friendly_name` | no | Human-readable label; stored but not validated |
| `issuer` | no | Overrides the JWT issuer in the `otpauth://` URI |

**Response (200):**

```json
{
  "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "type": "totp",
  "friendly_name": "My Phone",
  "status": "unverified",
  "totp": {
    "secret": "JBSWY3DPEHPK3PXP",
    "qr_code": "otpauth://totp/hauth:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=hauth&algorithm=SHA1&digits=6&period=30",
    "uri":     "otpauth://totp/hauth:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=hauth&algorithm=SHA1&digits=6&period=30"
  }
}
```

Key response fields:

- `id` — the factor UUID; store this in your frontend session to use in the
  challenge and verify calls.
- `totp.secret` — BASE32-encoded 20-byte secret. Show this to the user as a
  manual entry fallback if they cannot scan the QR code.
- `totp.uri` — an `otpauth://` URI. Feed this to a QR-rendering library to
  produce the scannable code.
- `totp.qr_code` — identical to `totp.uri` in v0.1. In future versions this
  may become a data URL containing the rendered image; for now render the URI
  yourself (see [Frontend integration tips](#frontend-integration-tips)).
- `status` — starts as `"unverified"`; becomes `"verified"` on the first
  successful verify call.

The `totp` object is only present on the enroll response. Subsequent `GET
/factors` calls return the factor without the secret.

### Step 2 — Challenge: `POST /factors/{id}/challenge`

**Auth:** same bearer token as enrollment.

**Request body:** an empty JSON object `{}`. For TOTP, no server-side state is
needed — the code is time-based. The challenge is a lightweight acknowledgement
that the client is ready to verify.

**Response (200):**

```json
{
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "type": "totp",
  "expires_at": "2025-01-01T12:05:00Z"
}
```

| Field | Notes |
|-------|-------|
| `id` | Challenge UUID — pass this as `challenge_id` in the verify request |
| `expires_at` | 300 seconds from the challenge creation time |

### Step 3 — Verify: `POST /factors/{id}/verify`

**Auth:** same bearer token.

**Request body:**

```json
{
  "challenge_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "code": "123456"
}
```

| Field | Notes |
|-------|-------|
| `challenge_id` | The `id` from the challenge response |
| `code` | The 6-digit TOTP code currently shown in the user's authenticator app |

**Response (200):** a flat session object identical to the password login
response, but with `aal: "aal2"` embedded in the access token:

```json
{
  "access_token": "<jwt>",
  "token_type": "bearer",
  "expires_in": 3600,
  "refresh_token": "<opaque>",
  "user": { ... }
}
```

Replace the access token in your client with this new token. The refresh token
is unchanged; you do not need to update it.

**On first verify:** the factor's `status` transitions from `"unverified"` to
`"verified"` automatically. You do not need to call a separate confirm endpoint.

---

## Worked Example

These commands run against a local hauth using `config.example.json` (Postgres
at `localhost:5432`, role/db `hauth`, password `hauth`, JWT secret
`0123456789abcdef0123456789abcdef`).

```sh
BASE=http://127.0.0.1:8080

# 1. Sign up and confirm (skip real SMTP for local testing).
curl -sS -X POST "$BASE/signup" \
  -H 'Content-Type: application/json' \
  -d '{"email":"mfa-test@example.com","password":"correct horse battery staple"}'

psql "postgresql://hauth:hauth@localhost:5432/hauth" \
  -c "UPDATE auth.users
      SET email_confirmed_at = now(), confirmation_token = NULL
      WHERE email = 'mfa-test@example.com';"

# 2. Log in (AAL1 session).
ACCESS=$(curl -sS -X POST "$BASE/token?grant_type=password" \
  -H 'Content-Type: application/json' \
  -d '{"email":"mfa-test@example.com","password":"correct horse battery staple"}' \
  | jq -r .access_token)

# 3. Enroll a TOTP factor.
ENROLL=$(curl -sS -X POST "$BASE/factors" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $ACCESS" \
  -d '{"factor_type":"totp","friendly_name":"My Phone"}')

FACTOR_ID=$(echo "$ENROLL" | jq -r .id)
SECRET=$(echo "$ENROLL" | jq -r .totp.secret)
URI=$(echo "$ENROLL" | jq -r .totp.uri)

echo "Factor ID : $FACTOR_ID"
echo "Secret    : $SECRET"
echo "OTP URI   : $URI"

# 4. Challenge.
CHALLENGE=$(curl -sS -X POST "$BASE/factors/$FACTOR_ID/challenge" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $ACCESS" \
  -d '{}')

CHALLENGE_ID=$(echo "$CHALLENGE" | jq -r .id)
echo "Challenge : $CHALLENGE_ID"

# 5. Generate and submit the current TOTP code.
#    Requires the `oathtool` package (or any TOTP client).
CODE=$(oathtool --base32 --totp "$SECRET")
echo "Code      : $CODE"

VERIFY=$(curl -sS -X POST "$BASE/factors/$FACTOR_ID/verify" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $ACCESS" \
  -d "{\"challenge_id\":\"$CHALLENGE_ID\",\"code\":\"$CODE\"}")

echo "$VERIFY" | jq '{access_token: .access_token[0:20], expires_in, refresh_token: .refresh_token[0:8]}'

# 6. The new access token carries aal:"aal2". Inspect the payload:
echo "$VERIFY" | jq -r .access_token \
  | cut -d. -f2 \
  | base64 -d 2>/dev/null \
  | jq '{aal, amr}'
```

Expected output for step 6:

```json
{
  "aal": "aal2",
  "amr": [
    {"method": "password", "timestamp": 1748700000},
    {"method": "totp",     "timestamp": 1748700000}
  ]
}
```

`oathtool` is available in most Linux distro package managers as `oathtool`
(Debian/Ubuntu: `apt install oathtool`; Arch: `pacman -S oath-toolkit`). Any
TOTP client that accepts a BASE32 secret also works.

---

## Verify Flow on Subsequent Logins

Once a factor is enrolled and verified, the user must repeat the
challenge + verify sequence after every password login to reach AAL2. A
password login alone always returns an AAL1 session.

```sh
# Normal password login → aal1.
ACCESS=$(curl -sS -X POST "$BASE/token?grant_type=password" \
  -H 'Content-Type: application/json' \
  -d '{"email":"mfa-test@example.com","password":"correct horse battery staple"}' \
  | jq -r .access_token)

# Retrieve the verified factor id.
FACTOR_ID=$(curl -sS "$BASE/factors" \
  -H "Authorization: Bearer $ACCESS" \
  | jq -r '.totp[0].id')

# Challenge.
CHALLENGE_ID=$(curl -sS -X POST "$BASE/factors/$FACTOR_ID/challenge" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $ACCESS" \
  -d '{}' | jq -r .id)

# Verify with a fresh code.
CODE=$(oathtool --base32 --totp "$SECRET")
curl -sS -X POST "$BASE/factors/$FACTOR_ID/verify" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $ACCESS" \
  -d "{\"challenge_id\":\"$CHALLENGE_ID\",\"code\":\"$CODE\"}" \
  | jq '{access_token: .access_token[0:20]}'
```

The session stays at AAL1 until the verify step succeeds. Calling
`GET /factors` lists all enrolled factors; `.totp[]` contains only the
verified ones.

---

## What Requires AAL2

hauth itself does not gate any of its own endpoints on AAL2. The `aal` and
`amr` claims in the access token are informational — they let downstream
services (your API, your BFF, RLS policies in Postgres, etc.) enforce
second-factor requirements.

**Convention:** check `aal == "aal2"` in the JWT payload of the incoming
access token before allowing access to sensitive operations. Do not rely on the
`amr` array alone; `aal` is the authoritative derived field.

Example JWT payload check (pseudo-code):

```
claims = verify_jwt(access_token, secret)
if claims["aal"] != "aal2":
    return 403 Forbidden
```

---

## Recovery Codes

Recovery codes are **not implemented in v0.1**.

If a user loses access to their authenticator app, the only recovery path is
for an administrator to delete the factor via the admin API:

```sh
# Service-role JWT required.
SERVICE_JWT="<your-service-role-jwt>"

curl -sS -X DELETE "$BASE/admin/users/$USER_ID/factors/$FACTOR_ID" \
  -H "Authorization: Bearer $SERVICE_JWT"
```

> Note: the admin factor-delete endpoint is on the roadmap; check open issues
> for the current status. In the interim, an admin can also delete the factor
> row directly in the database:
>
> ```sql
> DELETE FROM auth.mfa_factors WHERE id = '<factor_id>';
> ```
>
> After deletion the user's next login returns an AAL1 session with no factors
> enrolled and they can re-enroll.

This is a known limitation tracked for a future release.

---

## Frontend Integration Tips

### Rendering the QR code

`totp.uri` is an `otpauth://` URI. Pass it to a QR-encoding library in your
frontend to produce the scannable image. A few options (no recommendation —
choose what fits your stack):

- **qrcode** (npm) — `qrcode.toDataURL(uri)` → data URL for an `<img>`
- **qrcode.react** (npm) — `<QRCode value={uri} />` for React
- **python-qrcode** (PyPI) — `qrcode.make(uri).save("factor.png")`
- **qrencode** (CLI) — `echo -n "$URI" | qrencode -o factor.png`

`totp.secret` (the raw BASE32 string) is the manual entry fallback for users
whose camera does not work.

### Storing the factor ID during enrollment

The factor `id` returned from `POST /factors` is only needed during enrollment
(challenge + verify). Keep it in component state or a short-lived session
variable. There is no need to persist it to localStorage or a database on the
client side — once enrollment completes, `GET /factors` lets the client look up
verified factors at any time.

### Token replacement

After a successful `POST /factors/{id}/verify`, replace the in-memory access
token with the new one from the response. The refresh token is unchanged and
does not need to be updated. The new access token carries `aal: "aal2"`.

---

## Troubleshooting

### "invalid_code" (401) — code rejected

**Most likely cause:** clock skew between the user's device and the server.

hauth accepts codes for the current 30-second window plus the immediately
preceding and following windows (±1 step = up to ±30 seconds of skew). If the
device clock is more than 30 seconds off, every code will fail.

**Fix:** sync the device clock via NTP. Most modern phones do this
automatically; a reboot or toggling airplane mode can force re-sync.

**Other causes:**

- Typo in the 6-digit code — codes change every 30 seconds; ask the user to
  wait for the next one and try again.
- Wrong factor — user scanned the QR for a different account. Check which
  authenticator entry they are reading from.
- The code must be exactly 6 digits (zero-padded). Codes like `"01234"` (5
  chars) are rejected outright.

### "factor_not_found" (404)

The factor UUID in the URL does not match any factor for this user. Check that
you are using the `id` from the enroll response, not the `challenge_id`.

### "forbidden" (403) on challenge or verify

The factor belongs to a different user. The bearer token's `sub` claim must
match the factor's owner.

### Challenge expired

Challenges expire 300 seconds (5 minutes) after creation. If the user takes
longer, issue a new challenge (`POST /factors/{id}/challenge` again) and
re-submit.

### Factor stuck in "unverified"

The factor transitions to `"verified"` on the first successful verify call. If
it remains `"unverified"`, the verify call returned a non-200 status. Check the
response body for the specific error, fix the underlying issue (usually wrong
code or clock skew), and retry verify.

### "unsupported_factor_type" (400)

Only `"totp"` is supported in v0.1. Ensure `factor_type` in the enroll request
body is exactly `"totp"`.
