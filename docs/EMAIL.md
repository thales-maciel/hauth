# Email Templates

## Overview

hauth ships four email templates compiled into the binary at build time:

| Name | Triggered by |
|---|---|
| `confirmation` | Signup (confirmation email) |
| `recovery` | Password reset request |
| `invite` | Admin invite (`POST /admin/users`) |
| `email_change` | Email address change request |

At startup hauth loads any rows present in `auth.email_templates`. If a row
exists for a given name it overrides the compiled default; if the row is
absent the compiled default is used. Changes to `auth.email_templates` are
propagated to the running server via Postgres `LISTEN/NOTIFY` on the
`email_templates_updated` channel — usually within one second, at most a
few seconds on a loaded system.

## Template Variables

Every template body (text and HTML) and the subject line support the
following `{{var}}` placeholders:

| Placeholder | Description | Available in |
|---|---|---|
| `{{recipient_email}}` | Email address of the recipient | All templates |
| `{{action_url}}` | The verification / reset link the user should click | All templates |
| `{{site_url}}` | Value of `site.url` from `config.json` | All templates |
| `{{token_hash}}` | Raw token (opaque string; also embedded in `action_url`) | All templates |

Unknown placeholders are left unchanged in the rendered output.

Adding new variables is not supported in v0.2; variable expansion is deferred
to v0.3.

## Editing a Template

Use the service-role JWT to upsert a row:

```sh
SVC_JWT="<your service-role token>"

curl -sS -X PUT http://127.0.0.1:8080/admin/email-templates/confirmation \
  -H "Authorization: Bearer ${SVC_JWT}" \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "Welcome — please confirm your email",
    "body_text": "Hi {{recipient_email}},\n\nConfirm here: {{action_url}}\n\n-- {{site_url}}",
    "body_html": "<p>Hi {{recipient_email}},</p><p><a href=\"{{action_url}}\">Confirm your email</a></p>"
  }'
```

A successful response is `200 OK` with the stored row as JSON. The running
server picks up the change automatically via `LISTEN/NOTIFY`; no restart is
needed.

To list all overridden templates:

```sh
curl -sS http://127.0.0.1:8080/admin/email-templates \
  -H "Authorization: Bearer ${SVC_JWT}"
```

To read a single template's current DB override:

```sh
curl -sS http://127.0.0.1:8080/admin/email-templates/confirmation \
  -H "Authorization: Bearer ${SVC_JWT}"
```

## Reverting to the Compiled Default

Send a `DELETE` to remove the DB override. Subsequent emails will use the
compiled-in default again:

```sh
curl -sS -X DELETE http://127.0.0.1:8080/admin/email-templates/confirmation \
  -H "Authorization: Bearer ${SVC_JWT}"
```

Returns `204 No Content` on success. A `DELETE` on a name that has no DB row
is also a no-op (idempotent).

## Troubleshooting

**The change isn't reflected in sent emails.**

1. Check the DB row is present:
   ```sh
   curl -sS http://127.0.0.1:8080/admin/email-templates/confirmation \
     -H "Authorization: Bearer ${SVC_JWT}"
   ```
   A `404` means hauth fell back to the compiled default (no row in
   `auth.email_templates`).

2. Verify the `LISTEN/NOTIFY` thread is healthy. Look for log lines tagged
   `[warn]` that mention `email_templates` — these indicate a reconnect loop
   is running. The cache will recover once the connection to Postgres is
   re-established.

3. If hauth was restarted after a DB failure it will reload the cache on
   reconnect; no further action is needed.

**Adding a new variable does not expand.**

Variable substitution is fixed at compile time in v0.2. Only the four
placeholders listed above are supported. Adding a custom `{{my_var}}` in
the template body will leave `{{my_var}}` literally in the rendered output.
New variable support is tracked for v0.3.
