-- Migration 0011: email_templates table + seed rows mirroring the
-- TH-embedded templates in templates/.

CREATE TABLE auth.email_templates (
    name        text PRIMARY KEY,
    subject     text NOT NULL,
    body_text   text NOT NULL,
    body_html   text NOT NULL,
    updated_at  timestamptz NOT NULL DEFAULT now()
);

INSERT INTO auth.email_templates (name, subject, body_text, body_html) VALUES
(
    'confirmation',
    'Confirm your email address',
    $BODY$Confirm your email address

Follow the link below to confirm {{recipient_email}} and finish signing up.

{{action_url}}

If you didn't create an account, you can safely ignore this email.

-- {{site_url}}
$BODY$,
    $BODY$<h2>Confirm your email address</h2>

<p>Follow the link below to confirm <strong>{{recipient_email}}</strong> and finish signing up.</p>

<p><a href="{{action_url}}">Confirm email address</a></p>

<p>If you didn't create an account, you can safely ignore this email.</p>

<p><small><a href="{{site_url}}">{{site_url}}</a></small></p>
$BODY$
),
(
    'email_change',
    'Confirm your new email address',
    $BODY$Confirm your new email address

Follow the link below to confirm {{recipient_email}} as your new email address.

{{action_url}}

If you didn't request this change, you can safely ignore this email.
Your email address will not change until you follow the link above.

-- {{site_url}}
$BODY$,
    $BODY$<h2>Confirm your new email address</h2>

<p>Follow the link below to confirm <strong>{{recipient_email}}</strong> as your new email address.</p>

<p><a href="{{action_url}}">Confirm new email address</a></p>

<p>If you didn't request this change, you can safely ignore this email.
Your email address will not change until you follow the link above.</p>

<p><small><a href="{{site_url}}">{{site_url}}</a></small></p>
$BODY$
),
(
    'invite',
    'You''ve been invited',
    $BODY$You've been invited

You've been invited to create an account at {{site_url}}.
This invitation was sent to {{recipient_email}}.
Follow the link below to accept the invitation and set your password.

{{action_url}}

If you weren't expecting this invitation, you can safely ignore this email.
$BODY$,
    $BODY$<h2>You've been invited</h2>

<p>You've been invited to create an account at <a href="{{site_url}}">{{site_url}}</a>.
This invitation was sent to <strong>{{recipient_email}}</strong>.
Follow the link below to accept the invitation and set your password.</p>

<p><a href="{{action_url}}">Accept invitation</a></p>

<p>If you weren't expecting this invitation, you can safely ignore this email.</p>
$BODY$
),
(
    'recovery',
    'Reset your password',
    $BODY$Reset your password

We received a request to reset the password for {{recipient_email}}.
Follow the link below to choose a new password.

{{action_url}}

If you didn't request this, you can safely ignore this email.
Your password will not change until you follow the link above.

-- {{site_url}}
$BODY$,
    $BODY$<h2>Reset your password</h2>

<p>We received a request to reset the password for <strong>{{recipient_email}}</strong>.
Follow the link below to choose a new password.</p>

<p><a href="{{action_url}}">Reset password</a></p>

<p>If you didn't request this, you can safely ignore this email.
Your password will not change until you follow the link above.</p>

<p><small><a href="{{site_url}}">{{site_url}}</a></small></p>
$BODY$
);
