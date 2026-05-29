-- auth.users
--
-- Core user table. Supabase Auth (GoTrue) compatible shape for v0.1.
-- Supports email/password signup, OAuth, TOTP MFA, and sessions.

CREATE TABLE IF NOT EXISTS auth.users (
    id                       uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    instance_id              uuid,
    aud                      text,
    role                     text,
    email                    text,
    encrypted_password       text,
    email_confirmed_at       timestamptz,
    invited_at               timestamptz,
    confirmation_token       text,
    confirmation_sent_at     timestamptz,
    recovery_token           text,
    recovery_sent_at         timestamptz,
    email_change_token_new   text,
    email_change             text,
    email_change_sent_at     timestamptz,
    email_change_token_current text,
    email_change_confirm_status smallint DEFAULT 0,
    last_sign_in_at          timestamptz,
    raw_app_meta_data        jsonb,
    raw_user_meta_data       jsonb,
    is_super_admin           boolean,
    phone                    text,
    phone_confirmed_at       timestamptz,
    phone_change             text DEFAULT '',
    phone_change_token       text DEFAULT '',
    phone_change_sent_at     timestamptz,
    banned_until             timestamptz,
    reauthentication_token   text DEFAULT '',
    reauthentication_sent_at timestamptz,
    is_sso_user              boolean NOT NULL DEFAULT false,
    is_anonymous             boolean NOT NULL DEFAULT false,
    deleted_at               timestamptz,
    created_at               timestamptz DEFAULT now(),
    updated_at               timestamptz DEFAULT now()
);

-- Unique email per live (non-deleted) user, matching Supabase behaviour.
CREATE UNIQUE INDEX IF NOT EXISTS users_email_partial_key
    ON auth.users (email)
    WHERE deleted_at IS NULL;

-- Fast lookup by instance (multi-tenancy scaffold; single instance in v0.1).
CREATE INDEX IF NOT EXISTS users_instance_id_idx
    ON auth.users (instance_id);

-- Fast lookup of email column for login.
CREATE INDEX IF NOT EXISTS users_email_idx
    ON auth.users (email);
