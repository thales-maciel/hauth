-- auth.identities
--
-- OAuth / external-provider identity links for a user. Each row ties a
-- (provider, provider_id) pair to an auth.users row.

CREATE TABLE IF NOT EXISTS auth.identities (
    id           text        NOT NULL,
    provider     text        NOT NULL,
    provider_id  text        NOT NULL,
    user_id      uuid        NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
    identity_data jsonb      NOT NULL DEFAULT '{}',
    email        text        GENERATED ALWAYS AS (lower(identity_data ->> 'email')) STORED,
    last_sign_in_at timestamptz DEFAULT now(),
    created_at   timestamptz DEFAULT now(),
    updated_at   timestamptz DEFAULT now(),
    PRIMARY KEY (provider, provider_id)
);

-- Fast lookup of all identities for a user.
CREATE INDEX IF NOT EXISTS identities_user_id_idx
    ON auth.identities (user_id);

-- Lookup by email (generated from identity_data).
CREATE INDEX IF NOT EXISTS identities_email_idx
    ON auth.identities (email);
