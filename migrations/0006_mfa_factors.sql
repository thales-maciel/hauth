-- auth.mfa_factors
--
-- TOTP (and future) MFA factors enrolled by a user. In v0.1 only TOTP is
-- supported. Status values: 'unverified' (enrolled but not yet confirmed),
-- 'verified' (active factor).

CREATE TABLE IF NOT EXISTS auth.mfa_factors (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       uuid        NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
    friendly_name text,
    factor_type   text        NOT NULL,
    status        text        NOT NULL,
    secret        text,
    created_at    timestamptz DEFAULT now(),
    updated_at    timestamptz DEFAULT now()
);

-- Fast lookup of factors for a user.
CREATE INDEX IF NOT EXISTS mfa_factors_user_id_idx
    ON auth.mfa_factors (user_id);
