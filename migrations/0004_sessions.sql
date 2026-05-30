-- auth.sessions
--
-- Active authentication sessions. Each session is linked to a user and
-- carries AAL level and optional MFA factor reference.

CREATE TABLE IF NOT EXISTS auth.sessions (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       uuid        NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
    created_at    timestamptz DEFAULT now(),
    updated_at    timestamptz DEFAULT now(),
    factor_id     uuid,
    aal           text,
    not_after     timestamptz,
    refreshed_at  timestamptz,
    user_agent    text,
    ip            inet,
    tag           text
);

-- Fast lookup of sessions for a user.
CREATE INDEX IF NOT EXISTS sessions_user_id_idx
    ON auth.sessions (user_id);

-- Fast expiry sweeps.
CREATE INDEX IF NOT EXISTS sessions_not_after_idx
    ON auth.sessions (not_after DESC)
    WHERE not_after IS NOT NULL;
