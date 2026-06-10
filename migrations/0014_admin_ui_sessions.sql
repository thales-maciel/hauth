-- auth.admin_ui_sessions
--
-- Browser sessions for the operator-facing admin UI. Deliberately distinct
-- from auth.sessions: not linked to auth.users, not JWT-backed, short-lived.
-- The cookie token is stored only as a SHA-256 hex digest.

CREATE TABLE IF NOT EXISTS auth.admin_ui_sessions (
    token_hash  text        PRIMARY KEY,
    username    text        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL
);

-- Fast expiry sweeps.
CREATE INDEX IF NOT EXISTS admin_ui_sessions_expires_at_idx
    ON auth.admin_ui_sessions (expires_at);
