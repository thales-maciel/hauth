-- auth.refresh_tokens
--
-- Opaque refresh tokens used for session rotation. Matches the Supabase
-- (GoTrue) schema: bigserial PK, text token, user_id stored as text,
-- parent chain for rotation audit, and session FK for direct session lookup.

CREATE TABLE IF NOT EXISTS auth.refresh_tokens (
    id         bigserial   PRIMARY KEY,
    token      text        UNIQUE NOT NULL,
    user_id    text,
    parent     text,
    session_id uuid        REFERENCES auth.sessions (id) ON DELETE CASCADE,
    revoked    boolean     DEFAULT false,
    created_at timestamptz DEFAULT now(),
    updated_at timestamptz DEFAULT now()
);

-- Fast token lookup (used on every refresh).
CREATE INDEX IF NOT EXISTS refresh_tokens_token_idx
    ON auth.refresh_tokens (token);

-- Fast lookup of all tokens for a session (used on revocation).
CREATE INDEX IF NOT EXISTS refresh_tokens_session_id_idx
    ON auth.refresh_tokens (session_id);

-- Fast lookup of all tokens for a user (used on global sign-out).
CREATE INDEX IF NOT EXISTS refresh_tokens_user_id_idx
    ON auth.refresh_tokens (user_id);
