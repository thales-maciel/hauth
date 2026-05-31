CREATE TABLE IF NOT EXISTS auth.flow_state
    ( id uuid PRIMARY KEY DEFAULT gen_random_uuid()
    , user_id uuid REFERENCES auth.users (id) ON DELETE CASCADE
    , auth_code text NOT NULL
    , code_challenge_method text
    , code_challenge text
    , provider_type text NOT NULL
    , provider_access_token text
    , provider_refresh_token text
    , created_at timestamptz NOT NULL DEFAULT now()
    , updated_at timestamptz NOT NULL DEFAULT now()
    , authentication_method text NOT NULL
    , auth_code_issued_at timestamptz
    );

CREATE INDEX IF NOT EXISTS flow_state_created_at_idx ON auth.flow_state (created_at DESC);
CREATE INDEX IF NOT EXISTS flow_state_auth_code_idx ON auth.flow_state (auth_code);
