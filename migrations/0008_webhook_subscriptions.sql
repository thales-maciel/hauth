CREATE TABLE auth.webhook_subscriptions (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    url          text NOT NULL,
    secret       text NOT NULL,           -- plaintext; operators read it back from the admin UI
    events       text[] NOT NULL DEFAULT ARRAY[]::text[],  -- empty = subscribe to all events
    disabled_at  timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX webhook_subscriptions_enabled_idx
    ON auth.webhook_subscriptions (disabled_at)
    WHERE disabled_at IS NULL;
