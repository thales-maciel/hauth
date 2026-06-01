CREATE TABLE auth.webhook_deliveries (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    subscription_id   uuid NOT NULL REFERENCES auth.webhook_subscriptions(id) ON DELETE CASCADE,
    event_type        text NOT NULL,                        -- e.g. "user.signed_up"
    payload           jsonb NOT NULL,
    status            text NOT NULL DEFAULT 'pending',      -- pending | sent | failed | exhausted
    attempts          int NOT NULL DEFAULT 0,
    next_attempt_at   timestamptz NOT NULL DEFAULT now(),
    response_status   int,                                  -- last HTTP status; null until first attempt
    response_body     text,                                 -- truncated to first 2KB
    last_error        text,                                 -- network error message; null on HTTP success
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX webhook_deliveries_worker_idx
    ON auth.webhook_deliveries (status, next_attempt_at)
    WHERE status = 'pending';

CREATE INDEX webhook_deliveries_subscription_idx
    ON auth.webhook_deliveries (subscription_id, created_at DESC);
