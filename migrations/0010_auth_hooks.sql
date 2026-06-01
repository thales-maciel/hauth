-- auth.hooks
--
-- Synchronous HTTP callouts that block the corresponding auth handler. Each
-- hook_point can have at most one active configuration (UNIQUE constraint).
-- Operators toggle hooks via enabled; next request honours the change.

CREATE TABLE auth.hooks (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    hook_point      text NOT NULL UNIQUE,           -- only one config per hook point
    url             text NOT NULL,
    secret          text NOT NULL,                  -- plaintext; reuses Standard Webhooks signing
    timeout_ms      int NOT NULL DEFAULT 2000,      -- max 3000 enforced at write time
    fail_open       boolean NOT NULL DEFAULT false, -- false = reject on hook unreachable
    enabled         boolean NOT NULL DEFAULT true,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CHECK (timeout_ms BETWEEN 100 AND 3000),
    CHECK (hook_point IN ('before-user-created', 'custom-access-token',
                          'mfa-verification-attempt', 'password-verification-attempt'))
);
