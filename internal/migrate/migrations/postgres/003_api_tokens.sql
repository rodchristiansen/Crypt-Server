CREATE TABLE IF NOT EXISTS api_tokens (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    prefix TEXT NOT NULL UNIQUE,
    token_hash TEXT NOT NULL,
    kind TEXT NOT NULL,
    scopes TEXT NOT NULL DEFAULT '',
    username TEXT NULL,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NULL,
    last_used_at TIMESTAMPTZ NULL,
    last_used_ip TEXT NULL,
    revoked_at TIMESTAMPTZ NULL
);

CREATE INDEX IF NOT EXISTS idx_api_tokens_prefix ON api_tokens (prefix);
