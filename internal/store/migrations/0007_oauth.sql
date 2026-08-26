-- OAuth2/OIDC provider tables: registered "projects" (clients) and the
-- short-lived authorization codes issued during the login flow. Access
-- and ID tokens are stateless signed JWTs (see internal/oidc) — nothing
-- to store for those; only the one-time auth code needs a DB row.

CREATE TABLE IF NOT EXISTS oauth_clients (
    id                TEXT PRIMARY KEY,   -- client_id, random
    name              TEXT NOT NULL,
    secret_hash       TEXT NOT NULL DEFAULT '',  -- bcrypt; empty for public (PKCE-only) clients
    client_type       TEXT NOT NULL,      -- 'confidential' | 'public' | 'service'
    redirect_uris     TEXT NOT NULL DEFAULT '',  -- newline-separated, exact-match only
    created_by        INTEGER,
    created_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_codes (
    code                  TEXT PRIMARY KEY,
    client_id             TEXT NOT NULL,
    user_id               INTEGER NOT NULL,
    redirect_uri          TEXT NOT NULL,
    scope                 TEXT NOT NULL DEFAULT '',
    code_challenge        TEXT NOT NULL DEFAULT '',
    code_challenge_method TEXT NOT NULL DEFAULT '',
    nonce                 TEXT NOT NULL DEFAULT '',
    expires_at            TEXT NOT NULL,
    used                  INTEGER NOT NULL DEFAULT 0
);
