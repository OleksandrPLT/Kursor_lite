-- API keys for machine-to-machine integrations (internal/server's
-- /api/v1/* routes) — separate from OAuth2/OIDC (company/sso), which is
-- for a *person* signing into an external app as themselves. An API key
-- is for a script/webhook/external platform acting on its own, with no
-- human present to click through a consent screen.

CREATE TABLE api_keys (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    key_hash      TEXT NOT NULL UNIQUE, -- sha256, hex-encoded
    key_prefix    TEXT NOT NULL,        -- first 8 chars of the real key, shown in the list so an operator can tell keys apart without ever re-seeing the full value
    created_by    INTEGER NOT NULL REFERENCES users(id),
    created_at    TEXT NOT NULL,
    last_used_at  TEXT NOT NULL DEFAULT '',
    revoked_at    TEXT NOT NULL DEFAULT ''
);
