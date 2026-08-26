-- Domains: a registry of every domain the company owns/manages, tracked
-- independently of Sites (a domain can exist here before any vhost is
-- created for it — exactly the "just bought it, pointing it here today"
-- moment) and of DNS records (a domain can be delegated to an external
-- DNS provider entirely). Registrar/expiry/auto-renew are informational
-- only — Kursor has no registrar API integration, so these are exactly
-- what the operator types in, tracked here so it's visible next to the
-- domain instead of scattered in someone's notes.

CREATE TABLE domains (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    domain     TEXT NOT NULL UNIQUE,
    registrar  TEXT NOT NULL DEFAULT '',
    expires_at TEXT NOT NULL DEFAULT '', -- "YYYY-MM-DD", may be ''
    auto_renew INTEGER NOT NULL DEFAULT 0,
    notes      TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
