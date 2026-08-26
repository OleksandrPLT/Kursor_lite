-- Kursor's own metadata store. Kept deliberately small for the MVP —
-- see the build plan for what each table is for.

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token         TEXT PRIMARY KEY,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at    TEXT NOT NULL,
    expires_at    TEXT NOT NULL,
    last_seen_at  TEXT NOT NULL,
    user_agent    TEXT,
    ip            TEXT
);

CREATE TABLE IF NOT EXISTS sites (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    domain       TEXT NOT NULL UNIQUE,
    docroot      TEXT NOT NULL,
    php_enabled  INTEGER NOT NULL DEFAULT 0,
    status       TEXT NOT NULL DEFAULT 'enabled',
    conf_path    TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS db_connections (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    engine      TEXT NOT NULL,
    host        TEXT NOT NULL DEFAULT 'localhost',
    port        INTEGER,
    socket_path TEXT,
    username    TEXT,
    secret      TEXT,
    created_at  TEXT NOT NULL
);
