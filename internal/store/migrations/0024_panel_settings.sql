-- Panel-level settings: the panel's own access domain (bound via an
-- Nginx reverse proxy + real Let's Encrypt cert — see internal/sites/
-- panel_proxy.go), and an optional IP allow-list restricting who can
-- even reach the login page.
CREATE TABLE panel_settings (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    domain          TEXT NOT NULL DEFAULT '',
    contact_email   TEXT NOT NULL DEFAULT '',
    proxy_conf_path TEXT NOT NULL DEFAULT '',
    ssl_enabled     INTEGER NOT NULL DEFAULT 0,
    allowed_ips     TEXT NOT NULL DEFAULT ''
);
INSERT OR IGNORE INTO panel_settings (id) VALUES (1);

-- Brute-force protection on login, keyed by username (not IP — a
-- shared/NAT'd IP shouldn't lock out everyone behind it, and the whole
-- point is protecting one account from being guessed at, regardless of
-- where the guesses come from). See internal/store/loginlockout.go.
CREATE TABLE login_lockouts (
    username     TEXT PRIMARY KEY,
    fail_count   INTEGER NOT NULL DEFAULT 0,
    last_fail_at TEXT NOT NULL DEFAULT '',
    locked_until TEXT NOT NULL DEFAULT ''
);
