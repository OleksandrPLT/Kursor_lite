-- Real DNS records managed via dnsmasq (internal/dns). One row per
-- record; kursor.conf is a generated view of these rows, same
-- "database is truth" discipline as cron jobs and VPN peers.

CREATE TABLE dns_records (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    type       TEXT NOT NULL, -- A | AAAA | CNAME | MX | TXT
    value      TEXT NOT NULL,
    priority   INTEGER NOT NULL DEFAULT 0, -- MX only
    created_at TEXT NOT NULL
);
