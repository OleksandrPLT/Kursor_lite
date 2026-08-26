-- Real WireGuard VPN peer management (internal/vpn). One row per
-- device/person allowed to connect; the server's own keypair lives on
-- disk (internal/vpn.LoadOrGenerateServerKey), not in this table.

CREATE TABLE vpn_peers (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    user_id     INTEGER REFERENCES users(id) ON DELETE SET NULL,
    public_key  TEXT NOT NULL UNIQUE,
    allowed_ip  TEXT NOT NULL UNIQUE, -- e.g. "10.8.0.2/32"
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT NOT NULL,
    revoked_at  TEXT NOT NULL DEFAULT ''
);

-- Single-row settings: the box's public endpoint, since a peer's client
-- config needs a real host:port to dial and the panel has no other way
-- to know its own public-facing address.
CREATE TABLE vpn_settings (
    id             INTEGER PRIMARY KEY CHECK (id = 1),
    endpoint       TEXT NOT NULL DEFAULT '',
    port           INTEGER NOT NULL DEFAULT 51820,
    server_address TEXT NOT NULL DEFAULT '10.8.0.1/24'
);
INSERT OR IGNORE INTO vpn_settings (id) VALUES (1);
