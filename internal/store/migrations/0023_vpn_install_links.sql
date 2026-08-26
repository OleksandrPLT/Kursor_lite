-- Lets a peer's WireGuard config be installed via a shareable link
-- (scan a QR code or tap "download config") instead of only the
-- one-time reveal shown right after creation.

-- The peer's private key, encrypted at rest (AES-256-GCM, nonce
-- prepended to the ciphertext) with a server-only key file
-- (internal/vpn.LoadOrGenerateInstallKey) — never stored in plaintext.
-- NULL for peers created before this feature shipped; those have no
-- way to get an install link (the raw key was already discarded right
-- after its one-time reveal), only a freshly created peer can.
ALTER TABLE vpn_peers ADD COLUMN encrypted_private_key BLOB;

-- What the CLIENT routes through the tunnel (its own [Peer].AllowedIPs
-- line) — previously computed once at creation time and never stored,
-- so it couldn't be edited or re-rendered later for an install link.
-- Empty means "use the VPN subnet", the same default as before this
-- column existed.
ALTER TABLE vpn_peers ADD COLUMN client_allowed_ips TEXT NOT NULL DEFAULT '';

-- One active install link per peer — generating a new one replaces it
-- (delete+insert), revoking deletes it outright. Only the hash is
-- stored; the raw token lives only in the URL handed to whoever
-- installs it, same discipline as api_keys.key_hash.
CREATE TABLE vpn_install_links (
    peer_id    INTEGER PRIMARY KEY,
    token_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);
