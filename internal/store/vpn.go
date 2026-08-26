package store

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// VPNPeer is one device/person allowed to connect to the box's
// WireGuard VPN. The OS-level wg0.conf is a generated view of the
// enabled rows here — see internal/vpn.Apply, same "database is truth,
// the system file is a view" discipline as internal/cron.Sync.
type VPNPeer struct {
	ID        int64
	Name      string
	UserID    *int64
	UserName  string // joined from users, "" if unassigned or the user was deleted
	PublicKey string
	AllowedIP string
	Enabled   bool
	CreatedAt time.Time
	RevokedAt *time.Time

	// EncryptedPrivateKey is this peer's WireGuard private key,
	// AES-256-GCM–encrypted with this host's install key (see
	// internal/vpn.LoadOrGenerateInstallKey) — nil for a peer created
	// before install links existed, which has no way to get one (its
	// raw key was already discarded after its one-time reveal).
	EncryptedPrivateKey []byte
	// ClientAllowedIPs is what the peer's own client config routes
	// through the tunnel (its [Peer].AllowedIPs line) — "" means "use
	// the VPN subnet", the long-standing default.
	ClientAllowedIPs string
}

// VPNSettings is the single-row (id=1) server-facing configuration a
// peer's client config is rendered from.
type VPNSettings struct {
	Endpoint      string
	Port          int
	ServerAddress string
}

func (s *Store) GetVPNSettings() (VPNSettings, error) {
	var st VPNSettings
	err := s.db.QueryRow(`SELECT endpoint, port, server_address FROM vpn_settings WHERE id = 1`).
		Scan(&st.Endpoint, &st.Port, &st.ServerAddress)
	return st, err
}

func (s *Store) UpdateVPNSettings(endpoint string, port int) error {
	_, err := s.db.Exec(`UPDATE vpn_settings SET endpoint = ?, port = ? WHERE id = 1`, endpoint, port)
	return err
}

const vpnPeerSelect = `SELECT p.id, p.name, p.user_id, COALESCE(u.username, ''), p.public_key, p.allowed_ip, p.enabled, p.created_at, p.revoked_at, p.encrypted_private_key, p.client_allowed_ips
	FROM vpn_peers p LEFT JOIN users u ON u.id = p.user_id`

func scanVPNPeer(row interface{ Scan(...any) error }) (VPNPeer, error) {
	var p VPNPeer
	var userID sql.NullInt64
	var enabled int
	var createdAt, revokedAt string
	var encryptedPrivateKey []byte
	if err := row.Scan(&p.ID, &p.Name, &userID, &p.UserName, &p.PublicKey, &p.AllowedIP, &enabled, &createdAt, &revokedAt, &encryptedPrivateKey, &p.ClientAllowedIPs); err != nil {
		return VPNPeer{}, err
	}
	p.EncryptedPrivateKey = encryptedPrivateKey
	if userID.Valid {
		id := userID.Int64
		p.UserID = &id
	}
	p.Enabled = enabled != 0
	if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
		p.CreatedAt = t
	}
	if revokedAt != "" {
		if t, err := time.Parse(time.RFC3339, revokedAt); err == nil {
			p.RevokedAt = &t
		}
	}
	return p, nil
}

// ListVPNPeers returns every peer, oldest first.
func (s *Store) ListVPNPeers() ([]VPNPeer, error) {
	rows, err := s.db.Query(vpnPeerSelect + ` ORDER BY p.created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []VPNPeer
	for rows.Next() {
		p, err := scanVPNPeer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) GetVPNPeer(id int64) (*VPNPeer, error) {
	p, err := scanVPNPeer(s.db.QueryRow(vpnPeerSelect+` WHERE p.id = ?`, id))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &p, nil
}

// NextVPNIP picks the smallest free host address in the VPN subnet
// (.2 upward — .1 is the server's own address, set aside in
// vpn_settings.server_address), so peers get short, predictable IPs
// instead of an ever-growing counter that never reclaims a revoked
// peer's slot.
func (s *Store) NextVPNIP(subnetPrefix string) (string, error) {
	rows, err := s.db.Query(`SELECT allowed_ip FROM vpn_peers`)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	used := map[int]bool{}
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return "", err
		}
		host := strings.TrimPrefix(ip, subnetPrefix)
		host = strings.TrimSuffix(host, "/32")
		if n, err := strconv.Atoi(host); err == nil {
			used[n] = true
		}
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	for n := 2; n < 255; n++ {
		if !used[n] {
			return fmt.Sprintf("%s%d/32", subnetPrefix, n), nil
		}
	}
	return "", fmt.Errorf("no free address left in %s0/24", subnetPrefix)
}

// CreateVPNPeer records a new peer. The caller (server/vpn.go) has
// already generated the keypair and picked the IP — this is pure
// storage, same split as everywhere else in this file.
// encryptedPrivateKey may be nil (a peer opted out of install links
// would have no reason to, but the column allows it); clientAllowedIPs
// "" means "use the VPN subnet" at render time.
func (s *Store) CreateVPNPeer(name string, userID *int64, publicKey, allowedIP string, encryptedPrivateKey []byte, clientAllowedIPs string) (int64, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.db.Exec(`INSERT INTO vpn_peers (name, user_id, public_key, allowed_ip, enabled, created_at, revoked_at, encrypted_private_key, client_allowed_ips)
		VALUES (?, ?, ?, ?, 1, ?, '', ?, ?)`, name, userID, publicKey, allowedIP, now, encryptedPrivateKey, clientAllowedIPs)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateVPNPeer edits a peer's name, assigned user, and client-side
// routes — deliberately never its address, public key, or encrypted
// private key: those are the actual cryptographic identity wg0.conf
// already has running, and this is "edit the paperwork," not "reissue
// a new peer."
func (s *Store) UpdateVPNPeer(id int64, name string, userID *int64, clientAllowedIPs string) error {
	_, err := s.db.Exec(`UPDATE vpn_peers SET name = ?, user_id = ?, client_allowed_ips = ? WHERE id = ?`, name, userID, clientAllowedIPs, id)
	return err
}

// SetVPNPeerEnabled toggles a peer without deleting it — same
// reversible-disable pattern as cron jobs.
func (s *Store) SetVPNPeerEnabled(id int64, enabled bool) error {
	e := 0
	if enabled {
		e = 1
	}
	_, err := s.db.Exec(`UPDATE vpn_peers SET enabled = ? WHERE id = ?`, e, id)
	return err
}

// DeleteVPNPeer permanently removes a peer (its slot's IP can be
// reused by NextVPNIP afterward).
func (s *Store) DeleteVPNPeer(id int64) error {
	_, err := s.db.Exec(`DELETE FROM vpn_peers WHERE id = ?`, id)
	return err
}

// ---------- install links ----------
//
// A VPN install link is a bearer token that, while it hasn't expired,
// lets anyone holding it fetch one peer's client config (see
// internal/server's /vpn/install/{token} route) — the whole point of
// the feature is a link an admin can hand to someone else, so it's
// deliberately not tied to a Kursor session. Only the token's hash is
// ever stored, same discipline as api_keys.key_hash.

func generateVPNInstallToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func hashVPNInstallToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// CreateVPNInstallLink mints a fresh token for peerID, replacing
// whatever link that peer already had (at most one active link per
// peer — regenerating is how you invalidate a link someone shouldn't
// use anymore without a separate "revoke" step).
func (s *Store) CreateVPNInstallLink(peerID int64, ttl time.Duration) (token string, expiresAt time.Time, err error) {
	token, err = generateVPNInstallToken()
	if err != nil {
		return "", time.Time{}, err
	}
	now := time.Now().UTC()
	expiresAt = now.Add(ttl)
	if _, err = s.db.Exec(`DELETE FROM vpn_install_links WHERE peer_id = ?`, peerID); err != nil {
		return "", time.Time{}, err
	}
	if _, err = s.db.Exec(`INSERT INTO vpn_install_links (peer_id, token_hash, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		peerID, hashVPNInstallToken(token), now.Format(time.RFC3339), expiresAt.Format(time.RFC3339)); err != nil {
		return "", time.Time{}, err
	}
	return token, expiresAt, nil
}

// RevokeVPNInstallLink deletes peerID's active link, if any — after
// this, its old token 404s immediately rather than waiting out its
// expiry.
func (s *Store) RevokeVPNInstallLink(peerID int64) error {
	_, err := s.db.Exec(`DELETE FROM vpn_install_links WHERE peer_id = ?`, peerID)
	return err
}

// GetVPNInstallLinkExpiry reports when peerID's current link expires,
// nil if it has none — used by the peers list to show "link active
// until ..." without exposing the token itself.
func (s *Store) GetVPNInstallLinkExpiry(peerID int64) (*time.Time, error) {
	var expiresAt string
	err := s.db.QueryRow(`SELECT expires_at FROM vpn_install_links WHERE peer_id = ?`, peerID).Scan(&expiresAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	t, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// ResolveVPNInstallToken looks up which peer a presented token belongs
// to. found=false covers both "no such token" and "hash mismatch" —
// the caller (server/vpn_install.go) treats an unknown and an expired
// token differently, so expiry is returned rather than checked here.
func (s *Store) ResolveVPNInstallToken(token string) (peerID int64, expiresAt time.Time, found bool, err error) {
	var expiresAtStr string
	row := s.db.QueryRow(`SELECT peer_id, expires_at FROM vpn_install_links WHERE token_hash = ?`, hashVPNInstallToken(token))
	if err = row.Scan(&peerID, &expiresAtStr); err == sql.ErrNoRows {
		return 0, time.Time{}, false, nil
	}
	if err != nil {
		return 0, time.Time{}, false, err
	}
	expiresAt, _ = time.Parse(time.RFC3339, expiresAtStr)
	return peerID, expiresAt, true, nil
}
