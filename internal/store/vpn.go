package store

import (
	"database/sql"
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

const vpnPeerSelect = `SELECT p.id, p.name, p.user_id, COALESCE(u.username, ''), p.public_key, p.allowed_ip, p.enabled, p.created_at, p.revoked_at
	FROM vpn_peers p LEFT JOIN users u ON u.id = p.user_id`

func scanVPNPeer(row interface{ Scan(...any) error }) (VPNPeer, error) {
	var p VPNPeer
	var userID sql.NullInt64
	var enabled int
	var createdAt, revokedAt string
	if err := row.Scan(&p.ID, &p.Name, &userID, &p.UserName, &p.PublicKey, &p.AllowedIP, &enabled, &createdAt, &revokedAt); err != nil {
		return VPNPeer{}, err
	}
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
func (s *Store) CreateVPNPeer(name string, userID *int64, publicKey, allowedIP string) (int64, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.db.Exec(`INSERT INTO vpn_peers (name, user_id, public_key, allowed_ip, enabled, created_at, revoked_at)
		VALUES (?, ?, ?, ?, 1, ?, '')`, name, userID, publicKey, allowedIP, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
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
