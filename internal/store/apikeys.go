package store

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"time"
)

// APIKey is a machine-to-machine credential for Kursor's /api/v1/*
// integration endpoints — see internal/server/integrations.go. The raw
// key is only ever known at creation time (shown once, never stored);
// everything here is derived from it.
type APIKey struct {
	ID          int64
	Name        string
	KeyPrefix   string
	CreatedByID int64
	CreatedBy   string
	CreatedAt   time.Time
	LastUsedAt  *time.Time
	RevokedAt   *time.Time
}

// GenerateAPIKeyToken returns a fresh random token, "kur_" + 32 random
// bytes base64url-encoded — prefixed so a leaked key is recognizable in
// a log or a git-secrets scan for what it is at a glance.
func GenerateAPIKeyToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "kur_" + base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func hashAPIKeyToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// CreateAPIKey stores the hash of a freshly generated token and returns
// both the new row's ID and the one-time-visible raw token.
func (s *Store) CreateAPIKey(name string, createdBy int64) (id int64, token string, err error) {
	token, err = GenerateAPIKeyToken()
	if err != nil {
		return 0, "", err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	prefix := token
	if len(prefix) > 12 {
		prefix = prefix[:12]
	}
	res, err := s.db.Exec(`INSERT INTO api_keys (name, key_hash, key_prefix, created_by, created_at, last_used_at, revoked_at)
		VALUES (?, ?, ?, ?, ?, '', '')`, name, hashAPIKeyToken(token), prefix, createdBy, now)
	if err != nil {
		return 0, "", err
	}
	id, err = res.LastInsertId()
	return id, token, err
}

// ListAPIKeys returns every key (including revoked ones, shown
// struck-through in the UI), newest first.
func (s *Store) ListAPIKeys() ([]APIKey, error) {
	rows, err := s.db.Query(`SELECT k.id, k.name, k.key_prefix, k.created_by, u.username, k.created_at, k.last_used_at, k.revoked_at
		FROM api_keys k JOIN users u ON u.id = k.created_by ORDER BY k.created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []APIKey
	for rows.Next() {
		var k APIKey
		var createdAt, lastUsedAt, revokedAt string
		if err := rows.Scan(&k.ID, &k.Name, &k.KeyPrefix, &k.CreatedByID, &k.CreatedBy, &createdAt, &lastUsedAt, &revokedAt); err != nil {
			return nil, err
		}
		if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
			k.CreatedAt = t
		}
		if lastUsedAt != "" {
			if t, err := time.Parse(time.RFC3339, lastUsedAt); err == nil {
				k.LastUsedAt = &t
			}
		}
		if revokedAt != "" {
			if t, err := time.Parse(time.RFC3339, revokedAt); err == nil {
				k.RevokedAt = &t
			}
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *Store) RevokeAPIKey(id int64) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(`UPDATE api_keys SET revoked_at = ? WHERE id = ?`, now, id)
	return err
}

// ValidateAPIKey looks up a presented token by its hash (an equality
// lookup, not a loop with subtle.ConstantTimeCompare per row — the hash
// itself is the lookup key, so there's no per-row secret comparison to
// time; subtle.ConstantTimeCompare below only guards the final
// stored-vs-computed hash comparison against a timing side-channel on
// the hash value itself) and reports it if found, active, and not
// revoked. On success, stamps last_used_at — best-effort, errors here
// never fail the caller's actual request.
func (s *Store) ValidateAPIKey(token string) (*APIKey, error) {
	hash := hashAPIKeyToken(token)
	row := s.db.QueryRow(`SELECT k.id, k.name, k.key_prefix, k.created_by, u.username, k.created_at, k.last_used_at, k.revoked_at, k.key_hash
		FROM api_keys k JOIN users u ON u.id = k.created_by WHERE k.key_hash = ?`, hash)

	var k APIKey
	var createdAt, lastUsedAt, revokedAt, storedHash string
	if err := row.Scan(&k.ID, &k.Name, &k.KeyPrefix, &k.CreatedByID, &k.CreatedBy, &createdAt, &lastUsedAt, &revokedAt, &storedHash); err != nil {
		return nil, nil // not found, or any scan error — treated the same as "no such key" by the caller
	}
	if subtle.ConstantTimeCompare([]byte(hash), []byte(storedHash)) != 1 {
		return nil, nil
	}
	if revokedAt != "" {
		return nil, nil
	}
	if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
		k.CreatedAt = t
	}
	_, _ = s.db.Exec(`UPDATE api_keys SET last_used_at = ? WHERE id = ?`, time.Now().UTC().Format(time.RFC3339), k.ID)
	return &k, nil
}
