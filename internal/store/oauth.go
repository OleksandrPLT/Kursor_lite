package store

import (
	"database/sql"
	"strings"
	"time"
)

// OAuthClient is a registered "project" allowed to use Kursor as its
// identity provider.
type OAuthClient struct {
	ID           string // client_id
	Name         string
	SecretHash   string // bcrypt; empty for public clients
	ClientType   string // "confidential" | "public" | "service"
	RedirectURIs string // newline-separated
	CreatedAt    time.Time
}

// RedirectURIList splits RedirectURIs into a slice, skipping blanks.
func (c OAuthClient) RedirectURIList() []string {
	var out []string
	for _, line := range strings.Split(c.RedirectURIs, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

// HasRedirectURI reports whether uri exactly matches one of the
// client's registered redirect URIs — exact match only, never a prefix
// match, which is how open-redirect bugs sneak into OAuth
// implementations.
func (c OAuthClient) HasRedirectURI(uri string) bool {
	for _, u := range c.RedirectURIList() {
		if u == uri {
			return true
		}
	}
	return false
}

// CreateOAuthClient inserts a new registered project.
func (s *Store) CreateOAuthClient(id, name, secretHash, clientType, redirectURIs string, createdBy int64) error {
	_, err := s.db.Exec(`INSERT INTO oauth_clients (id, name, secret_hash, client_type, redirect_uris, created_by, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		id, name, secretHash, clientType, redirectURIs, createdBy, time.Now().UTC().Format(time.RFC3339))
	return err
}

// GetOAuthClient returns nil, nil if no such client exists.
func (s *Store) GetOAuthClient(id string) (*OAuthClient, error) {
	var c OAuthClient
	var createdAt string
	err := s.db.QueryRow(`SELECT id, name, secret_hash, client_type, redirect_uris, created_at
		FROM oauth_clients WHERE id = ?`, id).
		Scan(&c.ID, &c.Name, &c.SecretHash, &c.ClientType, &c.RedirectURIs, &createdAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
		c.CreatedAt = t
	}
	return &c, nil
}

// ListOAuthClients returns every registered project, oldest first.
func (s *Store) ListOAuthClients() ([]OAuthClient, error) {
	rows, err := s.db.Query(`SELECT id, name, secret_hash, client_type, redirect_uris, created_at
		FROM oauth_clients ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []OAuthClient
	for rows.Next() {
		var c OAuthClient
		var createdAt string
		if err := rows.Scan(&c.ID, &c.Name, &c.SecretHash, &c.ClientType, &c.RedirectURIs, &createdAt); err != nil {
			return nil, err
		}
		if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
			c.CreatedAt = t
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// DeleteOAuthClient removes a registered project.
func (s *Store) DeleteOAuthClient(id string) error {
	_, err := s.db.Exec(`DELETE FROM oauth_clients WHERE id = ?`, id)
	return err
}

// OAuthCode is a one-time authorization code from the /oauth/authorize
// step, redeemed at /oauth/token.
type OAuthCode struct {
	Code                string
	ClientID            string
	UserID              int64
	RedirectURI         string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string
	ExpiresAt           time.Time
}

// CreateOAuthCode inserts a fresh authorization code, valid for ttl.
func (s *Store) CreateOAuthCode(c OAuthCode, ttl time.Duration) error {
	_, err := s.db.Exec(`INSERT INTO oauth_codes
		(code, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, nonce, expires_at, used)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`,
		c.Code, c.ClientID, c.UserID, c.RedirectURI, c.Scope, c.CodeChallenge, c.CodeChallengeMethod, c.Nonce,
		time.Now().UTC().Add(ttl).Format(time.RFC3339))
	return err
}

// ConsumeOAuthCode atomically marks a code used and returns it — a code
// that's already used, expired, or unknown returns nil, nil (the caller
// treats all three the same way: reject the token request). Marking
// used happens in the same statement as the read via UPDATE...RETURNING
// semantics emulated with a check-then-update in a transaction, so a
// code can never be redeemed twice even under a race.
func (s *Store) ConsumeOAuthCode(code string) (*OAuthCode, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var c OAuthCode
	var expiresAt string
	var used int
	err = tx.QueryRow(`SELECT code, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, nonce, expires_at, used
		FROM oauth_codes WHERE code = ?`, code).
		Scan(&c.Code, &c.ClientID, &c.UserID, &c.RedirectURI, &c.Scope, &c.CodeChallenge, &c.CodeChallengeMethod, &c.Nonce, &expiresAt, &used)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if used != 0 {
		return nil, nil
	}
	exp, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return nil, err
	}
	c.ExpiresAt = exp
	if time.Now().UTC().After(exp) {
		return nil, nil
	}

	if _, err := tx.Exec(`UPDATE oauth_codes SET used = 1 WHERE code = ?`, code); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return &c, nil
}
