package store

import "time"

// AuditEntry is one logged state-changing request.
type AuditEntry struct {
	ID        int64
	UserID    int64
	Username  string
	Method    string
	Path      string
	Status    int
	IP        string
	CreatedAt time.Time
}

func (s *Store) CreateAuditEntry(userID int64, username, method, path string, status int, ip string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(`INSERT INTO audit_log (user_id, username, method, path, status, ip, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, userID, username, method, path, status, ip, now)
	return err
}

// ListAuditLog returns the most recent entries (newest first), limited
// to limit rows, optionally filtered by a case-insensitive substring
// match against username or path.
func (s *Store) ListAuditLog(q string, limit int) ([]AuditEntry, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	var rows interface {
		Close() error
		Next() bool
		Scan(...any) error
		Err() error
	}
	var err error
	if q == "" {
		rows, err = s.db.Query(`SELECT id, user_id, username, method, path, status, ip, created_at
			FROM audit_log ORDER BY created_at DESC LIMIT ?`, limit)
	} else {
		like := "%" + q + "%"
		rows, err = s.db.Query(`SELECT id, user_id, username, method, path, status, ip, created_at
			FROM audit_log WHERE username LIKE ? OR path LIKE ? ORDER BY created_at DESC LIMIT ?`, like, like, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var createdAt string
		if err := rows.Scan(&e.ID, &e.UserID, &e.Username, &e.Method, &e.Path, &e.Status, &e.IP, &createdAt); err != nil {
			return nil, err
		}
		if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
			e.CreatedAt = t
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
