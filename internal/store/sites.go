package store

import (
	"database/sql"
	"time"
)

// Site is a managed Nginx-backed site. A DB row only exists once Nginx
// has actually accepted the generated config — see internal/sites for
// the render -> validate -> reload sequence that guards that.
type Site struct {
	ID         int64
	Domain     string
	Docroot    string
	PHPEnabled bool
	Status     string // "enabled" | "disabled"
	ConfPath   string
	CreatedAt  time.Time
}

// ListSites returns every site, oldest first.
func (s *Store) ListSites() ([]Site, error) {
	rows, err := s.db.Query(`SELECT id, domain, docroot, php_enabled, status, conf_path, created_at
		FROM sites ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Site
	for rows.Next() {
		site, err := scanSite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *site)
	}
	return out, rows.Err()
}

func scanSite(row interface{ Scan(...any) error }) (*Site, error) {
	var site Site
	var phpEnabled int
	var createdAt string
	if err := row.Scan(&site.ID, &site.Domain, &site.Docroot, &phpEnabled, &site.Status, &site.ConfPath, &createdAt); err != nil {
		return nil, err
	}
	site.PHPEnabled = phpEnabled != 0
	if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
		site.CreatedAt = t
	}
	return &site, nil
}

// GetSiteByDomain returns nil, nil if no such site exists.
func (s *Store) GetSiteByDomain(domain string) (*Site, error) {
	row := s.db.QueryRow(`SELECT id, domain, docroot, php_enabled, status, conf_path, created_at
		FROM sites WHERE domain = ?`, domain)
	site, err := scanSite(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return site, err
}

// GetSiteByID returns nil, nil if no such site exists.
func (s *Store) GetSiteByID(id int64) (*Site, error) {
	row := s.db.QueryRow(`SELECT id, domain, docroot, php_enabled, status, conf_path, created_at
		FROM sites WHERE id = ?`, id)
	site, err := scanSite(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return site, err
}

// CreateSite inserts a site row. Callers must only call this AFTER
// Nginx has accepted the generated config (see internal/sites) — the DB
// should never claim a site exists if Nginx doesn't actually serve it.
func (s *Store) CreateSite(domain, docroot, confPath string) (int64, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.db.Exec(`INSERT INTO sites (domain, docroot, php_enabled, status, conf_path, created_at, updated_at)
		VALUES (?, ?, 0, 'enabled', ?, ?, ?)`,
		domain, docroot, confPath, now, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// SetSiteStatus updates a site's enabled/disabled status.
func (s *Store) SetSiteStatus(id int64, status string) error {
	_, err := s.db.Exec(`UPDATE sites SET status = ?, updated_at = ? WHERE id = ?`,
		status, time.Now().UTC().Format(time.RFC3339), id)
	return err
}

// DeleteSite removes a site row.
func (s *Store) DeleteSite(id int64) error {
	_, err := s.db.Exec(`DELETE FROM sites WHERE id = ?`, id)
	return err
}
