package store

import (
	"strings"
	"time"
)

// Domain is one entry in the company's domain registry — see migration
// 0016 for why this is separate from both Sites and DNS records.
// WHOISPrivacy/DNSSEC/ContactEmail/Tags (migration 0017) are
// informational tracking, same as Registrar/ExpiresAt/AutoRenew —
// Kursor has no registrar API to actually flip WHOIS privacy or DNSSEC
// on, so these just make what's already true at the registrar visible
// here too, instead of scattered in someone's notes.
type Domain struct {
	ID           int64
	Domain       string
	Registrar    string
	ExpiresAt    string // "YYYY-MM-DD", may be ""
	AutoRenew    bool
	Notes        string
	WHOISPrivacy bool
	DNSSEC       bool
	ContactEmail string
	Tags         string // comma-separated
	CreatedAt    time.Time
}

// TagsList splits the stored comma-separated tags, skipping empty entries.
func (d Domain) TagsList() []string {
	if d.Tags == "" {
		return nil
	}
	parts := strings.Split(d.Tags, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

const domainSelect = `SELECT id, domain, registrar, expires_at, auto_renew, notes, whois_privacy, dnssec, contact_email, tags, created_at FROM domains`

func scanDomain(row interface{ Scan(...any) error }) (Domain, error) {
	var d Domain
	var autoRenew, whoisPrivacy, dnssec int
	var createdAt string
	err := row.Scan(&d.ID, &d.Domain, &d.Registrar, &d.ExpiresAt, &autoRenew, &d.Notes, &whoisPrivacy, &dnssec, &d.ContactEmail, &d.Tags, &createdAt)
	if err != nil {
		return Domain{}, err
	}
	d.AutoRenew = autoRenew != 0
	d.WHOISPrivacy = whoisPrivacy != 0
	d.DNSSEC = dnssec != 0
	if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
		d.CreatedAt = t
	}
	return d, nil
}

func (s *Store) ListDomains() ([]Domain, error) {
	rows, err := s.db.Query(domainSelect + ` ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Domain
	for rows.Next() {
		d, err := scanDomain(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

type NewDomain struct {
	Domain       string
	Registrar    string
	ExpiresAt    string
	AutoRenew    bool
	Notes        string
	WHOISPrivacy bool
	DNSSEC       bool
	ContactEmail string
	Tags         string
}

func (s *Store) CreateDomain(d NewDomain) (int64, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.db.Exec(`INSERT INTO domains (domain, registrar, expires_at, auto_renew, notes, whois_privacy, dnssec, contact_email, tags, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.Domain, d.Registrar, d.ExpiresAt, boolToInt(d.AutoRenew), d.Notes,
		boolToInt(d.WHOISPrivacy), boolToInt(d.DNSSEC), d.ContactEmail, d.Tags, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// DomainUpdate carries every field UpdateDomain can change — a named
// struct rather than another long positional-bool parameter list like
// the original registrar/expiresAt/autoRenew/notes signature had.
type DomainUpdate struct {
	Registrar    string
	ExpiresAt    string
	AutoRenew    bool
	Notes        string
	WHOISPrivacy bool
	DNSSEC       bool
	ContactEmail string
	Tags         string
}

func (s *Store) UpdateDomain(id int64, u DomainUpdate) error {
	_, err := s.db.Exec(`UPDATE domains SET registrar = ?, expires_at = ?, auto_renew = ?, notes = ?,
		whois_privacy = ?, dnssec = ?, contact_email = ?, tags = ? WHERE id = ?`,
		u.Registrar, u.ExpiresAt, boolToInt(u.AutoRenew), u.Notes,
		boolToInt(u.WHOISPrivacy), boolToInt(u.DNSSEC), u.ContactEmail, u.Tags, id)
	return err
}

func (s *Store) DeleteDomain(id int64) error {
	_, err := s.db.Exec(`DELETE FROM domains WHERE id = ?`, id)
	return err
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
