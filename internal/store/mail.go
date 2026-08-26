package store

import "time"

// MailDomain is one domain Postfix accepts virtual mail for.
type MailDomain struct {
	ID        int64
	Domain    string
	CreatedAt time.Time
}

// MailMailbox is one virtual mailbox. PasswordHash is the Dovecot-format
// crypt string from internal/mail.HashPassword — never the plaintext.
type MailMailbox struct {
	ID           int64
	Address      string
	PasswordHash string
	CreatedAt    time.Time
}

func (s *Store) ListMailDomains() ([]MailDomain, error) {
	rows, err := s.db.Query(`SELECT id, domain, created_at FROM mail_domains ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MailDomain
	for rows.Next() {
		var d MailDomain
		var createdAt string
		if err := rows.Scan(&d.ID, &d.Domain, &createdAt); err != nil {
			return nil, err
		}
		if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
			d.CreatedAt = t
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Store) CreateMailDomain(domain string) (int64, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.db.Exec(`INSERT INTO mail_domains (domain, created_at) VALUES (?, ?)`, domain, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) DeleteMailDomain(id int64) error {
	_, err := s.db.Exec(`DELETE FROM mail_domains WHERE id = ?`, id)
	return err
}

func (s *Store) ListMailboxes() ([]MailMailbox, error) {
	rows, err := s.db.Query(`SELECT id, address, password_hash, created_at FROM mail_mailboxes ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MailMailbox
	for rows.Next() {
		var m MailMailbox
		var createdAt string
		if err := rows.Scan(&m.ID, &m.Address, &m.PasswordHash, &createdAt); err != nil {
			return nil, err
		}
		if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
			m.CreatedAt = t
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Store) CreateMailbox(address, passwordHash string) (int64, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.db.Exec(`INSERT INTO mail_mailboxes (address, password_hash, created_at) VALUES (?, ?, ?)`, address, passwordHash, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) SetMailboxPassword(id int64, passwordHash string) error {
	_, err := s.db.Exec(`UPDATE mail_mailboxes SET password_hash = ? WHERE id = ?`, passwordHash, id)
	return err
}

func (s *Store) DeleteMailbox(id int64) error {
	_, err := s.db.Exec(`DELETE FROM mail_mailboxes WHERE id = ?`, id)
	return err
}
