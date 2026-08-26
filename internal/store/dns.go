package store

import "time"

// DNSRecord is one entry Kursor manages via dnsmasq (see internal/dns).
type DNSRecord struct {
	ID        int64
	Name      string
	Type      string
	Value     string
	Priority  int
	CreatedAt time.Time
}

// ListDNSRecords returns every record, oldest first.
func (s *Store) ListDNSRecords() ([]DNSRecord, error) {
	rows, err := s.db.Query(`SELECT id, name, type, value, priority, created_at FROM dns_records ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []DNSRecord
	for rows.Next() {
		var r DNSRecord
		var createdAt string
		if err := rows.Scan(&r.ID, &r.Name, &r.Type, &r.Value, &r.Priority, &createdAt); err != nil {
			return nil, err
		}
		if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
			r.CreatedAt = t
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) CreateDNSRecord(name, recordType, value string, priority int) (int64, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.db.Exec(`INSERT INTO dns_records (name, type, value, priority, created_at) VALUES (?, ?, ?, ?, ?)`,
		name, recordType, value, priority, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) DeleteDNSRecord(id int64) error {
	_, err := s.db.Exec(`DELETE FROM dns_records WHERE id = ?`, id)
	return err
}
