package store

import (
	"strconv"
	"time"
)

// GetPortLabels returns every stored (port, proto) -> description
// label as a map keyed by "port/proto", for quick lookup while
// rendering the live rule list.
func (s *Store) GetPortLabels() (map[string]string, error) {
	rows, err := s.db.Query(`SELECT port, proto, description FROM port_labels`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]string{}
	for rows.Next() {
		var port int
		var proto, desc string
		if err := rows.Scan(&port, &proto, &desc); err != nil {
			return nil, err
		}
		out[portLabelKey(port, proto)] = desc
	}
	return out, rows.Err()
}

func portLabelKey(port int, proto string) string {
	return proto + ":" + strconv.Itoa(port)
}

// SetPortLabel upserts a description for a (port, proto) pair; an empty
// description removes the row (nothing to show, nothing to store).
func (s *Store) SetPortLabel(port int, proto, description string) error {
	if description == "" {
		_, err := s.db.Exec(`DELETE FROM port_labels WHERE port = ? AND proto = ?`, port, proto)
		return err
	}
	_, err := s.db.Exec(`INSERT INTO port_labels (port, proto, description) VALUES (?, ?, ?)
		ON CONFLICT (port, proto) DO UPDATE SET description = excluded.description`, port, proto, description)
	return err
}

// PortForward is one DNAT rule: external_port on this host forwards to
// internal_ip:internal_port.
type PortForward struct {
	ID            int64
	ExternalPort  int
	ExternalProto string
	InternalIP    string
	InternalPort  int
	Description   string
	CreatedAt     time.Time
}

func (s *Store) ListPortForwards() ([]PortForward, error) {
	rows, err := s.db.Query(`SELECT id, external_port, external_proto, internal_ip, internal_port, description, created_at
		FROM port_forwards ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []PortForward
	for rows.Next() {
		var f PortForward
		var createdAt string
		if err := rows.Scan(&f.ID, &f.ExternalPort, &f.ExternalProto, &f.InternalIP, &f.InternalPort, &f.Description, &createdAt); err != nil {
			return nil, err
		}
		if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
			f.CreatedAt = t
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *Store) CreatePortForward(f PortForward) (int64, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.db.Exec(`INSERT INTO port_forwards (external_port, external_proto, internal_ip, internal_port, description, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`, f.ExternalPort, f.ExternalProto, f.InternalIP, f.InternalPort, f.Description, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) DeletePortForward(id int64) error {
	_, err := s.db.Exec(`DELETE FROM port_forwards WHERE id = ?`, id)
	return err
}
