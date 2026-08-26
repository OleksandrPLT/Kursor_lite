package store

import "time"

// SupportGroup is an agent access tier — "Модератор", "Керівник",
// "Підтримка 1/2/3 лінія" — assignable to users and to tickets. Rank
// gives escalation a well-defined "next" group (the lowest rank
// strictly greater than the current one).
type SupportGroup struct {
	ID        int64
	Name      string
	Rank      int
	CreatedAt time.Time
}

func (s *Store) ListSupportGroups() ([]SupportGroup, error) {
	rows, err := s.db.Query(`SELECT id, name, rank, created_at FROM support_groups ORDER BY rank ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SupportGroup
	for rows.Next() {
		var g SupportGroup
		var createdAt string
		if err := rows.Scan(&g.ID, &g.Name, &g.Rank, &createdAt); err != nil {
			return nil, err
		}
		if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
			g.CreatedAt = t
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (s *Store) GetSupportGroup(id int64) (*SupportGroup, error) {
	groups, err := s.ListSupportGroups()
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		if g.ID == id {
			return &g, nil
		}
	}
	return nil, nil
}

// NextSupportGroup returns the group with the lowest rank strictly
// greater than fromRank — the escalation target. nil if fromRank is
// already the highest (nothing left to escalate to).
func NextSupportGroup(groups []SupportGroup, fromRank int) *SupportGroup {
	var next *SupportGroup
	for i := range groups {
		g := groups[i]
		if g.Rank > fromRank && (next == nil || g.Rank < next.Rank) {
			next = &groups[i]
		}
	}
	return next
}

func (s *Store) CreateSupportGroup(name string, rank int) (int64, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.db.Exec(`INSERT INTO support_groups (name, rank, created_at) VALUES (?, ?, ?)`, name, rank, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) DeleteSupportGroup(id int64) error {
	_, err := s.db.Exec(`DELETE FROM support_groups WHERE id = ?`, id)
	return err
}

// SetUserSupportGroup assigns (or, with nil, clears) a user's group.
func (s *Store) SetUserSupportGroup(userID int64, groupID *int64) error {
	_, err := s.db.Exec(`UPDATE users SET support_group_id = ? WHERE id = ?`, groupID, userID)
	return err
}

// ListUsersInSupportGroup is who gets notified when a ticket
// lands in/escalates to this group.
func (s *Store) ListUsersInSupportGroup(groupID int64) ([]User, error) {
	users, err := s.ListUsers()
	if err != nil {
		return nil, err
	}
	var out []User
	for _, u := range users {
		if u.SupportGroupID != nil && *u.SupportGroupID == groupID {
			out = append(out, u)
		}
	}
	return out, nil
}

// SetTicketSupportGroup assigns a ticket to a group directly (manual
// triage) — EscalateTicket (in server/servicedesk.go, which also needs
// to notify the new group's members) is the other way a ticket's group
// changes.
func (s *Store) SetTicketSupportGroup(ticketID int64, groupID *int64) error {
	_, err := s.db.Exec(`UPDATE tickets SET support_group_id = ? WHERE id = ?`, groupID, ticketID)
	return err
}
