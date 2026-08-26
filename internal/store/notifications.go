package store

import "time"

// Notification is one item in a user's notification center — see
// migration 0020. Kind mirrors what triggered it (see servicedesk.go's
// notify* helpers), used only to pick an icon in the UI.
type Notification struct {
	ID        int64
	UserID    int64
	Kind      string
	Title     string
	Body      string
	Link      string
	ReadAt    *time.Time
	CreatedAt time.Time
}

func (s *Store) CreateNotification(userID int64, kind, title, body, link string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(`INSERT INTO notifications (user_id, kind, title, body, link, read_at, created_at)
		VALUES (?, ?, ?, ?, ?, '', ?)`, userID, kind, title, body, link, now)
	return err
}

func scanNotification(row interface{ Scan(...any) error }) (Notification, error) {
	var n Notification
	var readAt, createdAt string
	if err := row.Scan(&n.ID, &n.UserID, &n.Kind, &n.Title, &n.Body, &n.Link, &readAt, &createdAt); err != nil {
		return Notification{}, err
	}
	if readAt != "" {
		if t, err := time.Parse(time.RFC3339, readAt); err == nil {
			n.ReadAt = &t
		}
	}
	if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
		n.CreatedAt = t
	}
	return n, nil
}

const notificationSelect = `SELECT id, user_id, kind, title, body, link, read_at, created_at FROM notifications`

// ListNotifications returns a user's most recent notifications, newest
// first.
func (s *Store) ListNotifications(userID int64, limit int) ([]Notification, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.db.Query(notificationSelect+` WHERE user_id = ? ORDER BY created_at DESC LIMIT ?`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Notification
	for rows.Next() {
		n, err := scanNotification(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// CountUnreadNotifications is the topbar bell's badge number — kept as
// a separate cheap COUNT query so every page load doesn't need to
// fetch and scan the full recent-notifications list just to show a
// number.
func (s *Store) CountUnreadNotifications(userID int64) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM notifications WHERE user_id = ? AND read_at = ''`, userID).Scan(&n)
	return n, err
}

func (s *Store) MarkNotificationRead(id, userID int64) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(`UPDATE notifications SET read_at = ? WHERE id = ? AND user_id = ? AND read_at = ''`, now, id, userID)
	return err
}

func (s *Store) MarkAllNotificationsRead(userID int64) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(`UPDATE notifications SET read_at = ? WHERE user_id = ? AND read_at = ''`, now, userID)
	return err
}
