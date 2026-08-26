package store

import (
	"database/sql"
	"time"
)

// TicketAttachment is one uploaded file — see migration 0022.
type TicketAttachment struct {
	ID             int64
	TicketID       int64
	CommentID      *int64
	OriginalName   string
	StoredName     string
	Size           int64
	UploadedBy     int64
	UploadedByName string
	CreatedAt      time.Time
}

func (s *Store) CreateTicketAttachment(ticketID int64, commentID *int64, originalName, storedName string, size int64, uploadedBy int64) (int64, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.db.Exec(`INSERT INTO ticket_attachments (ticket_id, comment_id, original_name, stored_name, size, uploaded_by, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, ticketID, commentID, originalName, storedName, size, uploadedBy, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) ListTicketAttachments(ticketID int64) ([]TicketAttachment, error) {
	rows, err := s.db.Query(`SELECT a.id, a.ticket_id, a.comment_id, a.original_name, a.stored_name, a.size, a.uploaded_by, u.username, a.created_at
		FROM ticket_attachments a JOIN users u ON u.id = a.uploaded_by WHERE a.ticket_id = ? ORDER BY a.created_at ASC`, ticketID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TicketAttachment
	for rows.Next() {
		var a TicketAttachment
		var commentID sql.NullInt64
		var createdAt string
		if err := rows.Scan(&a.ID, &a.TicketID, &commentID, &a.OriginalName, &a.StoredName, &a.Size, &a.UploadedBy, &a.UploadedByName, &createdAt); err != nil {
			return nil, err
		}
		if commentID.Valid {
			v := commentID.Int64
			a.CommentID = &v
		}
		if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
			a.CreatedAt = t
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) GetTicketAttachment(id int64) (*TicketAttachment, error) {
	row := s.db.QueryRow(`SELECT a.id, a.ticket_id, a.comment_id, a.original_name, a.stored_name, a.size, a.uploaded_by, u.username, a.created_at
		FROM ticket_attachments a JOIN users u ON u.id = a.uploaded_by WHERE a.id = ?`, id)
	var a TicketAttachment
	var commentID sql.NullInt64
	var createdAt string
	if err := row.Scan(&a.ID, &a.TicketID, &commentID, &a.OriginalName, &a.StoredName, &a.Size, &a.UploadedBy, &a.UploadedByName, &createdAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if commentID.Valid {
		v := commentID.Int64
		a.CommentID = &v
	}
	if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
		a.CreatedAt = t
	}
	return &a, nil
}
