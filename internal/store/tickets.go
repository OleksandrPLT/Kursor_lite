package store

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// slaHours maps ticket priority to how many hours it has to be resolved
// in — the "lightweight SLA" phase-1 scope note: a due date, not a full
// escalation/paging engine.
var slaHours = map[string]int{
	"critical": 4,
	"high":     24,
	"medium":   24 * 3,
	"low":      24 * 7,
}

// DueDateFor computes when a ticket of the given priority is due,
// relative to now.
func DueDateFor(priority string, now time.Time) time.Time {
	hours, ok := slaHours[priority]
	if !ok {
		hours = slaHours["medium"]
	}
	return now.Add(time.Duration(hours) * time.Hour)
}

// Ticket is one service desk ticket (incident, service request, or
// problem — see migration 0008). RequestKind/New*/TargetUserID and the
// approval fields are the request-fulfillment workflow from migration
// 0010: a ticket can concern an existing user (TargetUserID — "grant
// VPN to X") or carry a full new-employee questionnaire
// (RequestKind == "new_account"), optionally gated behind approval
// before an agent can act on it.
type Ticket struct {
	ID            int64
	Title         string
	Description   string
	Type          string
	Topic         string // which part of the system — same taxonomy as the sidebar menu
	Reason        string // free text, picked from a topic-specific quick list client-side
	Status        string
	Priority      string
	RequesterID   int64
	RequesterName string
	AssigneeID    *int64
	AssigneeName  string
	DueAt         time.Time
	CreatedAt     time.Time
	UpdatedAt     time.Time
	ResolvedAt    *time.Time

	TargetUserID   *int64
	TargetUserName string
	RequestKind    string // "" | "new_account" | "grant_access" | "terminate"

	NewLastName     string
	NewFirstName    string
	NewPatronymic   string
	NewEmail        string
	NewPhone        string
	NewHiredAt      string
	NewDepartmentID *int64
	NewPositionID   *int64

	// RequestedPermissions is comma-separated module keys — the
	// checkboxes on a "grant_access" request (same taxonomy as
	// users.permissions; a VPN access request is just topic=network_vpn
	// with "network" checked here, since there's no separate VPN module
	// yet — see the project memory note).
	RequestedPermissions string

	RequiresApproval bool
	ApprovalStatus   string // "none" | "pending" | "approved" | "rejected"
	ApprovedByID     *int64
	ApprovedByName   string
	ApprovedAt       *time.Time

	CreatedAccountID *int64
	// ActionApplied is the generic one-shot guard for whichever
	// one-click action RequestKind triggers — set once the action ran,
	// so a repeat click (or a slow double-submit) can never re-run it.
	ActionApplied   bool
	ActionAppliedAt *time.Time

	// SupportGroupID is which access tier currently owns this ticket —
	// nil until an agent sets it or escalates (see server/servicedesk.go
	// handleTicketEscalate).
	SupportGroupID   *int64
	SupportGroupName string
}

// RequestedPermissionsList splits RequestedPermissions, skipping blanks.
func (t Ticket) RequestedPermissionsList() []string {
	if t.RequestedPermissions == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(t.RequestedPermissions, ",") {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// NewAccountDisplayName composes the ПІБ for the new-employee
// questionnaire fields, mirroring User.DisplayName's field order.
func (t Ticket) NewAccountDisplayName() string {
	parts := make([]string, 0, 3)
	for _, p := range []string{t.NewLastName, t.NewFirstName, t.NewPatronymic} {
		if p != "" {
			parts = append(parts, p)
		}
	}
	if len(parts) == 0 {
		return ""
	}
	out := parts[0]
	for _, p := range parts[1:] {
		out += " " + p
	}
	return out
}

// DisplayID renders the ticket as a real-looking ticketing-system
// reference, e.g. "INC-0042" — the prefix follows Type so incidents,
// requests and problems are visually distinguishable at a glance.
func (t Ticket) DisplayID() string {
	prefix := "TCK"
	switch t.Type {
	case "incident":
		prefix = "INC"
	case "request":
		prefix = "REQ"
	case "problem":
		prefix = "PRB"
	}
	return fmt.Sprintf("%s-%04d", prefix, t.ID)
}

// IsOverdue reports whether an unresolved ticket has passed its SLA due
// date.
func (t Ticket) IsOverdue() bool {
	if t.Status == "resolved" || t.Status == "closed" {
		return false
	}
	return !t.DueAt.IsZero() && time.Now().UTC().After(t.DueAt)
}

const ticketSelect = `t.id, t.title, t.description, t.type, t.topic, t.reason, t.status, t.priority,
	t.requester_id, ru.username, t.assignee_id, COALESCE(au.username, ''),
	t.due_at, t.created_at, t.updated_at, t.resolved_at,
	t.target_user_id, COALESCE(tu.username, ''), t.request_kind,
	t.new_last_name, t.new_first_name, t.new_patronymic, t.new_email, t.new_phone, t.new_hired_at,
	t.new_department_id, t.new_position_id, t.requested_permissions,
	t.requires_approval, t.approval_status, t.approved_by, COALESCE(ab.username, ''), t.approved_at,
	t.created_account_id, t.action_applied_at, t.support_group_id, COALESCE(sg.name, '')`

const ticketFrom = `FROM tickets t
	JOIN users ru ON ru.id = t.requester_id
	LEFT JOIN users au ON au.id = t.assignee_id
	LEFT JOIN users tu ON tu.id = t.target_user_id
	LEFT JOIN users ab ON ab.id = t.approved_by
	LEFT JOIN support_groups sg ON sg.id = t.support_group_id`

func scanTicket(row interface{ Scan(...any) error }) (*Ticket, error) {
	var t Ticket
	var assigneeID, targetUserID, newDeptID, newPosID, approvedByID, createdAccountID, supportGroupID sql.NullInt64
	var requiresApproval int
	var dueAt, createdAt, updatedAt, resolvedAt, approvedAt, actionAppliedAt string
	if err := row.Scan(
		&t.ID, &t.Title, &t.Description, &t.Type, &t.Topic, &t.Reason, &t.Status, &t.Priority,
		&t.RequesterID, &t.RequesterName, &assigneeID, &t.AssigneeName,
		&dueAt, &createdAt, &updatedAt, &resolvedAt,
		&targetUserID, &t.TargetUserName, &t.RequestKind,
		&t.NewLastName, &t.NewFirstName, &t.NewPatronymic, &t.NewEmail, &t.NewPhone, &t.NewHiredAt,
		&newDeptID, &newPosID, &t.RequestedPermissions,
		&requiresApproval, &t.ApprovalStatus, &approvedByID, &t.ApprovedByName, &approvedAt,
		&createdAccountID, &actionAppliedAt, &supportGroupID, &t.SupportGroupName,
	); err != nil {
		return nil, err
	}
	if supportGroupID.Valid {
		v := supportGroupID.Int64
		t.SupportGroupID = &v
	}
	if assigneeID.Valid {
		v := assigneeID.Int64
		t.AssigneeID = &v
	}
	if targetUserID.Valid {
		v := targetUserID.Int64
		t.TargetUserID = &v
	}
	if newDeptID.Valid {
		v := newDeptID.Int64
		t.NewDepartmentID = &v
	}
	if newPosID.Valid {
		v := newPosID.Int64
		t.NewPositionID = &v
	}
	if approvedByID.Valid {
		v := approvedByID.Int64
		t.ApprovedByID = &v
	}
	if createdAccountID.Valid {
		v := createdAccountID.Int64
		t.CreatedAccountID = &v
	}
	t.RequiresApproval = requiresApproval != 0
	if v, err := time.Parse(time.RFC3339, actionAppliedAt); err == nil {
		t.ActionApplied = true
		t.ActionAppliedAt = &v
	}
	if v, err := time.Parse(time.RFC3339, dueAt); err == nil {
		t.DueAt = v
	}
	if v, err := time.Parse(time.RFC3339, createdAt); err == nil {
		t.CreatedAt = v
	}
	if v, err := time.Parse(time.RFC3339, updatedAt); err == nil {
		t.UpdatedAt = v
	}
	if v, err := time.Parse(time.RFC3339, resolvedAt); err == nil {
		t.ResolvedAt = &v
	}
	if v, err := time.Parse(time.RFC3339, approvedAt); err == nil {
		t.ApprovedAt = &v
	}
	return &t, nil
}

// NewTicket holds the fields needed to open a ticket.
type NewTicket struct {
	Title       string
	Description string
	Type        string
	Topic       string
	Reason      string
	Priority    string
	RequesterID int64

	TargetUserID *int64
	RequestKind  string

	NewLastName     string
	NewFirstName    string
	NewPatronymic   string
	NewEmail        string
	NewPhone        string
	NewHiredAt      string
	NewDepartmentID *int64
	NewPositionID   *int64

	RequestedPermissions string
}

// CreateTicket opens a new ticket, computing its SLA due date from
// priority. Any request kind that ends in a real account/access change
// (new_account, grant_access, terminate) always requires approval —
// someone else must sign off before an agent can act on it.
func (s *Store) CreateTicket(nt NewTicket) (int64, error) {
	now := time.Now().UTC()
	due := DueDateFor(nt.Priority, now)
	requiresApproval := 0
	approvalStatus := "none"
	switch nt.RequestKind {
	case "new_account", "grant_access", "terminate":
		requiresApproval = 1
		approvalStatus = "pending"
	}
	res, err := s.db.Exec(`INSERT INTO tickets
		(title, description, type, topic, reason, status, priority, requester_id, due_at, created_at, updated_at,
		 target_user_id, request_kind, new_last_name, new_first_name, new_patronymic, new_email, new_phone, new_hired_at,
		 new_department_id, new_position_id, requested_permissions, requires_approval, approval_status)
		VALUES (?, ?, ?, ?, ?, 'new', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		nt.Title, nt.Description, nt.Type, nt.Topic, nt.Reason, nt.Priority, nt.RequesterID,
		due.Format(time.RFC3339), now.Format(time.RFC3339), now.Format(time.RFC3339),
		nt.TargetUserID, nt.RequestKind, nt.NewLastName, nt.NewFirstName, nt.NewPatronymic, nt.NewEmail, nt.NewPhone, nt.NewHiredAt,
		nt.NewDepartmentID, nt.NewPositionID, nt.RequestedPermissions, requiresApproval, approvalStatus)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ListTickets returns every ticket, newest first.
func (s *Store) ListTickets() ([]Ticket, error) {
	return s.queryTickets(`SELECT ` + ticketSelect + ` ` + ticketFrom + ` ORDER BY t.created_at DESC`)
}

// ListTicketsForRequester returns only tickets a non-agent requester is
// allowed to see: their own.
func (s *Store) ListTicketsForRequester(userID int64) ([]Ticket, error) {
	return s.queryTickets(`SELECT `+ticketSelect+` `+ticketFrom+` WHERE t.requester_id = ? ORDER BY t.created_at DESC`, userID)
}

func (s *Store) queryTickets(query string, args ...any) ([]Ticket, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Ticket
	for rows.Next() {
		t, err := scanTicket(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

// GetTicket returns nil, nil if no such ticket exists.
func (s *Store) GetTicket(id int64) (*Ticket, error) {
	row := s.db.QueryRow(`SELECT `+ticketSelect+` `+ticketFrom+` WHERE t.id = ?`, id)
	t, err := scanTicket(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return t, err
}

// UpdateTicketStatus changes status, stamping resolved_at when moving
// into "resolved" and clearing it if reopened.
func (s *Store) UpdateTicketStatus(id int64, status string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	resolvedAt := ""
	if status == "resolved" || status == "closed" {
		resolvedAt = now
	}
	_, err := s.db.Exec(`UPDATE tickets SET status = ?, resolved_at = CASE WHEN ? != '' THEN ? ELSE resolved_at END, updated_at = ? WHERE id = ?`,
		status, resolvedAt, resolvedAt, now, id)
	return err
}

// AssignTicket sets (or clears, if assigneeID is nil) a ticket's assignee.
func (s *Store) AssignTicket(id int64, assigneeID *int64) error {
	_, err := s.db.Exec(`UPDATE tickets SET assignee_id = ?, updated_at = ? WHERE id = ?`,
		assigneeID, time.Now().UTC().Format(time.RFC3339), id)
	return err
}

// SetTicketTargetUser sets (or clears) which existing user a ticket
// concerns (e.g. "grant VPN access to X").
func (s *Store) SetTicketTargetUser(id int64, targetUserID *int64) error {
	_, err := s.db.Exec(`UPDATE tickets SET target_user_id = ?, updated_at = ? WHERE id = ?`,
		targetUserID, time.Now().UTC().Format(time.RFC3339), id)
	return err
}

// ListPendingApprovals returns every ticket awaiting an approval
// decision, oldest first (first in, first reviewed).
func (s *Store) ListPendingApprovals() ([]Ticket, error) {
	return s.queryTickets(`SELECT ` + ticketSelect + ` ` + ticketFrom + ` WHERE t.approval_status = 'pending' ORDER BY t.created_at ASC`)
}

// SetTicketApproval records an approve/reject decision.
func (s *Store) SetTicketApproval(id int64, status string, approvedBy int64) error {
	_, err := s.db.Exec(`UPDATE tickets SET approval_status = ?, approved_by = ?, approved_at = ?, updated_at = ? WHERE id = ?`,
		status, approvedBy, time.Now().UTC().Format(time.RFC3339), time.Now().UTC().Format(time.RFC3339), id)
	return err
}

// SetTicketCreatedAccount records that the ticket's "Create Account"
// action fired and which account it produced — so the button only ever
// runs once per ticket.
func (s *Store) SetTicketCreatedAccount(id, accountID int64) error {
	_, err := s.db.Exec(`UPDATE tickets SET created_account_id = ?, updated_at = ? WHERE id = ?`,
		accountID, time.Now().UTC().Format(time.RFC3339), id)
	return err
}

// SetTicketActionApplied marks a ticket's one-click workflow action
// (grant access / terminate — CreateAccount uses the more specific
// SetTicketCreatedAccount, itself its own guard) as done, so a repeat
// click can never re-run it.
func (s *Store) SetTicketActionApplied(id int64) error {
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(`UPDATE tickets SET action_applied_at = ?, updated_at = ? WHERE id = ?`, now, now, id)
	return err
}

// TicketComment is one entry in a ticket's activity timeline.
type TicketComment struct {
	ID         int64
	TicketID   int64
	AuthorID   int64
	AuthorName string
	Body       string
	CreatedAt  time.Time
}

// AddTicketComment appends a comment to a ticket's timeline.
func (s *Store) AddTicketComment(ticketID, authorID int64, body string) error {
	_, err := s.db.Exec(`INSERT INTO ticket_comments (ticket_id, author_id, body, created_at) VALUES (?, ?, ?, ?)`,
		ticketID, authorID, body, time.Now().UTC().Format(time.RFC3339))
	return err
}

// ListTicketComments returns a ticket's timeline, oldest first.
func (s *Store) ListTicketComments(ticketID int64) ([]TicketComment, error) {
	rows, err := s.db.Query(`SELECT tc.id, tc.ticket_id, tc.author_id, u.username, tc.body, tc.created_at
		FROM ticket_comments tc JOIN users u ON u.id = tc.author_id
		WHERE tc.ticket_id = ? ORDER BY tc.created_at ASC`, ticketID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []TicketComment
	for rows.Next() {
		var c TicketComment
		var createdAt string
		if err := rows.Scan(&c.ID, &c.TicketID, &c.AuthorID, &c.AuthorName, &c.Body, &createdAt); err != nil {
			return nil, err
		}
		if v, err := time.Parse(time.RFC3339, createdAt); err == nil {
			c.CreatedAt = v
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
