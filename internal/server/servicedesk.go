package server

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"kursor/internal/auth"
	"kursor/internal/i18n"
	"kursor/internal/store"
)

// ticketTopics is the ticket "topic" taxonomy — deliberately the same
// set as the sidebar menu, so a ticket says which part of the system
// it's about in terms an operator already knows. LabelKey points at an
// existing nav.* translation (reused, not duplicated) except for
// "other".
var ticketTopics = []struct{ Key, LabelKey string }{
	{"sites", "nav.sites"},
	{"files", "nav.files"},
	{"databases", "nav.databases"},
	{"ssl", "nav.ssl"},
	{"cron", "nav.cron"},
	{"backups", "nav.backups"},
	{"terminal", "nav.terminal"},
	{"network_dns", "nav.dns"},
	{"network_ports", "nav.ports"},
	{"network_vpn", "nav.vpn"},
	{"network_ssh", "nav.ssh"},
	{"accounts", "nav.accounts"},
	{"departments", "nav.departments"},
	{"mail", "nav.mail"},
	{"sso", "nav.sso"},
	{"other", "servicedesk.topic.other"},
}

// notifLang is fixed rather than the acting user's own language cookie
// (getLang(r)) — a notification is generated for a *different* user,
// whose language preference this request has no way to know (Kursor
// only tracks a per-browser cookie, not a stored per-account
// preference). Ukrainian, matching the product's primary language.
const notifLang = "uk"

func isValidTopic(topic string) bool {
	for _, t := range ticketTopics {
		if t.Key == topic {
			return true
		}
	}
	return false
}

// topicLabel translates a topic key — a template func (see templates.go).
func topicLabel(lang, topic string) string {
	for _, t := range ticketTopics {
		if t.Key == topic {
			return i18n.T(lang, t.LabelKey)
		}
	}
	return topic
}

// isAgent reports whether sess can see and triage every ticket (any
// admin, or a member explicitly granted the "servicedesk" permission —
// see accounts.go's allowedPermissions). Everyone else only ever sees
// their own tickets — see ticketsFor below.
func isAgent(sess *store.Session) bool {
	return sess != nil && sess.HasModule("servicedesk")
}

func (s *Server) ticketsFor(sess *store.Session) ([]store.Ticket, error) {
	if isAgent(sess) {
		return s.store.ListTickets()
	}
	return s.store.ListTicketsForRequester(sess.UserID)
}

// filterTickets applies the list page's search box (matches ticket
// DisplayID, title, or requester username/name) and topic/status
// dropdowns — done in Go over the already-scoped list rather than in
// SQL, which is plenty fast at MVP ticket volumes and keeps the access
// scoping (ticketsFor) and the filtering (this) as two separate,
// easy-to-audit steps.
func filterTickets(tickets []store.Ticket, q, topic, status string) []store.Ticket {
	q = strings.ToLower(strings.TrimSpace(q))
	out := make([]store.Ticket, 0, len(tickets))
	for _, t := range tickets {
		if q != "" {
			hay := strings.ToLower(t.DisplayID() + " " + t.Title + " " + t.RequesterName)
			if !strings.Contains(hay, q) {
				continue
			}
		}
		if topic != "" && topic != "all" && t.Topic != topic {
			continue
		}
		if status != "" && status != "all" && t.Status != status {
			continue
		}
		out = append(out, t)
	}
	return out
}

// TicketsData backs the ticket list/queue page.
type TicketsData struct {
	PageData
	IsAgent      bool
	Tickets      []store.Ticket
	Topics       []struct{ Key, LabelKey string }
	AllUsers     []store.User
	Departments  []store.Department
	Positions    []store.Position
	Q            string
	TopicFilter  string
	StatusFilter string
	FormErrorKey string
}

func (s *Server) handleServiceDeskPage(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	tickets, err := s.ticketsFor(sess)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	q := r.URL.Query().Get("q")
	topicFilter := r.URL.Query().Get("topic")
	statusFilter := r.URL.Query().Get("status")

	users, _ := s.store.ListUsers()
	departments, _ := s.store.ListDepartments()
	positions, _ := s.store.ListPositions()

	s.render(w, "servicedesk", TicketsData{
		PageData:     s.basePageData(w, r, "company-servicedesk", sess),
		IsAgent:      isAgent(sess),
		Tickets:      filterTickets(tickets, q, topicFilter, statusFilter),
		Topics:       ticketTopics,
		AllUsers:     users,
		Departments:  departments,
		Positions:    positions,
		Q:            q,
		TopicFilter:  topicFilter,
		StatusFilter: statusFilter,
	})
}

func (s *Server) handleTicketCreate(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)

	renderWithError := func(key string) {
		tickets, _ := s.ticketsFor(sess)
		users, _ := s.store.ListUsers()
		departments, _ := s.store.ListDepartments()
		positions, _ := s.store.ListPositions()
		s.render(w, "servicedesk", TicketsData{
			PageData:     s.basePageData(w, r, "company-servicedesk", sess),
			IsAgent:      isAgent(sess),
			Tickets:      tickets,
			Topics:       ticketTopics,
			AllUsers:     users,
			Departments:  departments,
			Positions:    positions,
			FormErrorKey: key,
		})
	}

	if !parseTicketFormAndCheckCSRF(r) {
		renderWithError("login.error.csrf")
		return
	}

	title := r.FormValue("title")
	if title == "" {
		renderWithError("servicedesk.error.title_required")
		return
	}
	ticketType := r.FormValue("type")
	if ticketType != "incident" && ticketType != "request" && ticketType != "problem" {
		ticketType = "incident"
	}
	priority := r.FormValue("priority")
	switch priority {
	case "low", "medium", "high", "critical":
	default:
		priority = "medium"
	}
	topic := r.FormValue("topic")
	if !isValidTopic(topic) {
		topic = "other"
	}

	nt := store.NewTicket{
		Title:       title,
		Description: r.FormValue("description"),
		Type:        ticketType,
		Topic:       topic,
		Reason:      r.FormValue("reason"),
		Priority:    priority,
		RequesterID: sess.UserID,
	}

	switch r.FormValue("request_kind") {
	case "grant_access":
		nt.RequestKind = "grant_access"
		if username := strings.TrimSpace(r.FormValue("target_username")); username != "" {
			if user, err := s.store.GetUserByUsername(username); err == nil && user != nil {
				nt.TargetUserID = &user.ID
			}
		}
		nt.RequestedPermissions = parsePermissions(r.Form["requested_permissions"])
	case "terminate":
		nt.RequestKind = "terminate"
		if username := strings.TrimSpace(r.FormValue("target_username")); username != "" {
			if user, err := s.store.GetUserByUsername(username); err == nil && user != nil {
				nt.TargetUserID = &user.ID
			}
		}
	case "new_account":
		nt.RequestKind = "new_account"
		nt.NewLastName = r.FormValue("new_last_name")
		nt.NewFirstName = r.FormValue("new_first_name")
		nt.NewPatronymic = r.FormValue("new_patronymic")
		nt.NewEmail = r.FormValue("new_email")
		nt.NewPhone = r.FormValue("new_phone")
		nt.NewHiredAt = r.FormValue("new_hired_at")
		nt.NewDepartmentID = parseOptionalID(r.FormValue("new_department_id"))
		nt.NewPositionID = parseOptionalID(r.FormValue("new_position_id"))
	}

	id, err := s.store.CreateTicket(nt)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if file, header, ferr := r.FormFile("attachment"); ferr == nil {
		defer file.Close()
		_ = saveTicketAttachment(s.store, s.cfg.DataDir, id, nil, sess.UserID, file, header)
	}
	if nt.RequestKind != "" {
		// Only the three request-kind workflows ever set requires_approval
		// (see store.CreateTicket) — a plain ticket never needs this.
		if ticket, err := s.store.GetTicket(id); err == nil && ticket != nil && ticket.RequiresApproval {
			s.notifyAdmins("approval_needed", i18n.T(notifLang, "notif.approval_needed_title"), ticket.Title, "/company/servicedesk/"+strconv.FormatInt(id, 10))
		}
	}
	http.Redirect(w, r, "/company/servicedesk/"+strconv.FormatInt(id, 10), http.StatusSeeOther)
}

// notifyUser records one notification for a single user — every
// ticket-workflow trigger below funnels through this, so "who gets
// notified about what" stays in one place.
func (s *Server) notifyUser(userID int64, kind, title, body, link string) {
	_ = s.store.CreateNotification(userID, kind, title, body, link)
}

// notifyAdmins fans a notification out to every admin — used for the
// one notification that isn't about a specific person (a new request
// needs *someone's* sign-off, not a particular admin's).
func (s *Server) notifyAdmins(kind, title, body, link string) {
	users, err := s.store.ListUsers()
	if err != nil {
		return
	}
	for _, u := range users {
		if u.Role == "admin" {
			s.notifyUser(u.ID, kind, title, body, link)
		}
	}
}

// TicketData backs the ticket detail page.
type TicketData struct {
	PageData
	IsAgent       bool
	Ticket        store.Ticket
	Comments      []store.TicketComment
	Attachments   []store.TicketAttachment
	AllUsers      []store.User
	SupportGroups []store.SupportGroup
	NewUsername   string
	NewPassword   string
	FormErrorKey  string
}

// ticketAttachmentsByComment groups a ticket's attachments by which
// comment they belong to (0 for ones attached to the ticket itself) —
// a template helper so ticket.html can render each comment's own
// attachments inline without a per-comment DB query.
func ticketAttachmentsByComment(attachments []store.TicketAttachment) map[int64][]store.TicketAttachment {
	out := map[int64][]store.TicketAttachment{}
	for _, a := range attachments {
		key := int64(0)
		if a.CommentID != nil {
			key = *a.CommentID
		}
		out[key] = append(out[key], a)
	}
	return out
}

// loadTicket fetches a ticket and enforces access: agents see
// everything, everyone else only their own.
func (s *Server) loadTicket(r *http.Request, sess *store.Session) (*store.Ticket, error) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		return nil, nil
	}
	t, err := s.store.GetTicket(id)
	if err != nil || t == nil {
		return nil, err
	}
	if !isAgent(sess) && t.RequesterID != sess.UserID {
		return nil, nil
	}
	return t, nil
}

func (s *Server) handleTicketPage(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	ticket, err := s.loadTicket(r, sess)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if ticket == nil {
		http.NotFound(w, r)
		return
	}
	comments, _ := s.store.ListTicketComments(ticket.ID)
	attachments, _ := s.store.ListTicketAttachments(ticket.ID)

	data := TicketData{
		PageData:    s.basePageData(w, r, "company-servicedesk", sess),
		IsAgent:     isAgent(sess),
		Ticket:      *ticket,
		Comments:    comments,
		Attachments: attachments,
	}
	if data.IsAgent {
		data.AllUsers, _ = s.store.ListUsers()
		data.SupportGroups, _ = s.store.ListSupportGroups()
	}
	s.render(w, "ticket", data)
}

func (s *Server) handleTicketStatus(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	ticket, err := s.loadTicket(r, sess)
	if err != nil || ticket == nil || !isAgent(sess) {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		http.Redirect(w, r, "/company/servicedesk/"+strconv.FormatInt(ticket.ID, 10), http.StatusSeeOther)
		return
	}
	status := r.FormValue("status")
	switch status {
	case "new", "in_progress", "resolved", "closed":
		_ = s.store.UpdateTicketStatus(ticket.ID, status)
		if ticket.RequesterID != sess.UserID {
			s.notifyUser(ticket.RequesterID, "ticket_status", i18n.T(notifLang, "notif.status_changed_title"),
				ticket.DisplayID()+" "+ticket.Title+" → "+i18n.T(notifLang, "servicedesk.status."+status),
				"/company/servicedesk/"+strconv.FormatInt(ticket.ID, 10))
		}
	}
	http.Redirect(w, r, "/company/servicedesk/"+strconv.FormatInt(ticket.ID, 10), http.StatusSeeOther)
}

// handleTicketSetGroup lets an agent manually assign (or clear, with an
// empty value) which support group currently owns a ticket — the other
// way a ticket's group changes besides escalation.
func (s *Server) handleTicketSetGroup(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	ticket, err := s.loadTicket(r, sess)
	if err != nil || ticket == nil || !isAgent(sess) {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		http.Redirect(w, r, "/company/servicedesk/"+strconv.FormatInt(ticket.ID, 10), http.StatusSeeOther)
		return
	}
	groupID := parseOptionalID(r.FormValue("support_group_id"))
	_ = s.store.SetTicketSupportGroup(ticket.ID, groupID)
	if groupID != nil {
		s.notifyGroup(*groupID, ticket, sess.UserID)
	}
	http.Redirect(w, r, "/company/servicedesk/"+strconv.FormatInt(ticket.ID, 10), http.StatusSeeOther)
}

// notifyGroup fans a notification out to every member of a support
// group about a ticket now in their queue — used by both manual group
// assignment and escalation.
func (s *Server) notifyGroup(groupID int64, ticket *store.Ticket, actorID int64) {
	members, err := s.store.ListUsersInSupportGroup(groupID)
	if err != nil {
		return
	}
	link := "/company/servicedesk/" + strconv.FormatInt(ticket.ID, 10)
	for _, u := range members {
		if u.ID != actorID {
			s.notifyUser(u.ID, "ticket_assigned", i18n.T(notifLang, "notif.assigned_title"), ticket.DisplayID()+" "+ticket.Title, link)
		}
	}
}

// handleTicketEscalate moves a ticket to the next-higher-rank support
// group (see store.NextSupportGroup) — a ticket with no group yet
// escalates to the lowest-rank one (rank 0 is treated as "below every
// real group"). Every escalation also drops a comment in the ticket's
// own thread, so the "why did this move" trail lives right next to the
// conversation, not just in the audit log.
func (s *Server) handleTicketEscalate(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	ticket, err := s.loadTicket(r, sess)
	if err != nil || ticket == nil || !isAgent(sess) {
		http.NotFound(w, r)
		return
	}
	renderErr := func(key string) {
		comments, _ := s.store.ListTicketComments(ticket.ID)
		updated, _ := s.store.GetTicket(ticket.ID)
		data := TicketData{
			PageData:     s.basePageData(w, r, "company-servicedesk", sess),
			IsAgent:      true,
			Ticket:       *updated,
			Comments:     comments,
			FormErrorKey: key,
		}
		data.AllUsers, _ = s.store.ListUsers()
		data.SupportGroups, _ = s.store.ListSupportGroups()
		s.render(w, "ticket", data)
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		renderErr("login.error.csrf")
		return
	}

	groups, err := s.store.ListSupportGroups()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	currentRank := 0
	if ticket.SupportGroupID != nil {
		for _, g := range groups {
			if g.ID == *ticket.SupportGroupID {
				currentRank = g.Rank
				break
			}
		}
	}
	next := store.NextSupportGroup(groups, currentRank)
	if next == nil {
		renderErr("servicedesk.escalate_none_higher")
		return
	}

	_ = s.store.SetTicketSupportGroup(ticket.ID, &next.ID)
	_, _ = s.store.AddTicketComment(ticket.ID, sess.UserID, i18n.T(notifLang, "servicedesk.escalated_notice")+" "+next.Name)
	s.notifyGroup(next.ID, ticket, sess.UserID)

	http.Redirect(w, r, "/company/servicedesk/"+strconv.FormatInt(ticket.ID, 10), http.StatusSeeOther)
}

func (s *Server) handleTicketAssignToMe(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	ticket, err := s.loadTicket(r, sess)
	if err != nil || ticket == nil || !isAgent(sess) {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		http.Redirect(w, r, "/company/servicedesk/"+strconv.FormatInt(ticket.ID, 10), http.StatusSeeOther)
		return
	}
	if ticket.AssigneeID != nil && *ticket.AssigneeID == sess.UserID {
		_ = s.store.AssignTicket(ticket.ID, nil) // click again to unassign yourself
	} else {
		id := sess.UserID
		_ = s.store.AssignTicket(ticket.ID, &id)
	}
	http.Redirect(w, r, "/company/servicedesk/"+strconv.FormatInt(ticket.ID, 10), http.StatusSeeOther)
}

// notifyAssignment tells a newly-assigned agent about their new ticket
// — shared by both assignment paths (assign-to-me never needs it, since
// you obviously already know; only handleTicketAssign's search-picker
// path does).
func (s *Server) notifyAssignment(ticket *store.Ticket, assigneeID, actorID int64) {
	if assigneeID != actorID {
		s.notifyUser(assigneeID, "ticket_assigned", i18n.T(notifLang, "notif.assigned_title"), ticket.DisplayID()+" "+ticket.Title, "/company/servicedesk/"+strconv.FormatInt(ticket.ID, 10))
	}
}

// handleTicketAssign is the search-picker assignment path: an agent
// types/picks any user (not just themselves) via the username-backed
// <datalist> in ticket.html. The same "search a user, assign
// something to them" pattern is meant to be reused for other
// per-user resources later (e.g. VPN peers, once that module exists).
func (s *Server) handleTicketAssign(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	ticket, err := s.loadTicket(r, sess)
	if err != nil || ticket == nil || !isAgent(sess) {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		http.Redirect(w, r, "/company/servicedesk/"+strconv.FormatInt(ticket.ID, 10), http.StatusSeeOther)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	if username == "" {
		_ = s.store.AssignTicket(ticket.ID, nil)
	} else if user, err := s.store.GetUserByUsername(username); err == nil && user != nil {
		_ = s.store.AssignTicket(ticket.ID, &user.ID)
		s.notifyAssignment(ticket, user.ID, sess.UserID)
	}
	http.Redirect(w, r, "/company/servicedesk/"+strconv.FormatInt(ticket.ID, 10), http.StatusSeeOther)
}

func (s *Server) handleTicketComment(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	ticket, err := s.loadTicket(r, sess)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if ticket == nil {
		http.NotFound(w, r)
		return
	}
	if !parseTicketFormAndCheckCSRF(r) {
		http.Redirect(w, r, "/company/servicedesk/"+strconv.FormatInt(ticket.ID, 10), http.StatusSeeOther)
		return
	}
	body := r.FormValue("body")
	if body != "" {
		commentID, _ := s.store.AddTicketComment(ticket.ID, sess.UserID, body)
		if file, header, ferr := r.FormFile("attachment"); ferr == nil {
			defer file.Close()
			_ = saveTicketAttachment(s.store, s.cfg.DataDir, ticket.ID, &commentID, sess.UserID, file, header)
		}
		// Notify "the other side" of the conversation — the requester if
		// an agent just commented, or the assignee (if any) if the
		// requester themselves just commented. Never notify yourself.
		title := i18n.T(notifLang, "notif.new_comment_title")
		link := "/company/servicedesk/" + strconv.FormatInt(ticket.ID, 10)
		if sess.UserID == ticket.RequesterID {
			if ticket.AssigneeID != nil && *ticket.AssigneeID != sess.UserID {
				s.notifyUser(*ticket.AssigneeID, "ticket_comment", title, ticket.DisplayID()+" "+ticket.Title, link)
			}
		} else if ticket.RequesterID != sess.UserID {
			s.notifyUser(ticket.RequesterID, "ticket_comment", title, ticket.DisplayID()+" "+ticket.Title, link)
		}
	}
	http.Redirect(w, r, "/company/servicedesk/"+strconv.FormatInt(ticket.ID, 10), http.StatusSeeOther)
}

// ---------- approvals ----------

// ApprovalsData backs the approvals queue page.
type ApprovalsData struct {
	PageData
	Tickets []store.Ticket
}

func (s *Server) handleApprovalsPage(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	tickets, _ := s.store.ListPendingApprovals()
	s.render(w, "approvals", ApprovalsData{
		PageData: s.basePageData(w, r, "company-approvals", sess),
		Tickets:  tickets,
	})
}

// handleTicketApproval is the sign-off decision — deliberately
// admin-only (not just "servicedesk" agents): approving a request that
// can end in a real account being created is a governance action, not
// routine triage.
func (s *Server) handleTicketApproval(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		http.Redirect(w, r, "/company/servicedesk/"+strconv.FormatInt(id, 10), http.StatusSeeOther)
		return
	}
	decision := r.FormValue("decision")
	if decision == "approved" || decision == "rejected" {
		_ = s.store.SetTicketApproval(id, decision, sess.UserID)
	}
	http.Redirect(w, r, "/company/servicedesk/"+strconv.FormatInt(id, 10), http.StatusSeeOther)
}

// handleTicketCreateAccount is the "one button" from the request
// user's original ask: turn a ticket's new-employee questionnaire into
// a real Kursor account, reusing the exact same creation logic
// accounts.go's form uses (temp password, bcrypt hash, everything) —
// only gated by approval when the ticket required it.
func (s *Server) handleTicketCreateAccount(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	ticket, err := s.loadTicket(r, sess)
	if err != nil || ticket == nil || !isAgent(sess) {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		http.Redirect(w, r, "/company/servicedesk/"+strconv.FormatInt(ticket.ID, 10), http.StatusSeeOther)
		return
	}

	redirectBack := func() {
		http.Redirect(w, r, "/company/servicedesk/"+strconv.FormatInt(ticket.ID, 10), http.StatusSeeOther)
	}

	if ticket.RequestKind != "new_account" || ticket.CreatedAccountID != nil {
		redirectBack()
		return
	}
	if ticket.RequiresApproval && ticket.ApprovalStatus != "approved" {
		redirectBack()
		return
	}

	username := auth.SuggestUsername(ticket.NewFirstName, ticket.NewLastName)
	if username == "" {
		username = "user"
	}
	// A ticket-generated username has no human watching the field to
	// notice a collision the way the accounts.html form does — resolve
	// it here instead, trying username2, username3, ... until one's free.
	finalUsername := username
	for i := 2; i < 50; i++ {
		existing, err := s.store.GetUserByUsername(finalUsername)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if existing == nil {
			break
		}
		finalUsername = username + strconv.Itoa(i)
	}

	tempPassword, err := auth.GenerateTempPassword()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	hash, err := auth.HashPassword(tempPassword)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	newID, err := s.store.CreateUser(store.NewUser{
		Username:     finalUsername,
		PasswordHash: hash,
		Email:        ticket.NewEmail,
		Role:         "member",
		LastName:     ticket.NewLastName,
		FirstName:    ticket.NewFirstName,
		Patronymic:   ticket.NewPatronymic,
		Phone:        ticket.NewPhone,
		DepartmentID: ticket.NewDepartmentID,
		PositionID:   ticket.NewPositionID,
		HiredAt:      ticket.NewHiredAt,
	})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	_ = s.store.SetTicketCreatedAccount(ticket.ID, newID)
	_ = s.store.UpdateTicketStatus(ticket.ID, "resolved")

	comments, _ := s.store.ListTicketComments(ticket.ID)
	updated, _ := s.store.GetTicket(ticket.ID)
	users, _ := s.store.ListUsers()
	data := TicketData{
		PageData:    s.basePageData(w, r, "company-servicedesk", sess),
		IsAgent:     true,
		Ticket:      *updated,
		Comments:    comments,
		AllUsers:    users,
		NewUsername: finalUsername,
		NewPassword: tempPassword,
	}
	s.render(w, "ticket", data)
}

// mergePermissions unions two comma-separated permission lists into one,
// deduplicated and restricted to the allowedPermissions whitelist — the
// same defense-in-depth the checkbox form already applies at submit
// time, re-applied here since these values may have been sitting in a
// ticket for days before an agent acts on them.
func mergePermissions(existing, add []string) string {
	seen := map[string]bool{}
	var out []string
	for _, p := range append(append([]string{}, existing...), add...) {
		if !allowedPermissions[p] || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return strings.Join(out, ",")
}

// handleTicketGrantAccess is the one-click fulfillment for a
// "grant_access" request: unions the checkboxes the requester picked
// into the target user's existing permissions. Guarded the same way as
// account creation — right request kind, approved if approval was
// required, and only once (ActionApplied).
func (s *Server) handleTicketGrantAccess(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	ticket, err := s.loadTicket(r, sess)
	if err != nil || ticket == nil || !isAgent(sess) {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		http.Redirect(w, r, "/company/servicedesk/"+strconv.FormatInt(ticket.ID, 10), http.StatusSeeOther)
		return
	}

	redirectBack := func() {
		http.Redirect(w, r, "/company/servicedesk/"+strconv.FormatInt(ticket.ID, 10), http.StatusSeeOther)
	}

	if ticket.RequestKind != "grant_access" || ticket.TargetUserID == nil || ticket.ActionApplied {
		redirectBack()
		return
	}
	if ticket.RequiresApproval && ticket.ApprovalStatus != "approved" {
		redirectBack()
		return
	}

	target, err := s.store.GetUserByID(*ticket.TargetUserID)
	if err != nil || target == nil {
		redirectBack()
		return
	}

	merged := mergePermissions(target.PermissionsList(), ticket.RequestedPermissionsList())
	if err := s.store.SetUserPermissions(target.ID, merged); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	_ = s.store.SetTicketActionApplied(ticket.ID)
	_ = s.store.UpdateTicketStatus(ticket.ID, "resolved")
	redirectBack()
}

// handleTicketTerminateTarget is the one-click fulfillment for a
// "terminate" (offboarding) request: reuses the exact same
// Store.Terminate the Accounts page's "Звільнити" button calls, which
// records today as the last day and disables the account — disabling
// revokes every module permission and VPN/SSH/etc. access at once,
// since a disabled account fails GetSession on its very next request.
// Guarded by canDeactivate the same way the Accounts page action is:
// never terminate yourself, never terminate the last active admin.
func (s *Server) handleTicketTerminateTarget(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	ticket, err := s.loadTicket(r, sess)
	if err != nil || ticket == nil || !isAgent(sess) {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		http.Redirect(w, r, "/company/servicedesk/"+strconv.FormatInt(ticket.ID, 10), http.StatusSeeOther)
		return
	}

	redirectBack := func() {
		http.Redirect(w, r, "/company/servicedesk/"+strconv.FormatInt(ticket.ID, 10), http.StatusSeeOther)
	}

	if ticket.RequestKind != "terminate" || ticket.TargetUserID == nil || ticket.ActionApplied {
		redirectBack()
		return
	}
	if ticket.RequiresApproval && ticket.ApprovalStatus != "approved" {
		redirectBack()
		return
	}

	target, err := s.store.GetUserByID(*ticket.TargetUserID)
	if err != nil || target == nil || !s.canDeactivate(sess, target) {
		redirectBack()
		return
	}

	if err := s.store.Terminate(target.ID, time.Now().Format("2006-01-02")); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	_ = s.store.SetTicketActionApplied(ticket.ID)
	_ = s.store.UpdateTicketStatus(ticket.ID, "resolved")
	redirectBack()
}
