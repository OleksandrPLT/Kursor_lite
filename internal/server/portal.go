// Package server's portal.go: the Service Desk portal — same accounts,
// same session cookie, same password as the main panel (auth.
// StartSession/CurrentSession are shared), just a different login page
// and its own set of routes/templates. No self-registration: an account
// here is still created the normal way, by an admin on the Accounts
// page.
//
// Two experiences share this one surface, branching on isAgent(sess)
// (the same "servicedesk" permission/admin check the main panel's
// /company/servicedesk uses):
//   - a plain account sees only "submit and track my own tickets" —
//     the original, minimal reason this surface exists;
//   - an agent (any support-group member with the servicedesk
//     permission, or an admin) gets the full triage toolkit — the same
//     queue, filters, assignment/escalation/approval/one-click
//     fulfillment actions as /company/servicedesk, just reachable
//     without ever landing in the rest of the panel. That matters for
//     staff who only ever do ticket work and have no other module
//     access at all.
package server

import (
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"kursor/internal/auth"
	"kursor/internal/i18n"
	"kursor/internal/store"
)

// PortalLoginData backs /portal/login.
type PortalLoginData struct {
	Lang        string
	ErrorKey    string
	ErrorDetail string
	CSRFToken   string
}

func (s *Server) handlePortalLoginPage(w http.ResponseWriter, r *http.Request) {
	if auth.CurrentSession(r, s.store) != nil {
		http.Redirect(w, r, "/portal", http.StatusSeeOther)
		return
	}
	s.render(w, "portal_login", PortalLoginData{Lang: getLang(r), CSRFToken: auth.IssueCSRFToken(w)})
}

func (s *Server) handlePortalLoginSubmit(w http.ResponseWriter, r *http.Request) {
	renderErr := func(key, detail string) {
		s.render(w, "portal_login", PortalLoginData{Lang: getLang(r), ErrorKey: key, ErrorDetail: detail, CSRFToken: auth.IssueCSRFToken(w)})
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		renderErr("login.error.csrf", "")
		return
	}
	username := r.FormValue("username")

	// Same account, same brute-force lockout as the main panel's login
	// (store.IsLoginLockedOut/RecordFailedLogin) — a portal-only account
	// deserves the same protection as an admin one.
	if locked, until, err := s.store.IsLoginLockedOut(username); err == nil && locked {
		lang := getLang(r)
		minutesLeft := int(until.Sub(time.Now().UTC()).Minutes()) + 1
		renderErr("login.error.locked_out", "("+strconv.Itoa(minutesLeft)+" "+i18n.T(lang, "login.minutes_short")+")")
		return
	}

	user, err := s.store.GetUserByUsername(username)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if user == nil || !auth.CheckPassword(user.PasswordHash, r.FormValue("password")) {
		if username != "" {
			_ = s.store.RecordFailedLogin(username)
		}
		renderErr("login.error.invalid", "")
		return
	}
	if user.Status != "active" {
		renderErr("login.error.disabled", "")
		return
	}
	_ = s.store.ClearLoginLockout(username)
	if err := auth.StartSession(w, s.store, user.ID, r); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/portal", http.StatusSeeOther)
}

func (s *Server) handlePortalLogout(w http.ResponseWriter, r *http.Request) {
	auth.EndSession(w, r, s.store)
	http.Redirect(w, r, "/portal/login", http.StatusSeeOther)
}

// PortalData backs every page in the portal. Most fields only matter
// for the agent view (AllUsers/Departments/Positions are the exception —
// the "new ticket" form's request-kind blocks need them for everyone,
// since submitting a new_account/grant_access/terminate request isn't
// an agent-only action).
type PortalData struct {
	Lang         string
	Username     string
	UserInitials string
	UserID       int64
	CSRFToken    string

	IsAgent bool
	IsAdmin bool

	Tickets       []store.Ticket
	Topics        []struct{ Key, LabelKey string }
	AllUsers      []store.User
	Departments   []store.Department
	Positions     []store.Position
	SupportGroups []store.SupportGroup

	// MySupportGroupIDStr is the acting agent's own support group, if
	// any — powers the sidebar's "My group" quick filter. Empty for a
	// non-agent or an agent in no group.
	MySupportGroupIDStr string

	Q              string
	TopicFilter    string
	StatusFilter   string
	AssignedFilter string
	GroupFilter    string

	FormErrorKey string
}

func (s *Server) portalBaseData(w http.ResponseWriter, r *http.Request, sess *store.Session) PortalData {
	data := PortalData{
		Lang:         getLang(r),
		Username:     sess.Username,
		UserInitials: userInitials(sess.Username),
		UserID:       sess.UserID,
		CSRFToken:    auth.IssueCSRFToken(w),
		IsAgent:      isAgent(sess),
		IsAdmin:      sess.Role == "admin",
		Topics:       ticketTopics,
	}
	// Every portal user (not just agents) can submit a grant_access/
	// new_account/terminate ticket — same request-kind menu the panel's
	// create form offers — so these lists are loaded unconditionally.
	data.AllUsers, _ = s.store.ListUsers()
	data.Departments, _ = s.store.ListDepartments()
	data.Positions, _ = s.store.ListPositions()
	if data.IsAgent {
		if u, err := s.store.GetUserByID(sess.UserID); err == nil && u != nil && u.SupportGroupID != nil {
			data.MySupportGroupIDStr = strconv.FormatInt(*u.SupportGroupID, 10)
		}
	}
	return data
}

// filterTicketsByAssignee narrows to tickets assigned to a specific
// user (id != nil) or to nobody (id == nil) — the sidebar's "assigned
// to me"/"unassigned" quick filters.
func filterTicketsByAssignee(tickets []store.Ticket, id *int64) []store.Ticket {
	out := make([]store.Ticket, 0, len(tickets))
	for _, t := range tickets {
		switch {
		case id == nil:
			if t.AssigneeID == nil {
				out = append(out, t)
			}
		case t.AssigneeID != nil && *t.AssigneeID == *id:
			out = append(out, t)
		}
	}
	return out
}

// filterTicketsByGroup narrows to tickets currently owned by one
// support group — the sidebar's "my group" quick filter.
func filterTicketsByGroup(tickets []store.Ticket, groupID int64) []store.Ticket {
	out := make([]store.Ticket, 0, len(tickets))
	for _, t := range tickets {
		if t.SupportGroupID != nil && *t.SupportGroupID == groupID {
			out = append(out, t)
		}
	}
	return out
}

func (s *Server) handlePortalPage(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	tickets, err := s.ticketsFor(sess)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	q := r.URL.Query().Get("q")
	topicFilter := r.URL.Query().Get("topic")
	statusFilter := r.URL.Query().Get("status")
	tickets = filterTickets(tickets, q, topicFilter, statusFilter)

	data := s.portalBaseData(w, r, sess)
	if data.IsAgent {
		assigned := r.URL.Query().Get("assigned")
		switch assigned {
		case "me":
			tickets = filterTicketsByAssignee(tickets, &sess.UserID)
		case "none":
			tickets = filterTicketsByAssignee(tickets, nil)
		}
		data.AssignedFilter = assigned

		if groupFilter := r.URL.Query().Get("group"); groupFilter != "" {
			if gid, err := strconv.ParseInt(groupFilter, 10, 64); err == nil {
				tickets = filterTicketsByGroup(tickets, gid)
				data.GroupFilter = groupFilter
			}
		}
		data.SupportGroups, _ = s.store.ListSupportGroups()
	}

	data.Tickets = tickets
	data.Q, data.TopicFilter, data.StatusFilter = q, topicFilter, statusFilter
	s.render(w, "portal", data)
}

func (s *Server) handlePortalTicketCreate(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	renderErr := func(key string) {
		data := s.portalBaseData(w, r, sess)
		data.Tickets, _ = s.ticketsFor(sess)
		data.FormErrorKey = key
		s.render(w, "portal", data)
	}
	if !parseTicketFormAndCheckCSRF(r) {
		renderErr("login.error.csrf")
		return
	}
	title := r.FormValue("title")
	if title == "" {
		renderErr("servicedesk.error.title_required")
		return
	}
	nt := s.newTicketFromForm(r, sess.UserID, title)

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
		if ticket, err := s.store.GetTicket(id); err == nil && ticket != nil && ticket.RequiresApproval {
			s.notifyAdmins("approval_needed", i18n.T(notifLang, "notif.approval_needed_title"), ticket.Title, "/company/servicedesk/"+strconv.FormatInt(id, 10))
		}
	}
	http.Redirect(w, r, "/portal/tickets/"+strconv.FormatInt(id, 10), http.StatusSeeOther)
}

// PortalTicketData backs the portal's single-ticket view.
type PortalTicketData struct {
	PortalData
	Ticket      store.Ticket
	Comments    []store.TicketComment
	Attachments []store.TicketAttachment
	NewUsername string
	NewPassword string
}

func (s *Server) handlePortalTicketPage(w http.ResponseWriter, r *http.Request) {
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
	data := PortalTicketData{
		PortalData:  s.portalBaseData(w, r, sess),
		Ticket:      *ticket,
		Comments:    comments,
		Attachments: attachments,
	}
	if data.IsAgent {
		data.SupportGroups, _ = s.store.ListSupportGroups()
	}
	s.render(w, "portal_ticket", data)
}

func (s *Server) handlePortalTicketComment(w http.ResponseWriter, r *http.Request) {
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
		http.Redirect(w, r, "/portal/tickets/"+strconv.FormatInt(ticket.ID, 10), http.StatusSeeOther)
		return
	}
	body := r.FormValue("body")
	if body != "" {
		commentID, _ := s.store.AddTicketComment(ticket.ID, sess.UserID, body)
		if file, header, ferr := r.FormFile("attachment"); ferr == nil {
			defer file.Close()
			_ = saveTicketAttachment(s.store, s.cfg.DataDir, ticket.ID, &commentID, sess.UserID, file, header)
		}
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
	http.Redirect(w, r, "/portal/tickets/"+strconv.FormatInt(ticket.ID, 10), http.StatusSeeOther)
}

// handlePortalTicketStatus mirrors handleTicketStatus (servicedesk.go),
// scoped to /portal — an agent working the portal gets the exact same
// status-change action, not a crippled copy.
func (s *Server) handlePortalTicketStatus(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	ticket, err := s.loadTicket(r, sess)
	if err != nil || ticket == nil || !isAgent(sess) {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		http.Redirect(w, r, "/portal/tickets/"+strconv.FormatInt(ticket.ID, 10), http.StatusSeeOther)
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
	http.Redirect(w, r, "/portal/tickets/"+strconv.FormatInt(ticket.ID, 10), http.StatusSeeOther)
}

// handlePortalTicketSetGroup mirrors handleTicketSetGroup.
func (s *Server) handlePortalTicketSetGroup(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	ticket, err := s.loadTicket(r, sess)
	if err != nil || ticket == nil || !isAgent(sess) {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		http.Redirect(w, r, "/portal/tickets/"+strconv.FormatInt(ticket.ID, 10), http.StatusSeeOther)
		return
	}
	groupID := parseOptionalID(r.FormValue("support_group_id"))
	_ = s.store.SetTicketSupportGroup(ticket.ID, groupID)
	if groupID != nil {
		s.notifyGroup(*groupID, ticket, sess.UserID)
	}
	http.Redirect(w, r, "/portal/tickets/"+strconv.FormatInt(ticket.ID, 10), http.StatusSeeOther)
}

// handlePortalTicketEscalate mirrors handleTicketEscalate, rendering
// "portal_ticket" (not "ticket") on the "nothing higher" error so the
// operator never leaves the portal chrome to see it.
func (s *Server) handlePortalTicketEscalate(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	ticket, err := s.loadTicket(r, sess)
	if err != nil || ticket == nil || !isAgent(sess) {
		http.NotFound(w, r)
		return
	}
	renderErr := func(key string) {
		comments, _ := s.store.ListTicketComments(ticket.ID)
		attachments, _ := s.store.ListTicketAttachments(ticket.ID)
		updated, _ := s.store.GetTicket(ticket.ID)
		data := PortalTicketData{
			PortalData:  s.portalBaseData(w, r, sess),
			Ticket:      *updated,
			Comments:    comments,
			Attachments: attachments,
		}
		data.FormErrorKey = key
		data.SupportGroups, _ = s.store.ListSupportGroups()
		s.render(w, "portal_ticket", data)
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

	http.Redirect(w, r, "/portal/tickets/"+strconv.FormatInt(ticket.ID, 10), http.StatusSeeOther)
}

// handlePortalTicketAssignToMe mirrors handleTicketAssignToMe.
func (s *Server) handlePortalTicketAssignToMe(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	ticket, err := s.loadTicket(r, sess)
	if err != nil || ticket == nil || !isAgent(sess) {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		http.Redirect(w, r, "/portal/tickets/"+strconv.FormatInt(ticket.ID, 10), http.StatusSeeOther)
		return
	}
	if ticket.AssigneeID != nil && *ticket.AssigneeID == sess.UserID {
		_ = s.store.AssignTicket(ticket.ID, nil)
	} else {
		id := sess.UserID
		_ = s.store.AssignTicket(ticket.ID, &id)
	}
	http.Redirect(w, r, "/portal/tickets/"+strconv.FormatInt(ticket.ID, 10), http.StatusSeeOther)
}

// handlePortalTicketAssign mirrors handleTicketAssign.
func (s *Server) handlePortalTicketAssign(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	ticket, err := s.loadTicket(r, sess)
	if err != nil || ticket == nil || !isAgent(sess) {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		http.Redirect(w, r, "/portal/tickets/"+strconv.FormatInt(ticket.ID, 10), http.StatusSeeOther)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	if username == "" {
		_ = s.store.AssignTicket(ticket.ID, nil)
	} else if user, err := s.store.GetUserByUsername(username); err == nil && user != nil {
		_ = s.store.AssignTicket(ticket.ID, &user.ID)
		s.notifyAssignment(ticket, user.ID, sess.UserID)
	}
	http.Redirect(w, r, "/portal/tickets/"+strconv.FormatInt(ticket.ID, 10), http.StatusSeeOther)
}

// handlePortalTicketCreateAccount mirrors handleTicketCreateAccount —
// including rendering inline (never redirecting) on success, since the
// generated temp password is shown exactly once and is never persisted
// anywhere in retrievable form.
func (s *Server) handlePortalTicketCreateAccount(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	ticket, err := s.loadTicket(r, sess)
	if err != nil || ticket == nil || !isAgent(sess) {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		http.Redirect(w, r, "/portal/tickets/"+strconv.FormatInt(ticket.ID, 10), http.StatusSeeOther)
		return
	}

	redirectBack := func() {
		http.Redirect(w, r, "/portal/tickets/"+strconv.FormatInt(ticket.ID, 10), http.StatusSeeOther)
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
	attachments, _ := s.store.ListTicketAttachments(ticket.ID)
	updated, _ := s.store.GetTicket(ticket.ID)
	data := PortalTicketData{
		PortalData:  s.portalBaseData(w, r, sess),
		Ticket:      *updated,
		Comments:    comments,
		Attachments: attachments,
		NewUsername: finalUsername,
		NewPassword: tempPassword,
	}
	data.SupportGroups, _ = s.store.ListSupportGroups()
	s.render(w, "portal_ticket", data)
}

// handlePortalTicketGrantAccess mirrors handleTicketGrantAccess.
func (s *Server) handlePortalTicketGrantAccess(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	ticket, err := s.loadTicket(r, sess)
	if err != nil || ticket == nil || !isAgent(sess) {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		http.Redirect(w, r, "/portal/tickets/"+strconv.FormatInt(ticket.ID, 10), http.StatusSeeOther)
		return
	}

	redirectBack := func() {
		http.Redirect(w, r, "/portal/tickets/"+strconv.FormatInt(ticket.ID, 10), http.StatusSeeOther)
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

// handlePortalTicketTerminateTarget mirrors handleTicketTerminateTarget.
func (s *Server) handlePortalTicketTerminateTarget(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	ticket, err := s.loadTicket(r, sess)
	if err != nil || ticket == nil || !isAgent(sess) {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		http.Redirect(w, r, "/portal/tickets/"+strconv.FormatInt(ticket.ID, 10), http.StatusSeeOther)
		return
	}

	redirectBack := func() {
		http.Redirect(w, r, "/portal/tickets/"+strconv.FormatInt(ticket.ID, 10), http.StatusSeeOther)
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

// PortalApprovalsData backs the portal's own approvals queue —
// admin-only, mirroring /company/approvals, so an admin who lives in
// the portal never has to leave it to sign off a request.
type PortalApprovalsData struct {
	PortalData
	Tickets []store.Ticket
}

func (s *Server) handlePortalApprovalsPage(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	tickets, _ := s.store.ListPendingApprovals()
	s.render(w, "portal_approvals", PortalApprovalsData{
		PortalData: s.portalBaseData(w, r, sess),
		Tickets:    tickets,
	})
}

// handlePortalTicketApproval mirrors handleTicketApproval. Reachable
// only via the admin-only /portal route group (see server.go) — same
// governance boundary as the panel's version.
func (s *Server) handlePortalTicketApproval(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		http.Redirect(w, r, "/portal/tickets/"+strconv.FormatInt(id, 10), http.StatusSeeOther)
		return
	}
	decision := r.FormValue("decision")
	if decision == "approved" || decision == "rejected" {
		_ = s.store.SetTicketApproval(id, decision, sess.UserID)
	}
	http.Redirect(w, r, "/portal/tickets/"+strconv.FormatInt(id, 10), http.StatusSeeOther)
}

// handlePortalAttachmentDownloadPortal serves an attachment; access is
// enforced the same way the ticket itself is (loadTicket), so an agent
// can reach any ticket's files from the portal too, not just their own.
func (s *Server) handlePortalAttachmentDownload(w http.ResponseWriter, r *http.Request) {
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
	attID, err := strconv.ParseInt(chi.URLParam(r, "attachment_id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	att, err := s.store.GetTicketAttachment(attID)
	if err != nil || att == nil || att.TicketID != ticket.ID {
		http.NotFound(w, r)
		return
	}
	path := filepath.Join(ticketAttachmentsDir(s.cfg.DataDir, ticket.ID), att.StoredName)
	w.Header().Set("Content-Disposition", `attachment; filename="`+strings.ReplaceAll(att.OriginalName, `"`, "")+`"`)
	http.ServeFile(w, r, path)
}
