// Package server's portal.go: a minimal, sidebar-free experience for
// people who have a Kursor account but no reason to see the rest of
// the panel — "submit and track my own tickets," nothing else. Same
// accounts, same session cookie, same password as the main panel
// (auth.StartSession/CurrentSession are shared) — this is a different
// set of routes and templates over the same login, not a second auth
// system. No self-registration: an account here is still created the
// normal way, by an admin on the Accounts page.
package server

import (
	"net/http"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"kursor/internal/auth"
	"kursor/internal/i18n"
	"kursor/internal/store"
)

// PortalLoginData backs /portal/login.
type PortalLoginData struct {
	Lang      string
	ErrorKey  string
	CSRFToken string
}

func (s *Server) handlePortalLoginPage(w http.ResponseWriter, r *http.Request) {
	if auth.CurrentSession(r, s.store) != nil {
		http.Redirect(w, r, "/portal", http.StatusSeeOther)
		return
	}
	s.render(w, "portal_login", PortalLoginData{Lang: getLang(r), CSRFToken: auth.IssueCSRFToken(w)})
}

func (s *Server) handlePortalLoginSubmit(w http.ResponseWriter, r *http.Request) {
	renderErr := func(key string) {
		s.render(w, "portal_login", PortalLoginData{Lang: getLang(r), ErrorKey: key, CSRFToken: auth.IssueCSRFToken(w)})
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		renderErr("login.error.csrf")
		return
	}
	user, err := s.store.GetUserByUsername(r.FormValue("username"))
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if user == nil || !auth.CheckPassword(user.PasswordHash, r.FormValue("password")) {
		renderErr("login.error.invalid")
		return
	}
	if user.Status != "active" {
		renderErr("login.error.disabled")
		return
	}
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

// PortalData backs the portal's ticket list / new-ticket page.
type PortalData struct {
	Lang         string
	Username     string
	UserInitials string
	CSRFToken    string
	Tickets      []store.Ticket
	Topics       []struct{ Key, LabelKey string }
	FormErrorKey string
}

func (s *Server) portalBaseData(w http.ResponseWriter, r *http.Request, sess *store.Session) PortalData {
	return PortalData{
		Lang:         getLang(r),
		Username:     sess.Username,
		UserInitials: userInitials(sess.Username),
		CSRFToken:    auth.IssueCSRFToken(w),
		Topics:       ticketTopics,
	}
}

func (s *Server) handlePortalPage(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	// Deliberately always "my own tickets" here, even for an agent/admin
	// account browsing the portal — that's the whole point of this
	// surface being separate from /company/servicedesk.
	tickets, _ := s.store.ListTicketsForRequester(sess.UserID)
	data := s.portalBaseData(w, r, sess)
	data.Tickets = tickets
	s.render(w, "portal", data)
}

func (s *Server) handlePortalTicketCreate(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	renderErr := func(key string) {
		data := s.portalBaseData(w, r, sess)
		data.Tickets, _ = s.store.ListTicketsForRequester(sess.UserID)
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
	topic := r.FormValue("topic")
	if !isValidTopic(topic) {
		topic = "other"
	}
	priority := r.FormValue("priority")
	switch priority {
	case "low", "medium", "high", "critical":
	default:
		priority = "medium"
	}

	id, err := s.store.CreateTicket(store.NewTicket{
		Title:       title,
		Description: r.FormValue("description"),
		Type:        "incident",
		Topic:       topic,
		Priority:    priority,
		RequesterID: sess.UserID,
	})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if file, header, ferr := r.FormFile("attachment"); ferr == nil {
		defer file.Close()
		_ = saveTicketAttachment(s.store, s.cfg.DataDir, id, nil, sess.UserID, file, header)
	}
	http.Redirect(w, r, "/portal/tickets/"+strconv.FormatInt(id, 10), http.StatusSeeOther)
}

// PortalTicketData backs the portal's single-ticket view.
type PortalTicketData struct {
	PortalData
	Ticket      store.Ticket
	Comments    []store.TicketComment
	Attachments []store.TicketAttachment
}

// loadPortalTicket enforces the portal's own, stricter access rule:
// only the ticket's own requester, full stop — no agent-sees-everything
// exception the way loadTicket (servicedesk.go) has, since the portal
// is specifically the "just my own stuff" surface.
func (s *Server) loadPortalTicket(r *http.Request, sess *store.Session) (*store.Ticket, error) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		return nil, nil
	}
	t, err := s.store.GetTicket(id)
	if err != nil || t == nil || t.RequesterID != sess.UserID {
		return nil, err
	}
	return t, nil
}

func (s *Server) handlePortalTicketPage(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	ticket, err := s.loadPortalTicket(r, sess)
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
	s.render(w, "portal_ticket", PortalTicketData{
		PortalData:  s.portalBaseData(w, r, sess),
		Ticket:      *ticket,
		Comments:    comments,
		Attachments: attachments,
	})
}

func (s *Server) handlePortalTicketComment(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	ticket, err := s.loadPortalTicket(r, sess)
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
		if ticket.AssigneeID != nil {
			s.notifyUser(*ticket.AssigneeID, "ticket_comment", i18n.T(notifLang, "notif.new_comment_title"), ticket.DisplayID()+" "+ticket.Title, "/company/servicedesk/"+strconv.FormatInt(ticket.ID, 10))
		}
	}
	http.Redirect(w, r, "/portal/tickets/"+strconv.FormatInt(ticket.ID, 10), http.StatusSeeOther)
}

// handleTicketAttachmentDownloadPortal serves an attachment through the
// portal's own stricter access rule — the plain /company/servicedesk/...
// download route (attachments.go) uses loadTicket, which would let an
// agent account reach it too; fine there, wrong assumption to reuse
// for the portal's dedicated URL space.
func (s *Server) handlePortalAttachmentDownload(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	ticket, err := s.loadPortalTicket(r, sess)
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
