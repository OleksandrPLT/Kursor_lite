package server

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"kursor/internal/auth"
	kmail "kursor/internal/mail"
	ksites "kursor/internal/sites"
	"kursor/internal/store"
)

// MailData backs the Mail page — real Postfix/Dovecot virtual mail (see
// internal/mail), not a mockup.
type MailData struct {
	PageData
	PostfixInstalled bool
	DovecotInstalled bool
	Domains          []store.MailDomain
	Mailboxes        []store.MailMailbox
	NewMailboxAddr   string
	NewMailboxPass   string // shown once, right after creation
	FormErrorKey     string
	ErrorDetail      string
}

func (s *Server) loadMailData(w http.ResponseWriter, r *http.Request, sess *store.Session) MailData {
	domains, _ := s.store.ListMailDomains()
	mailboxes, _ := s.store.ListMailboxes()
	status := kmail.Detect()
	return MailData{
		PageData:         s.basePageData(w, r, "company-mail", sess),
		PostfixInstalled: status.PostfixInstalled,
		DovecotInstalled: status.DovecotInstalled,
		Domains:          domains,
		Mailboxes:        mailboxes,
	}
}

func (s *Server) handleMailPage(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	s.render(w, "mail", s.loadMailData(w, r, sess))
}

func (s *Server) handleMailInstall(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	renderErr := func(key, detail string) {
		data := s.loadMailData(w, r, sess)
		data.FormErrorKey = key
		data.ErrorDetail = detail
		s.render(w, "mail", data)
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		renderErr("login.error.csrf", "")
		return
	}
	pkg := r.FormValue("package")
	if pkg != "postfix" && pkg != "dovecot-imapd" {
		renderErr("mail.error.unknown_package", "")
		return
	}
	if out, err := ksites.InstallPackage(pkg); err != nil {
		renderErr("mail.error.install", out)
		return
	}
	http.Redirect(w, r, "/company/mail", http.StatusSeeOther)
}

// applyMail regenerates every Postfix/Dovecot file from the current DB
// state and reloads both — always the full set, same discipline as
// every other apply* helper in this codebase.
func (s *Server) applyMail() error {
	domains, err := s.store.ListMailDomains()
	if err != nil {
		return err
	}
	dbMailboxes, err := s.store.ListMailboxes()
	if err != nil {
		return err
	}
	domainNames := make([]string, 0, len(domains))
	for _, d := range domains {
		domainNames = append(domainNames, d.Domain)
	}
	mailboxes := make([]kmail.Mailbox, 0, len(dbMailboxes))
	for _, m := range dbMailboxes {
		mailboxes = append(mailboxes, kmail.Mailbox{Address: m.Address, PasswordHash: m.PasswordHash})
	}
	if err := kmail.ApplyPostfix(domainNames, mailboxes); err != nil {
		return err
	}

	masterPassword, err := kmail.LoadOrGenerateMasterPassword(s.cfg.DataDir)
	if err != nil {
		return err
	}
	masterHash, err := kmail.HashPassword(masterPassword)
	if err != nil {
		return err
	}
	return kmail.ApplyDovecot(mailboxes, masterHash)
}

func (s *Server) handleMailDomainCreate(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	renderErr := func(key, detail string) {
		data := s.loadMailData(w, r, sess)
		data.FormErrorKey = key
		data.ErrorDetail = detail
		s.render(w, "mail", data)
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		renderErr("login.error.csrf", "")
		return
	}
	domain := strings.TrimSpace(r.FormValue("domain"))
	if !kmail.ValidDomain(domain) {
		renderErr("mail.error.invalid_domain", "")
		return
	}
	id, err := s.store.CreateMailDomain(domain)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := s.applyMail(); err != nil {
		_ = s.store.DeleteMailDomain(id)
		renderErr("mail.error.apply", err.Error())
		return
	}
	http.Redirect(w, r, "/company/mail", http.StatusSeeOther)
}

func (s *Server) handleMailDomainDelete(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if !auth.ValidCSRF(r) {
		http.Redirect(w, r, "/company/mail", http.StatusSeeOther)
		return
	}
	_ = s.store.DeleteMailDomain(id)
	if err := s.applyMail(); err != nil {
		data := s.loadMailData(w, r, sess)
		data.FormErrorKey = "mail.error.apply"
		data.ErrorDetail = err.Error()
		s.render(w, "mail", data)
		return
	}
	http.Redirect(w, r, "/company/mail", http.StatusSeeOther)
}

// handleMailboxCreate generates a temporary password (shown once, same
// discipline as a ticket-created account) and hashes it via
// internal/mail.HashPassword (a real `doveadm pw` call — never stored
// as plaintext, and this handler doesn't keep a copy either).
func (s *Server) handleMailboxCreate(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	renderErr := func(key, detail string) {
		data := s.loadMailData(w, r, sess)
		data.FormErrorKey = key
		data.ErrorDetail = detail
		s.render(w, "mail", data)
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		renderErr("login.error.csrf", "")
		return
	}
	address := strings.TrimSpace(r.FormValue("address"))
	if !kmail.ValidAddress(address) {
		renderErr("mail.error.invalid_address", "")
		return
	}

	tempPassword, err := auth.GenerateTempPassword()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	hash, err := kmail.HashPassword(tempPassword)
	if err != nil {
		renderErr("mail.error.dovecot_required", err.Error())
		return
	}

	id, err := s.store.CreateMailbox(address, hash)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := s.applyMail(); err != nil {
		_ = s.store.DeleteMailbox(id)
		renderErr("mail.error.apply", err.Error())
		return
	}

	data := s.loadMailData(w, r, sess)
	data.NewMailboxAddr = address
	data.NewMailboxPass = tempPassword
	s.render(w, "mail", data)
}

func (s *Server) handleMailboxDelete(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if !auth.ValidCSRF(r) {
		http.Redirect(w, r, "/company/mail", http.StatusSeeOther)
		return
	}
	_ = s.store.DeleteMailbox(id)
	if err := s.applyMail(); err != nil {
		data := s.loadMailData(w, r, sess)
		data.FormErrorKey = "mail.error.apply"
		data.ErrorDetail = err.Error()
		s.render(w, "mail", data)
		return
	}
	http.Redirect(w, r, "/company/mail", http.StatusSeeOther)
}

// handleMailboxResetPassword generates a fresh temp password for an
// existing mailbox — same one-time-reveal pattern as creation.
func (s *Server) handleMailboxResetPassword(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	renderErr := func(key, detail string) {
		data := s.loadMailData(w, r, sess)
		data.FormErrorKey = key
		data.ErrorDetail = detail
		s.render(w, "mail", data)
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		renderErr("login.error.csrf", "")
		return
	}

	mailboxes, _ := s.store.ListMailboxes()
	var address string
	for _, m := range mailboxes {
		if m.ID == id {
			address = m.Address
			break
		}
	}
	if address == "" {
		http.Redirect(w, r, "/company/mail", http.StatusSeeOther)
		return
	}

	tempPassword, err := auth.GenerateTempPassword()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	hash, err := kmail.HashPassword(tempPassword)
	if err != nil {
		renderErr("mail.error.dovecot_required", err.Error())
		return
	}
	if err := s.store.SetMailboxPassword(id, hash); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := s.applyMail(); err != nil {
		renderErr("mail.error.apply", err.Error())
		return
	}

	data := s.loadMailData(w, r, sess)
	data.NewMailboxAddr = address
	data.NewMailboxPass = tempPassword
	s.render(w, "mail", data)
}

func (s *Server) findMailbox(id int64) *store.MailMailbox {
	mailboxes, _ := s.store.ListMailboxes()
	for _, m := range mailboxes {
		if m.ID == id {
			return &m
		}
	}
	return nil
}

// InboxData backs the mailbox inbox viewer — a real IMAP session via
// Dovecot's master-user login (see internal/mail.FetchInbox), not a
// mock. Deliberately minimal: newest 25 messages, envelope only.
type InboxData struct {
	PageData
	Mailbox   store.MailMailbox
	Messages  []kmail.InboxMessage
	LoadError string
}

// handleMailboxInbox lists a mailbox's most recent INBOX messages —
// "so can I actually look at the mailbox" made real.
func (s *Server) handleMailboxInbox(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	mailbox := s.findMailbox(id)
	if mailbox == nil {
		http.NotFound(w, r)
		return
	}

	data := InboxData{
		PageData: s.basePageData(w, r, "company-mail", sess),
		Mailbox:  *mailbox,
	}
	masterPassword, err := kmail.LoadOrGenerateMasterPassword(s.cfg.DataDir)
	if err != nil {
		data.LoadError = err.Error()
		s.render(w, "mail_inbox", data)
		return
	}
	messages, err := kmail.FetchInbox(mailbox.Address, masterPassword, 25)
	if err != nil {
		data.LoadError = err.Error()
		s.render(w, "mail_inbox", data)
		return
	}
	data.Messages = messages
	s.render(w, "mail_inbox", data)
}

// MessageData backs the single-message viewer.
type MessageData struct {
	PageData
	Mailbox   store.MailMailbox
	UID       uint32
	Raw       string
	LoadError string
}

func (s *Server) handleMailboxMessage(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	uid64, err := strconv.ParseUint(chi.URLParam(r, "uid"), 10, 32)
	if err != nil {
		http.Error(w, "bad uid", http.StatusBadRequest)
		return
	}
	mailbox := s.findMailbox(id)
	if mailbox == nil {
		http.NotFound(w, r)
		return
	}

	data := MessageData{
		PageData: s.basePageData(w, r, "company-mail", sess),
		Mailbox:  *mailbox,
		UID:      uint32(uid64),
	}
	masterPassword, err := kmail.LoadOrGenerateMasterPassword(s.cfg.DataDir)
	if err != nil {
		data.LoadError = err.Error()
		s.render(w, "mail_message", data)
		return
	}
	raw, err := kmail.FetchMessageRaw(mailbox.Address, masterPassword, uint32(uid64))
	if err != nil {
		data.LoadError = err.Error()
		s.render(w, "mail_message", data)
		return
	}
	data.Raw = raw
	s.render(w, "mail_message", data)
}
