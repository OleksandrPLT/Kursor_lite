package server

import (
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"kursor/internal/auth"
	"kursor/internal/i18n"
	"kursor/internal/store"
	"kursor/internal/wildduck"
)

// maxAvatarBytes caps profile photo uploads well under sqlite BLOB
// comfort range — plenty for a small square headshot.
const maxAvatarBytes = 1_500_000

// mailboxPrefixRe mirrors what WildDuck itself accepts for a mailbox
// username (letters/digits/dots/hyphens/underscores) — checked here
// too so a rejected value comes back as a clear Kursor-side message
// instead of a raw WildDuck API error.
var mailboxPrefixRe = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)

var allowedAvatarMimes = map[string]bool{
	"image/png":  true,
	"image/jpeg": true,
	"image/webp": true,
	"image/gif":  true,
}

// allowedPermissions is the whitelist of grantable module keys — see
// migration 0004 and Session.HasModule. "network" covers the DNS/ports/
// VPN placeholders under the Мережа nav group.
var allowedPermissions = map[string]bool{
	"sites":       true,
	"files":       true,
	"databases":   true,
	"network":     true,
	"server":      true,
	"servicedesk": true, // "agent" access: see & triage every ticket, not just your own
}

// AccountsData backs the accounts (team) page: the "account manager"
// module — a single login shared across every connected project, per
// the project plan's phase-2 note. This slice is step one: proper
// multi-user employee profiles inside Kursor itself. Project/client
// registration (OAuth2/OIDC) is the next slice.
type AccountsData struct {
	PageData
	Accounts     []store.User
	Departments  []store.Department
	Positions    []store.Position
	NewUsername  string
	NewPassword  string
	FormErrorKey string

	// MailAvailable gates the "also create a mailbox" checkbox on the
	// create form — hidden entirely when WildDuck isn't configured
	// (internal/wildduck.LoadAPIToken), rather than showing a control
	// that would just fail.
	MailAvailable bool
	MailDomain    string

	// NewMailboxAddress/Password — shown once, right alongside the
	// account's own new credentials, when mailbox creation was
	// requested and succeeded.
	NewMailboxAddress  string
	NewMailboxPassword string
	// MailboxWarning is set instead when the account itself was
	// created fine but provisioning its mailbox failed — the account
	// creation is never rolled back for this, since a working Kursor
	// login is more important than a mailbox that can be added later.
	MailboxWarning string
}

// ProfileData backs the read-only profile detail page for one account.
type ProfileData struct {
	PageData
	Account         store.User
	IsOwnProfile    bool
	MyTickets       []store.Ticket // only populated for IsOwnProfile — "Мої запити"
	MyApprovals     []store.Ticket // only populated for IsOwnProfile admins — "Мої погодження"
	PasswordChanged bool
	FormErrorKey    string
}

// AccountEditData backs the edit-account page.
type AccountEditData struct {
	PageData
	Account       store.User
	Departments   []store.Department
	Positions     []store.Position
	SupportGroups []store.SupportGroup
	SelectedPerm  map[string]bool
	NewPassword   string
	FormErrorKey  string
}

// defaultMailDomain is the one real domain this box's WildDuck mail
// server is currently configured for (see internal/wildduck) — a
// constant for now since there's only ever the one; if a second
// domain is ever added to WildDuck, this becomes a dropdown backed by
// a real list instead of a single hardcoded value.
const defaultMailDomain = "intech.org.ua"

// mailIntegrationStatus reports whether account creation can offer
// "also create a mailbox" — gated on WildDuck actually being
// configured (internal/wildduck.LoadAPIToken), so the checkbox never
// shows up on a box that has no mail server integration wired up.
func (s *Server) mailIntegrationStatus() (available bool, domain string) {
	if _, err := wildduck.LoadAPIToken(s.cfg.DataDir); err != nil {
		return false, ""
	}
	return true, defaultMailDomain
}

func (s *Server) handleAccountsPage(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	accounts, err := s.store.ListUsers()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	departments, _ := s.store.ListDepartments()
	positions, _ := s.store.ListPositions()
	mailAvailable, mailDomain := s.mailIntegrationStatus()
	s.render(w, "accounts", AccountsData{
		PageData:      s.basePageData(w, r, "accounts", sess),
		Accounts:      accounts,
		Departments:   departments,
		Positions:     positions,
		MailAvailable: mailAvailable,
		MailDomain:    mailDomain,
	})
}

// loadProfileData builds the profile page's data for account id — used
// by the plain GET as well as every self-service POST action below, so
// a validation error or the post-password-change confirmation re-renders
// the exact same page rather than a stripped-down copy of it.
func (s *Server) loadProfileData(w http.ResponseWriter, r *http.Request, sess *store.Session, account *store.User) ProfileData {
	data := ProfileData{
		PageData:     s.basePageData(w, r, "accounts", sess),
		Account:      *account,
		IsOwnProfile: sess != nil && sess.UserID == account.ID,
	}
	if data.IsOwnProfile {
		data.MyTickets, _ = s.store.ListTicketsForRequester(account.ID)
		if len(data.MyTickets) > 5 {
			data.MyTickets = data.MyTickets[:5]
		}
		if account.Role == "admin" {
			data.MyApprovals, _ = s.store.ListTicketsApprovedBy(account.ID)
			if len(data.MyApprovals) > 5 {
				data.MyApprovals = data.MyApprovals[:5]
			}
		}
	}
	return data
}

func (s *Server) handleAccountProfile(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	account, err := s.store.GetUserByID(id)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if account == nil {
		http.NotFound(w, r)
		return
	}
	s.render(w, "profile", s.loadProfileData(w, r, sess, account))
}

// handleAccountSelfPassword lets an account change its OWN password —
// the one profile field self-service editing touches directly. Every
// other field goes through handleAccountRequestEdit's ticket instead,
// since those (department transfers, name corrections, ...) need
// someone else to actually act on them, not just a click. Requires the
// CURRENT password, unlike an admin's reset button — so an unattended,
// already-logged-in session sitting open can't be used by whoever
// finds it to lock the real owner out.
func (s *Server) handleAccountSelfPassword(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if sess == nil || sess.UserID != id {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	account, err := s.store.GetUserByID(id)
	if err != nil || account == nil {
		http.NotFound(w, r)
		return
	}
	renderErr := func(key string) {
		data := s.loadProfileData(w, r, sess, account)
		data.FormErrorKey = key
		s.render(w, "profile", data)
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		renderErr("login.error.csrf")
		return
	}
	if !auth.CheckPassword(account.PasswordHash, r.FormValue("current_password")) {
		renderErr("profile.error.wrong_current_password")
		return
	}
	newPassword := r.FormValue("new_password")
	if len(newPassword) < 8 {
		renderErr("profile.error.password_too_short")
		return
	}
	if newPassword != r.FormValue("new_password_confirm") {
		renderErr("profile.error.password_mismatch")
		return
	}
	hash, err := auth.HashPassword(newPassword)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := s.store.ResetPassword(id, hash); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	data := s.loadProfileData(w, r, sess, account)
	data.PasswordChanged = true
	s.render(w, "profile", data)
}

// handleAccountRequestEdit is every OTHER profile change: instead of a
// direct edit, it files a real Service Desk ticket (topic "accounts")
// describing what the person wants changed, so an admin/HR actually
// acts on it — the same "topic -> queue" path every other request
// already goes through, just launched from the profile page instead of
// the Service Desk's own "new ticket" form.
func (s *Server) handleAccountRequestEdit(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if sess == nil || sess.UserID != id {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	account, err := s.store.GetUserByID(id)
	if err != nil || account == nil {
		http.NotFound(w, r)
		return
	}
	renderErr := func(key string) {
		data := s.loadProfileData(w, r, sess, account)
		data.FormErrorKey = key
		s.render(w, "profile", data)
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		renderErr("login.error.csrf")
		return
	}
	details := strings.TrimSpace(r.FormValue("details"))
	if details == "" {
		renderErr("profile.error.details_required")
		return
	}
	ticketID, err := s.store.CreateTicket(store.NewTicket{
		Title:       i18n.T(getLang(r), "profile.edit_request_title"),
		Description: details,
		Type:        "request",
		Topic:       "accounts",
		Priority:    "medium",
		RequesterID: sess.UserID,
	})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/company/servicedesk/"+strconv.FormatInt(ticketID, 10), http.StatusSeeOther)
}

// handleAccountAvatar serves a stored profile photo. Any authenticated
// user can fetch one by id — photos aren't sensitive, and the profile
// page needs to embed them as plain <img> tags.
func (s *Server) handleAccountAvatar(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	data, mime, err := s.store.GetAvatar(id)
	if err != nil || len(data) == 0 {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", mime)
	w.Header().Set("Cache-Control", "private, max-age=300")
	w.Write(data)
}

func (s *Server) handleAccountsCreate(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)

	renderWithError := func(key string) {
		accounts, _ := s.store.ListUsers()
		departments, _ := s.store.ListDepartments()
		positions, _ := s.store.ListPositions()
		mailAvailable, mailDomain := s.mailIntegrationStatus()
		s.render(w, "accounts", AccountsData{
			PageData:      s.basePageData(w, r, "accounts", sess),
			Accounts:      accounts,
			Departments:   departments,
			Positions:     positions,
			MailAvailable: mailAvailable,
			MailDomain:    mailDomain,
			FormErrorKey:  key,
		})
	}

	// 10MB overall cap: form fields are tiny, this is really bounding
	// the avatar file (further capped below to maxAvatarBytes).
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		renderWithError("accounts.error.generic")
		return
	}

	if !auth.ValidCSRF(r) {
		renderWithError("login.error.csrf")
		return
	}

	username := r.FormValue("username")
	if username == "" {
		renderWithError("accounts.error.generic")
		return
	}
	role := r.FormValue("role")
	if role != "admin" && role != "member" {
		role = "member"
	}

	existing, err := s.store.GetUserByUsername(username)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if existing != nil {
		renderWithError("accounts.error.username_taken")
		return
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

	id, err := s.store.CreateUser(store.NewUser{
		Username:     username,
		PasswordHash: hash,
		Email:        r.FormValue("email"),
		Role:         role,
		LastName:     r.FormValue("last_name"),
		FirstName:    r.FormValue("first_name"),
		Patronymic:   r.FormValue("patronymic"),
		JobTitle:     r.FormValue("job_title"),
		Phone:        r.FormValue("phone"),
		HiredAt:      r.FormValue("hired_at"),
		Permissions:  parsePermissions(r.Form["permissions"]),
		DepartmentID: parseOptionalID(r.FormValue("department_id")),
		PositionID:   parseOptionalID(r.FormValue("position_id")),
	})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if file, header, err := r.FormFile("avatar"); err == nil {
		defer file.Close()
		s.saveAvatarIfValid(id, file, header.Size)
	}

	data := AccountsData{
		NewUsername: username,
		NewPassword: tempPassword,
	}
	if strings.TrimSpace(r.FormValue("create_mailbox")) != "" {
		s.provisionMailbox(id, username, r.FormValue("mailbox_prefix"), r.FormValue("first_name"), r.FormValue("last_name"), &data)
	}

	data.PageData = s.basePageData(w, r, "accounts", sess)
	data.Accounts, _ = s.store.ListUsers()
	data.Departments, _ = s.store.ListDepartments()
	data.Positions, _ = s.store.ListPositions()
	data.MailAvailable, data.MailDomain = s.mailIntegrationStatus()
	s.render(w, "accounts", data)
}

// provisionMailbox creates a real WildDuck mailbox for a
// just-created account and ties it to that account
// (store.SetUserMailbox) — best-effort: a failure here is recorded as
// MailboxWarning on data, never as a hard error, since the Kursor
// account itself is already created and working regardless of
// whether its mailbox came along with it. prefix falls back to the
// account's own username when left blank.
func (s *Server) provisionMailbox(userID int64, username, prefix, firstName, lastName string, data *AccountsData) {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		prefix = username
	}
	if !mailboxPrefixRe.MatchString(prefix) {
		data.MailboxWarning = "mail.error.invalid_prefix"
		return
	}

	token, err := wildduck.LoadAPIToken(s.cfg.DataDir)
	if err != nil {
		data.MailboxWarning = "mail.error.not_configured"
		return
	}
	mailboxPassword, err := auth.GenerateTempPassword()
	if err != nil {
		data.MailboxWarning = "accounts.error.generic"
		return
	}
	address := prefix + "@" + defaultMailDomain
	fullName := strings.TrimSpace(firstName + " " + lastName)

	client := wildduck.NewClient("http://127.0.0.1:8080", token)
	mailboxID, err := client.CreateUser(prefix, mailboxPassword, address, fullName)
	if err != nil {
		data.MailboxWarning = "mail.error.create_failed"
		return
	}
	_ = s.store.SetUserMailbox(userID, address, mailboxID)
	data.NewMailboxAddress = address
	data.NewMailboxPassword = mailboxPassword
}

// parsePermissions joins submitted permission checkboxes, keeping only
// whitelisted module keys.
func parsePermissions(values []string) string {
	kept := make([]string, 0, len(values))
	for _, v := range values {
		if allowedPermissions[v] {
			kept = append(kept, v)
		}
	}
	return strings.Join(kept, ",")
}

func parseOptionalID(s string) *int64 {
	if s == "" {
		return nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return nil
	}
	return &n
}

// saveAvatarIfValid reads at most maxAvatarBytes+1 from file, sniffs the
// content type, and stores it only if it's an allowed image format and
// within the size cap. Failures are silent (best-effort — the account is
// still created/updated without a photo) since a bad avatar shouldn't
// block the rest of the action.
func (s *Server) saveAvatarIfValid(userID int64, file io.Reader, declaredSize int64) {
	if declaredSize > maxAvatarBytes {
		return
	}
	data, err := io.ReadAll(io.LimitReader(file, maxAvatarBytes+1))
	if err != nil || len(data) == 0 || len(data) > maxAvatarBytes {
		return
	}
	mime := http.DetectContentType(data)
	if !allowedAvatarMimes[mime] {
		return
	}
	_ = s.store.UpdateAvatar(userID, data, mime)
}

// handleAccountEditPage renders the edit form for an existing account.
func (s *Server) handleAccountEditPage(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	account, err := s.store.GetUserByID(id)
	if err != nil || account == nil {
		http.NotFound(w, r)
		return
	}
	departments, _ := s.store.ListDepartments()
	positions, _ := s.store.ListPositions()
	supportGroups, _ := s.store.ListSupportGroups()

	selected := map[string]bool{}
	for _, p := range account.PermissionsList() {
		selected[p] = true
	}

	s.render(w, "account_edit", AccountEditData{
		PageData:      s.basePageData(w, r, "accounts", sess),
		Account:       *account,
		Departments:   departments,
		Positions:     positions,
		SupportGroups: supportGroups,
		SelectedPerm:  selected,
	})
}

// handleAccountEditSubmit updates every editable field on an account
// (profile info, role, access levels, optional new photo).
func (s *Server) handleAccountEditSubmit(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	account, err := s.store.GetUserByID(id)
	if err != nil || account == nil {
		http.NotFound(w, r)
		return
	}

	renderWithError := func(key string) {
		departments, _ := s.store.ListDepartments()
		positions, _ := s.store.ListPositions()
		supportGroups, _ := s.store.ListSupportGroups()
		selected := map[string]bool{}
		for _, p := range account.PermissionsList() {
			selected[p] = true
		}
		s.render(w, "account_edit", AccountEditData{
			PageData:      s.basePageData(w, r, "accounts", sess),
			Account:       *account,
			Departments:   departments,
			Positions:     positions,
			SupportGroups: supportGroups,
			SelectedPerm:  selected,
			FormErrorKey:  key,
		})
	}

	if err := r.ParseMultipartForm(10 << 20); err != nil {
		renderWithError("accounts.error.generic")
		return
	}
	if !auth.ValidCSRF(r) {
		renderWithError("login.error.csrf")
		return
	}

	role := r.FormValue("role")
	if role != "admin" && role != "member" {
		role = "member"
	}
	// Demoting the last active admin (including demoting yourself) would
	// leave nobody able to administer Kursor — same guard as disable/delete.
	if account.Role == "admin" && role != "admin" {
		if n, err := s.store.CountAdmins(); err != nil || n <= 1 {
			renderWithError("accounts.error.last_admin")
			return
		}
	}

	err = s.store.UpdateProfile(id, store.ProfileUpdate{
		LastName:       r.FormValue("last_name"),
		FirstName:      r.FormValue("first_name"),
		Patronymic:     r.FormValue("patronymic"),
		JobTitle:       r.FormValue("job_title"),
		Phone:          r.FormValue("phone"),
		Email:          r.FormValue("email"),
		HiredAt:        r.FormValue("hired_at"),
		TerminatedAt:   r.FormValue("terminated_at"),
		Role:           role,
		Permissions:    parsePermissions(r.Form["permissions"]),
		DepartmentID:   parseOptionalID(r.FormValue("department_id")),
		PositionID:     parseOptionalID(r.FormValue("position_id")),
		SupportGroupID: parseOptionalID(r.FormValue("support_group_id")),
		Extension:      r.FormValue("extension"),
		ContractNumber: r.FormValue("contract_number"),
	})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if file, header, err := r.FormFile("avatar"); err == nil {
		defer file.Close()
		s.saveAvatarIfValid(id, file, header.Size)
	}

	http.Redirect(w, r, "/accounts/"+strconv.FormatInt(id, 10), http.StatusSeeOther)
}

// handleAccountResetPassword issues a fresh temp password, shown once on
// the edit page — the same pattern as account creation.
func (s *Server) handleAccountResetPassword(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	account, err := s.store.GetUserByID(id)
	if err != nil || account == nil {
		http.NotFound(w, r)
		return
	}
	if !auth.ValidCSRF(r) {
		http.Redirect(w, r, "/accounts/"+strconv.FormatInt(id, 10)+"/edit", http.StatusSeeOther)
		return
	}

	newPassword, err := auth.GenerateTempPassword()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	hash, err := auth.HashPassword(newPassword)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := s.store.ResetPassword(id, hash); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	departments, _ := s.store.ListDepartments()
	positions, _ := s.store.ListPositions()
	selected := map[string]bool{}
	for _, p := range account.PermissionsList() {
		selected[p] = true
	}
	s.render(w, "account_edit", AccountEditData{
		PageData:     s.basePageData(w, r, "accounts", sess),
		Account:      *account,
		Departments:  departments,
		Positions:    positions,
		SelectedPerm: selected,
		NewPassword:  newPassword,
	})
}

func (s *Server) handleAccountStatus(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if !auth.ValidCSRF(r) {
		http.Redirect(w, r, "/accounts", http.StatusSeeOther)
		return
	}

	target, err := s.store.GetUserByID(id)
	if err != nil || target == nil {
		http.Redirect(w, r, "/accounts", http.StatusSeeOther)
		return
	}

	newStatus := "disabled"
	if target.Status == "disabled" {
		newStatus = "active"
	}

	if newStatus == "disabled" && !s.canDeactivate(sess, target) {
		http.Redirect(w, r, "/accounts", http.StatusSeeOther)
		return
	}

	_ = s.store.UpdateUserStatus(id, newStatus)
	http.Redirect(w, r, "/accounts", http.StatusSeeOther)
}

// handleAccountTerminate is the distinct HR action ("звільнити"): records
// today as the last day and disables login, separate from a plain
// enable/disable toggle.
func (s *Server) handleAccountTerminate(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if !auth.ValidCSRF(r) {
		http.Redirect(w, r, "/accounts", http.StatusSeeOther)
		return
	}

	target, err := s.store.GetUserByID(id)
	if err != nil || target == nil || !s.canDeactivate(sess, target) {
		http.Redirect(w, r, "/accounts", http.StatusSeeOther)
		return
	}

	_ = s.store.Terminate(id, time.Now().Format("2006-01-02"))
	http.Redirect(w, r, "/accounts", http.StatusSeeOther)
}

func (s *Server) handleAccountDelete(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if !auth.ValidCSRF(r) {
		http.Redirect(w, r, "/accounts", http.StatusSeeOther)
		return
	}

	target, err := s.store.GetUserByID(id)
	if err != nil || target == nil || !s.canDeactivate(sess, target) {
		http.Redirect(w, r, "/accounts", http.StatusSeeOther)
		return
	}

	_ = s.store.DeleteUser(id)
	http.Redirect(w, r, "/accounts", http.StatusSeeOther)
}

// canDeactivate guards every action that would remove someone's access
// (disable, terminate, delete): never act on your own account, and
// never remove the last active admin — either would lock everyone out.
func (s *Server) canDeactivate(sess *store.Session, target *store.User) bool {
	if target.ID == sess.UserID {
		return false
	}
	if target.Role == "admin" {
		n, err := s.store.CountAdmins()
		if err != nil || n <= 1 {
			return false
		}
	}
	return true
}
