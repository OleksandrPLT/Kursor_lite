package server

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"kursor/internal/auth"
	"kursor/internal/store"
)

// maxAvatarBytes caps profile photo uploads well under sqlite BLOB
// comfort range — plenty for a small square headshot.
const maxAvatarBytes = 1_500_000

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
}

// ProfileData backs the read-only profile detail page for one account.
type ProfileData struct {
	PageData
	Account store.User
}

// AccountEditData backs the edit-account page.
type AccountEditData struct {
	PageData
	Account      store.User
	Departments  []store.Department
	Positions    []store.Position
	SelectedPerm map[string]bool
	NewPassword  string
	FormErrorKey string
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
	s.render(w, "accounts", AccountsData{
		PageData:    s.basePageData(w, r, "accounts", sess),
		Accounts:    accounts,
		Departments: departments,
		Positions:   positions,
	})
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
	s.render(w, "profile", ProfileData{
		PageData: s.basePageData(w, r, "accounts", sess),
		Account:  *account,
	})
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
		s.render(w, "accounts", AccountsData{
			PageData:     s.basePageData(w, r, "accounts", sess),
			Accounts:     accounts,
			Departments:  departments,
			Positions:    positions,
			FormErrorKey: key,
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

	accounts, _ := s.store.ListUsers()
	departments, _ := s.store.ListDepartments()
	positions, _ := s.store.ListPositions()
	s.render(w, "accounts", AccountsData{
		PageData:    s.basePageData(w, r, "accounts", sess),
		Accounts:    accounts,
		Departments: departments,
		Positions:   positions,
		NewUsername: username,
		NewPassword: tempPassword,
	})
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
			FormErrorKey: key,
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
		LastName:     r.FormValue("last_name"),
		FirstName:    r.FormValue("first_name"),
		Patronymic:   r.FormValue("patronymic"),
		JobTitle:     r.FormValue("job_title"),
		Phone:        r.FormValue("phone"),
		Email:        r.FormValue("email"),
		HiredAt:      r.FormValue("hired_at"),
		TerminatedAt: r.FormValue("terminated_at"),
		Role:         role,
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
