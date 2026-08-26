package server

import (
	"net/http"
	"strings"

	"kursor/internal/auth"
	ksys "kursor/internal/sysusers"
)

// handleSysUserCreate adds a real system account and shows its
// generated password once — same one-time-reveal discipline as every
// other "here's a temp password" flow in this codebase.
func (s *Server) handleSysUserCreate(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	renderErr := func(key, detail string) {
		data := s.loadSSHData(w, r, sess)
		data.FormErrorKey = key
		data.ErrorDetail = detail
		s.render(w, "network_ssh", data)
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		renderErr("login.error.csrf", "")
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	if !ksys.ValidUsername(username) {
		renderErr("sysusers.error.invalid_username", "")
		return
	}
	tempPassword, err := auth.GenerateTempPassword()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := ksys.CreateSystemUser(username, tempPassword); err != nil {
		renderErr("sysusers.error.create", err.Error())
		return
	}
	data := s.loadSSHData(w, r, sess)
	data.NewSysUsername = username
	data.NewSysPassword = tempPassword
	s.render(w, "network_ssh", data)
}

func (s *Server) handleSysUserResetPassword(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	renderErr := func(key, detail string) {
		data := s.loadSSHData(w, r, sess)
		data.FormErrorKey = key
		data.ErrorDetail = detail
		s.render(w, "network_ssh", data)
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		renderErr("login.error.csrf", "")
		return
	}
	username := r.FormValue("username")
	if !ksys.ValidUsername(username) {
		renderErr("sysusers.error.invalid_username", "")
		return
	}
	tempPassword, err := auth.GenerateTempPassword()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := ksys.ResetPassword(username, tempPassword); err != nil {
		renderErr("sysusers.error.reset", err.Error())
		return
	}
	data := s.loadSSHData(w, r, sess)
	data.NewSysUsername = username
	data.NewSysPassword = tempPassword
	s.render(w, "network_ssh", data)
}

func (s *Server) handleSysUserLock(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	renderErr := func(key, detail string) {
		data := s.loadSSHData(w, r, sess)
		data.FormErrorKey = key
		data.ErrorDetail = detail
		s.render(w, "network_ssh", data)
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		renderErr("login.error.csrf", "")
		return
	}
	username := r.FormValue("username")
	var err error
	if r.FormValue("action") == "unlock" {
		err = ksys.Unlock(username)
	} else {
		err = ksys.Lock(username)
	}
	if err != nil {
		renderErr("sysusers.error.lock", err.Error())
		return
	}
	http.Redirect(w, r, "/network/ssh", http.StatusSeeOther)
}
