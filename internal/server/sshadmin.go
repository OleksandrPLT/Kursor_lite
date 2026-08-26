package server

import (
	"net/http"
	"strconv"
	"strings"

	"kursor/internal/auth"
	kfw "kursor/internal/firewall"
	kssh "kursor/internal/sshadmin"
	"kursor/internal/store"
)

// sshTargetUser is whose authorized_keys/login this page manages — root,
// since kursord itself runs as root and that's the account real SSH
// access to this box actually uses (same root-mode trade-off documented
// for every other host-level module).
const sshTargetUser = "root"

// SSHData backs the SSH page.
type SSHData struct {
	PageData
	Config       kssh.Config
	Keys         []kssh.AuthorizedKey
	FormErrorKey string
	ErrorDetail  string
}

func (s *Server) loadSSHData(w http.ResponseWriter, r *http.Request, sess *store.Session) SSHData {
	cfg, _ := kssh.GetConfig()
	keys, _ := kssh.ListAuthorizedKeys(sshTargetUser)
	return SSHData{
		PageData: s.basePageData(w, r, "network-ssh", sess),
		Config:   cfg,
		Keys:     keys,
	}
}

func (s *Server) handleSSHPage(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	s.render(w, "network_ssh", s.loadSSHData(w, r, sess))
}

func (s *Server) handleSSHKeyAdd(w http.ResponseWriter, r *http.Request) {
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
	if err := kssh.AddAuthorizedKey(sshTargetUser, r.FormValue("public_key")); err != nil {
		renderErr("sshadmin.error.add_key", err.Error())
		return
	}
	http.Redirect(w, r, "/network/ssh", http.StatusSeeOther)
}

func (s *Server) handleSSHKeyDelete(w http.ResponseWriter, r *http.Request) {
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
	if err := kssh.RemoveAuthorizedKey(sshTargetUser, r.FormValue("raw")); err != nil {
		renderErr("sshadmin.error.remove_key", err.Error())
		return
	}
	http.Redirect(w, r, "/network/ssh", http.StatusSeeOther)
}

// handleSSHPortUpdate opens the new port in whatever firewall backend
// is active *before* touching sshd_config — so a config change that
// succeeds never leaves the operator unable to actually reach the new
// port. The old port is deliberately left open too; closing it is a
// separate, manual step once the operator has confirmed the new one
// works (see the page's own hint text).
func (s *Server) handleSSHPortUpdate(w http.ResponseWriter, r *http.Request) {
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
	port, err := strconv.Atoi(r.FormValue("port"))
	if err != nil || port < 1 || port > 65535 {
		renderErr("sshadmin.error.invalid_port", "")
		return
	}
	if backend := kfw.Detect(); backend != kfw.BackendNone {
		if err := kfw.OpenPort(backend, port, "tcp"); err != nil {
			renderErr("sshadmin.error.firewall", err.Error())
			return
		}
	}
	if err := kssh.SetPort(port); err != nil {
		renderErr("sshadmin.error.apply", err.Error())
		return
	}
	http.Redirect(w, r, "/network/ssh", http.StatusSeeOther)
}

func (s *Server) handleSSHPasswordAuthUpdate(w http.ResponseWriter, r *http.Request) {
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
	enabled := strings.TrimSpace(r.FormValue("enabled")) == "on"
	if err := kssh.SetPasswordAuth(enabled, sshTargetUser); err != nil {
		renderErr("sshadmin.error.apply", err.Error())
		return
	}
	http.Redirect(w, r, "/network/ssh", http.StatusSeeOther)
}
