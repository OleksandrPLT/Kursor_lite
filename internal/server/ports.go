package server

import (
	"net/http"
	"strconv"

	"kursor/internal/auth"
	kfw "kursor/internal/firewall"
	ksites "kursor/internal/sites"
	"kursor/internal/store"
)

// PortsData backs the firewall ports page — real ufw/firewalld state
// (see internal/firewall), queried live, not a mockup.
type PortsData struct {
	PageData
	Backend      string
	UFWInstalled bool
	Rules        []kfw.Rule
	FormErrorKey string
	ErrorDetail  string
}

func (s *Server) loadPortsData(w http.ResponseWriter, r *http.Request, sess *store.Session) PortsData {
	backend := kfw.Detect()
	var rules []kfw.Rule
	if backend != kfw.BackendNone {
		rules, _ = kfw.ListRules(backend)
	}
	return PortsData{
		PageData:     s.basePageData(w, r, "network-ports", sess),
		Backend:      string(backend),
		UFWInstalled: kfw.UFWInstalled(),
		Rules:        rules,
	}
}

func (s *Server) handlePortsPage(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	s.render(w, "network_ports", s.loadPortsData(w, r, sess))
}

func (s *Server) handlePortsInstallUFW(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	renderErr := func(key, detail string) {
		data := s.loadPortsData(w, r, sess)
		data.FormErrorKey = key
		data.ErrorDetail = detail
		s.render(w, "network_ports", data)
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		renderErr("login.error.csrf", "")
		return
	}
	if out, err := ksites.InstallPackage("ufw"); err != nil {
		renderErr("ports.error.install", out)
		return
	}
	http.Redirect(w, r, "/network/ports", http.StatusSeeOther)
}

func (s *Server) handlePortsEnableUFW(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	renderErr := func(key, detail string) {
		data := s.loadPortsData(w, r, sess)
		data.FormErrorKey = key
		data.ErrorDetail = detail
		s.render(w, "network_ports", data)
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		renderErr("login.error.csrf", "")
		return
	}
	if err := kfw.EnableUFW(); err != nil {
		renderErr("ports.error.enable", err.Error())
		return
	}
	http.Redirect(w, r, "/network/ports", http.StatusSeeOther)
}

func (s *Server) handlePortOpen(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	renderErr := func(key, detail string) {
		data := s.loadPortsData(w, r, sess)
		data.FormErrorKey = key
		data.ErrorDetail = detail
		s.render(w, "network_ports", data)
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		renderErr("login.error.csrf", "")
		return
	}
	port, err := strconv.Atoi(r.FormValue("port"))
	if err != nil || !kfw.ValidPort(port) {
		renderErr("ports.error.invalid_port", "")
		return
	}
	proto := r.FormValue("proto")
	if !kfw.ValidProto(proto) {
		renderErr("ports.error.invalid_port", "")
		return
	}
	backend := kfw.Detect()
	if backend == kfw.BackendNone {
		renderErr("ports.not_detected", "")
		return
	}
	if err := kfw.OpenPort(backend, port, proto); err != nil {
		renderErr("ports.error.apply", err.Error())
		return
	}
	http.Redirect(w, r, "/network/ports", http.StatusSeeOther)
}

func (s *Server) handlePortClose(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	renderErr := func(key, detail string) {
		data := s.loadPortsData(w, r, sess)
		data.FormErrorKey = key
		data.ErrorDetail = detail
		s.render(w, "network_ports", data)
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		renderErr("login.error.csrf", "")
		return
	}
	port, err := strconv.Atoi(r.FormValue("port"))
	if err != nil || !kfw.ValidPort(port) {
		renderErr("ports.error.invalid_port", "")
		return
	}
	proto := r.FormValue("proto")
	if !kfw.ValidProto(proto) {
		renderErr("ports.error.invalid_port", "")
		return
	}
	backend := kfw.Detect()
	if backend == kfw.BackendNone {
		renderErr("ports.not_detected", "")
		return
	}
	if err := kfw.ClosePort(backend, port, proto); err != nil {
		renderErr("ports.error.apply", err.Error())
		return
	}
	http.Redirect(w, r, "/network/ports", http.StatusSeeOther)
}
