package server

import (
	"net"
	"net/http"
	"strconv"
	"strings"

	"kursor/internal/auth"
	kfw "kursor/internal/firewall"
	ksites "kursor/internal/sites"
	"kursor/internal/store"
)

// PortGroup is CommonPorts pre-grouped for the template — Go templates
// have no "group by" of their own.
type PortGroup struct {
	Name  string
	Ports []kfw.CommonPort
}

func groupedCommonPorts() []PortGroup {
	var groups []PortGroup
	index := map[string]int{}
	for _, p := range kfw.CommonPorts {
		i, ok := index[p.Group]
		if !ok {
			groups = append(groups, PortGroup{Name: p.Group})
			i = len(groups) - 1
			index[p.Group] = i
		}
		groups[i].Ports = append(groups[i].Ports, p)
	}
	return groups
}

func portKey(port int, proto string) string { return proto + ":" + strconv.Itoa(port) }

// PortsData backs the firewall ports page — real ufw/firewalld/iptables
// state (see internal/firewall), queried live, not a mockup.
type PortsData struct {
	PageData
	Backend      string
	UFWInstalled bool
	Rules        []kfw.Rule
	Labels       map[string]string // "proto:port" -> description, see internal/store.GetPortLabels
	CommonGroups []PortGroup
	OpenSet      map[string]bool // "proto:port" already open, for the common-ports grid
	Forwards     []store.PortForward
	FormErrorKey string
	ErrorDetail  string
}

func (s *Server) loadPortsData(w http.ResponseWriter, r *http.Request, sess *store.Session) PortsData {
	backend := kfw.Detect()
	var rules []kfw.Rule
	if backend != kfw.BackendNone {
		rules, _ = kfw.ListRules(backend)
	}
	labels, _ := s.store.GetPortLabels()
	forwards, _ := s.store.ListPortForwards()

	openSet := map[string]bool{}
	for _, ru := range rules {
		openSet[portKey(ru.Port, ru.Proto)] = true
	}

	return PortsData{
		PageData:     s.basePageData(w, r, "network-ports", sess),
		Backend:      string(backend),
		UFWInstalled: kfw.UFWInstalled(),
		Rules:        rules,
		Labels:       labels,
		CommonGroups: groupedCommonPorts(),
		OpenSet:      openSet,
		Forwards:     forwards,
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
	// Never let enabling ufw cut off the panel itself, on top of SSH
	// (which EnableUFW always allows regardless) — whatever port this
	// very request came in on.
	mustAllow := []int{}
	if _, portStr, err := net.SplitHostPort(s.cfg.Addr); err == nil {
		if p, err := strconv.Atoi(portStr); err == nil {
			mustAllow = append(mustAllow, p)
		}
	}
	if err := kfw.EnableUFW(mustAllow); err != nil {
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
	if desc := strings.TrimSpace(r.FormValue("description")); desc != "" {
		_ = s.store.SetPortLabel(port, proto, desc)
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
	_ = s.store.SetPortLabel(port, proto, "")
	http.Redirect(w, r, "/network/ports", http.StatusSeeOther)
}

// handlePortsCloseMany closes every "proto:port" the bulk-select
// checkboxes submitted — best-effort per port, so one bad entry doesn't
// abort the rest; every real error is collected and shown together.
func (s *Server) handlePortsCloseMany(w http.ResponseWriter, r *http.Request) {
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
	backend := kfw.Detect()
	if backend == kfw.BackendNone {
		renderErr("ports.not_detected", "")
		return
	}
	var errs []string
	for _, entry := range r.Form["ports"] {
		proto, portStr, ok := strings.Cut(entry, ":")
		if !ok {
			continue
		}
		port, err := strconv.Atoi(portStr)
		if err != nil || !kfw.ValidPort(port) || !kfw.ValidProto(proto) {
			continue
		}
		if err := kfw.ClosePort(backend, port, proto); err != nil {
			errs = append(errs, entry+": "+err.Error())
			continue
		}
		_ = s.store.SetPortLabel(port, proto, "")
	}
	if len(errs) > 0 {
		renderErr("ports.error.apply", strings.Join(errs, "; "))
		return
	}
	http.Redirect(w, r, "/network/ports", http.StatusSeeOther)
}

// handlePortLabelSet lets an operator add/edit a description for an
// already-open port — purely a Kursor-side annotation (see
// store.SetPortLabel), since ufw/firewalld/iptables don't uniformly
// support arbitrary labels themselves.
func (s *Server) handlePortLabelSet(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	renderErr := func(key string) {
		data := s.loadPortsData(w, r, sess)
		data.FormErrorKey = key
		s.render(w, "network_ports", data)
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		renderErr("login.error.csrf")
		return
	}
	port, err := strconv.Atoi(r.FormValue("port"))
	if err != nil || !kfw.ValidPort(port) {
		renderErr("ports.error.invalid_port")
		return
	}
	proto := r.FormValue("proto")
	if !kfw.ValidProto(proto) {
		renderErr("ports.error.invalid_port")
		return
	}
	_ = s.store.SetPortLabel(port, proto, strings.TrimSpace(r.FormValue("description")))
	http.Redirect(w, r, "/network/ports", http.StatusSeeOther)
}

// handlePortForwardCreate applies a DNAT rule (see internal/firewall's
// AddForward) and records it so the page can list/remove it later.
func (s *Server) handlePortForwardCreate(w http.ResponseWriter, r *http.Request) {
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
	extPort, err := strconv.Atoi(r.FormValue("external_port"))
	if err != nil || !kfw.ValidPort(extPort) {
		renderErr("ports.error.invalid_port", "")
		return
	}
	intPort, err := strconv.Atoi(r.FormValue("internal_port"))
	if err != nil || !kfw.ValidPort(intPort) {
		renderErr("ports.error.invalid_port", "")
		return
	}
	proto := r.FormValue("external_proto")
	if !kfw.ValidProto(proto) {
		renderErr("ports.error.invalid_port", "")
		return
	}
	internalIP := strings.TrimSpace(r.FormValue("internal_ip"))
	if !kfw.ValidInternalIP(internalIP) {
		renderErr("ports.error.invalid_ip", "")
		return
	}
	backend := kfw.Detect()
	if backend == kfw.BackendNone {
		renderErr("ports.not_detected", "")
		return
	}

	forward := kfw.Forward{ExternalPort: extPort, ExternalProto: proto, InternalIP: internalIP, InternalPort: intPort}
	if err := kfw.AddForward(backend, forward); err != nil {
		renderErr("ports.error.forward_apply", err.Error())
		return
	}

	if _, err := s.store.CreatePortForward(store.PortForward{
		ExternalPort:  extPort,
		ExternalProto: proto,
		InternalIP:    internalIP,
		InternalPort:  intPort,
		Description:   strings.TrimSpace(r.FormValue("description")),
	}); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/network/ports", http.StatusSeeOther)
}

func (s *Server) handlePortForwardDelete(w http.ResponseWriter, r *http.Request) {
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
	id, err := strconv.ParseInt(r.FormValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}

	forwards, _ := s.store.ListPortForwards()
	var target *store.PortForward
	for _, f := range forwards {
		if f.ID == id {
			target = &f
			break
		}
	}
	if target == nil {
		http.Redirect(w, r, "/network/ports", http.StatusSeeOther)
		return
	}

	backend := kfw.Detect()
	if backend != kfw.BackendNone {
		_ = kfw.RemoveForward(backend, kfw.Forward{
			ExternalPort:  target.ExternalPort,
			ExternalProto: target.ExternalProto,
			InternalIP:    target.InternalIP,
			InternalPort:  target.InternalPort,
		})
	}
	_ = s.store.DeletePortForward(id)
	http.Redirect(w, r, "/network/ports", http.StatusSeeOther)
}
