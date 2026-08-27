// panelsettings.go: "Налаштування панелі" — the professional-panel
// settings page real control panels (aaPanel, Plesk, cPanel) all have:
// bind a real domain to reach the panel by (with an actual DNS/NS
// check — "is this domain really pointed at this server" — not just a
// text field), get it a real Let's Encrypt certificate over an Nginx
// reverse proxy, change the panel's own port, and restrict who can
// even reach the login page by IP. Every one of these can go wrong in
// a way that locks the operator out of their own panel, so each action
// below documents its own specific safety rail.
package server

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"kursor/internal/auth"
	kfw "kursor/internal/firewall"
	"kursor/internal/netcheck"
	"kursor/internal/paneladmin"
	ksites "kursor/internal/sites"
	"kursor/internal/store"
)

// PanelSettingsData backs /system/panel-settings.
type PanelSettingsData struct {
	PageData
	Settings     store.PanelSettings
	CurrentPort  int // what the unit file specifies for the NEXT restart — see paneladmin.CurrentPort
	NginxReady   bool
	CertbotReady bool
	CertStatus   ksites.CertStatus

	// Domain check results — populated only right after the "check"
	// action, never on a plain page load (a stale result from an
	// earlier visit would be actively misleading).
	Checked     bool
	PublicIP    string
	ResolvedIPs []string
	PointsHere  bool
	Nameservers []string

	// RestartPending/NewPort/RestartHost — shown once, right after a
	// port change is accepted: the panel is about to restart on a
	// different address, so this response is the last thing rendered at
	// the OLD one.
	RestartPending bool
	NewPort        int
	RestartHost    string

	FormErrorKey string
	ErrorDetail  string
}

func (s *Server) loadPanelSettingsData(w http.ResponseWriter, r *http.Request, sess *store.Session) PanelSettingsData {
	settings, _ := s.store.GetPanelSettings()
	port, _ := paneladmin.CurrentPort()
	data := PanelSettingsData{
		PageData:     s.basePageData(w, r, "system-panel-settings", sess),
		Settings:     settings,
		CurrentPort:  port,
		NginxReady:   ksites.Detect().Ready(),
		CertbotReady: ksites.DetectCertbot(),
	}
	if settings.Domain != "" {
		data.CertStatus = ksites.GetCertStatus(settings.Domain)
	}
	return data
}

func (s *Server) handlePanelSettingsPage(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	s.render(w, "panel_settings", s.loadPanelSettingsData(w, r, sess))
}

// panelLocalAddr turns this running process's own listen address
// (":8888", "0.0.0.0:8888", ...) into a loopback target Nginx can
// reverse-proxy to — the proxy always talks to the SAME machine, so
// whatever interface Kursor bound to, 127.0.0.1:<port> reaches it.
func panelLocalAddr(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		port = "8888"
	}
	return "127.0.0.1:" + port
}

// handlePanelDomainCheck saves the entered domain/contact email and
// runs a real DNS check against it — the explicit "check whether the
// domain is actually pointed at this server" the settings page exists
// for, not a cosmetic text field.
func (s *Server) handlePanelDomainCheck(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	renderErr := func(key, detail string) {
		data := s.loadPanelSettingsData(w, r, sess)
		data.FormErrorKey = key
		data.ErrorDetail = detail
		s.render(w, "panel_settings", data)
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		renderErr("login.error.csrf", "")
		return
	}
	domain := strings.TrimSpace(r.FormValue("domain"))
	email := strings.TrimSpace(r.FormValue("contact_email"))
	if !ksites.ValidDomain(domain) {
		renderErr("panelsettings.error.invalid_domain", "")
		return
	}
	if err := s.store.SetPanelDomain(domain, email); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	data := s.loadPanelSettingsData(w, r, sess)
	data.Checked = true
	if pubIP, err := netcheck.PublicIP(); err == nil {
		data.PublicIP = pubIP
		if points, resolved, err := netcheck.PointsHere(domain, pubIP); err == nil {
			data.PointsHere = points
			data.ResolvedIPs = resolved
		}
	}
	if ns, err := netcheck.ResolveNS(domain); err == nil {
		data.Nameservers = ns
	}
	s.render(w, "panel_settings", data)
}

// handlePanelProxySetup stands up the Nginx reverse proxy for the
// already-saved domain and, once it's actually reachable on port 80,
// issues it a real Let's Encrypt certificate and upgrades the vhost to
// HTTPS. Every step here follows internal/sites' own
// render->validate->reload discipline (see panel_proxy.go) — a failure
// at any point leaves the previous, working state in place rather than
// a half-applied config.
func (s *Server) handlePanelProxySetup(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	renderErr := func(key, detail string) {
		data := s.loadPanelSettingsData(w, r, sess)
		data.FormErrorKey = key
		data.ErrorDetail = detail
		s.render(w, "panel_settings", data)
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		renderErr("login.error.csrf", "")
		return
	}
	settings, err := s.store.GetPanelSettings()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if settings.Domain == "" {
		renderErr("panelsettings.error.no_domain", "")
		return
	}

	panelAddr := panelLocalAddr(s.cfg.Addr)
	challengeRoot := ksites.PanelChallengeRoot(s.cfg.DataDir)

	result, err := ksites.CreatePanelProxyVhost(settings.Domain, panelAddr, challengeRoot)
	if err != nil {
		renderErr("panelsettings.error.proxy_setup", err.Error())
		return
	}
	_ = s.store.SetPanelProxyConfigured(result.ConfPath, false)

	if err := ksites.IssueCertificate(settings.Domain, challengeRoot, settings.ContactEmail); err != nil {
		// The HTTP-only proxy is already live and working (the panel is
		// reachable at http://domain right now) — just no certificate
		// yet. A real, expected failure mode (DNS not fully propagated,
		// rate-limited, port 80 not actually reachable from the
		// internet) worth surfacing plainly rather than papering over.
		renderErr("panelsettings.error.certbot", err.Error())
		return
	}
	if err := ksites.EnablePanelProxySSL(settings.Domain, panelAddr, challengeRoot, result.ConfPath); err != nil {
		renderErr("panelsettings.error.ssl_enable", err.Error())
		return
	}
	_ = s.store.SetPanelProxyConfigured(result.ConfPath, true)

	http.Redirect(w, r, "/system/panel-settings", http.StatusSeeOther)
}

// handlePanelPortChange is the one action on this page that can
// actually interrupt the operator's own connection: changing the port
// kursord listens on requires restarting kursord itself. Safety order,
// same discipline as SSH's own port change (internal/sshadmin):
// open the new port in the firewall FIRST (never touch the currently-
// working one), write the config change, respond with an explicit
// "restarting, reconnect at the new address" page — and only THEN,
// after that response is already on the wire, trigger the actual
// restart from a background goroutine.
func (s *Server) handlePanelPortChange(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	renderErr := func(key, detail string) {
		data := s.loadPanelSettingsData(w, r, sess)
		data.FormErrorKey = key
		data.ErrorDetail = detail
		s.render(w, "panel_settings", data)
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		renderErr("login.error.csrf", "")
		return
	}
	port, err := strconv.Atoi(r.FormValue("port"))
	if err != nil || port < 1 || port > 65535 {
		renderErr("panelsettings.error.invalid_port", "")
		return
	}
	if backend := kfw.Detect(); backend != kfw.BackendNone {
		if err := kfw.OpenPort(backend, port, "tcp"); err != nil {
			renderErr("panelsettings.error.firewall", err.Error())
			return
		}
	}
	if err := paneladmin.SetPort(port); err != nil {
		renderErr("panelsettings.error.port_change", err.Error())
		return
	}

	data := s.loadPanelSettingsData(w, r, sess)
	data.RestartPending = true
	data.NewPort = port
	if host, _, err := net.SplitHostPort(r.Host); err == nil {
		data.RestartHost = host
	} else {
		data.RestartHost = r.Host
	}
	s.render(w, "panel_settings", data)

	// The response above is fully buffered/rendered before this
	// goroutine even starts (html/template.Execute returns before
	// render() returns, and the handler function returns right after) —
	// the extra sleep is just slack for it to actually reach the
	// client's TCP stack before the process restarts out from under it.
	go func() {
		time.Sleep(1500 * time.Millisecond)
		_ = paneladmin.RestartPanel()
	}()
}

// handlePanelAllowedIPsUpdate saves the login IP allow-list. The one
// safety rail that matters here: refuse to save a list that would lock
// out the very request submitting it — every other mistake (a typo'd
// CIDR that's merely useless) is just a validation error, but this one
// would be an operator locking themselves out with no easy way back
// short of shell access to edit the database directly.
func (s *Server) handlePanelAllowedIPsUpdate(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	renderErr := func(key, detail string) {
		data := s.loadPanelSettingsData(w, r, sess)
		data.FormErrorKey = key
		data.ErrorDetail = detail
		s.render(w, "panel_settings", data)
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		renderErr("login.error.csrf", "")
		return
	}
	raw := strings.TrimSpace(r.FormValue("allowed_ips"))
	if raw != "" {
		for _, entry := range splitAllowedIPs(raw) {
			if _, _, err := net.ParseCIDR(normalizeIPEntry(entry)); err != nil {
				renderErr("panelsettings.error.invalid_ip_entry", entry)
				return
			}
		}
		if !ipAllowed(clientIP(r), raw) {
			renderErr("panelsettings.error.would_lock_out", clientIP(r))
			return
		}
	}
	if err := s.store.SetPanelAllowedIPs(raw); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/system/panel-settings", http.StatusSeeOther)
}
