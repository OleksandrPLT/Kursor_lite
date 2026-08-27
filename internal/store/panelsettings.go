package store

// PanelSettings is the single-row (id=1) configuration for the panel's
// own access — a real bound domain (reverse-proxied through Nginx with
// its own Let's Encrypt cert, see internal/sites/panel_proxy.go), and
// an optional IP allow-list for the login/authenticated surface.
type PanelSettings struct {
	Domain        string
	ContactEmail  string
	ProxyConfPath string
	SSLEnabled    bool
	AllowedIPs    string // comma-separated CIDRs/IPs; empty = allow all
}

func (s *Store) GetPanelSettings() (PanelSettings, error) {
	var p PanelSettings
	var sslEnabled int
	err := s.db.QueryRow(`SELECT domain, contact_email, proxy_conf_path, ssl_enabled, allowed_ips FROM panel_settings WHERE id = 1`).
		Scan(&p.Domain, &p.ContactEmail, &p.ProxyConfPath, &sslEnabled, &p.AllowedIPs)
	p.SSLEnabled = sslEnabled != 0
	return p, err
}

// SetPanelDomain records the domain the admin intends to reach the
// panel by, before anything (proxy, cert) has actually been set up for
// it — the domain-check step needs somewhere to remember what was
// entered between "check" and "set up."
func (s *Store) SetPanelDomain(domain, contactEmail string) error {
	_, err := s.db.Exec(`UPDATE panel_settings SET domain = ?, contact_email = ? WHERE id = 1`, domain, contactEmail)
	return err
}

// SetPanelProxyConfigured records that the reverse-proxy vhost (and,
// once sslEnabled, its Let's Encrypt cert) is live for the current
// domain.
func (s *Store) SetPanelProxyConfigured(confPath string, sslEnabled bool) error {
	e := 0
	if sslEnabled {
		e = 1
	}
	_, err := s.db.Exec(`UPDATE panel_settings SET proxy_conf_path = ?, ssl_enabled = ? WHERE id = 1`, confPath, e)
	return err
}

// SetPanelAllowedIPs updates the login IP allow-list. Validating that
// the saving admin's own request would still be allowed is the
// caller's job (internal/server/panelsettings.go) — this is pure
// storage.
func (s *Store) SetPanelAllowedIPs(allowedIPs string) error {
	_, err := s.db.Exec(`UPDATE panel_settings SET allowed_ips = ? WHERE id = 1`, allowedIPs)
	return err
}
