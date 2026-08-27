// panelaccess.go: the panel's own IP allow-list — an optional,
// off-by-default restriction on who can even reach the login page and
// everything behind it. Deliberately its own small file since both the
// enforcing middleware (requirePanelIPAllowed) and the settings-page
// handler that edits the list (panelsettings.go) need the exact same
// ipAllowed logic, and it has one safety rule that must never drift
// between the two call sites: loopback is always allowed, so a
// misconfigured list can never lock out someone with shell access to
// the box itself.
package server

import (
	"net"
	"net/http"
	"strings"
)

func isLoopbackIP(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.IsLoopback()
}

// normalizeIPEntry turns a bare IP into a /32 (or /128 for IPv6) so
// net.ParseCIDR accepts it — the settings textarea takes either a bare
// IP or a CIDR range per line/comma, since typing "/32" for a single
// address is a needless speed bump most operators won't expect.
func normalizeIPEntry(entry string) string {
	entry = strings.TrimSpace(entry)
	if entry == "" || strings.Contains(entry, "/") {
		return entry
	}
	if strings.Contains(entry, ":") {
		return entry + "/128"
	}
	return entry + "/32"
}

// splitAllowedIPs parses the stored comma-separated list into its
// individual, trimmed, non-empty entries.
func splitAllowedIPs(raw string) []string {
	var out []string
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ipAllowed is the actual decision: an empty list allows everyone (the
// default, off state), loopback always passes regardless of the list,
// and otherwise ip must fall inside at least one configured CIDR.
func ipAllowed(ip, allowedIPsRaw string) bool {
	if strings.TrimSpace(allowedIPsRaw) == "" {
		return true
	}
	if isLoopbackIP(ip) {
		return true
	}
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	for _, entry := range splitAllowedIPs(allowedIPsRaw) {
		_, cidr, err := net.ParseCIDR(normalizeIPEntry(entry))
		if err != nil {
			continue // an unparsable saved entry is skipped, not a hard failure — see panelsettings.go's own validation on save
		}
		if cidr.Contains(parsedIP) {
			return true
		}
	}
	return false
}

// clientIP extracts the bare IP from a request's RemoteAddr (which
// normally carries "ip:port").
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// requirePanelIPAllowed gates the main panel's login page and its
// entire authenticated surface behind the configured allow-list.
// Deliberately NOT applied to /portal/*, VPN install links, the OIDC
// endpoints, or any other route meant for a different, wider audience
// than "people allowed to administer this box."
func (s *Server) requirePanelIPAllowed(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		settings, err := s.store.GetPanelSettings()
		if err != nil || settings.AllowedIPs == "" {
			next.ServeHTTP(w, r)
			return
		}
		if !ipAllowed(clientIP(r), settings.AllowedIPs) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
