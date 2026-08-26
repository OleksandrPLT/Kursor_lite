// Domains ties Sites, DNS, and SSL together per-domain — the missing
// "one place to attach a real domain today" view: for each domain, a
// live DNS lookup (real net.Resolver calls, done fresh on every page
// load, same as SSL's live x509 parsing) shows whether it currently
// resolves to this server at all, right next to whatever site/cert/DNS
// records already exist for it, plus one-click subdomain creation that
// provisions both the site and its DNS record together.
package server

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"kursor/internal/auth"
	kdns "kursor/internal/dns"
	kmail "kursor/internal/mail" // ValidDomain — same regex, no need to duplicate it a third time
	ksites "kursor/internal/sites"
	"kursor/internal/store"
)

// dnsLookupTimeout keeps a slow/unreachable resolver from ever hanging
// the page — a domain that fails to resolve within this window is
// reported as such, not left spinning.
const dnsLookupTimeout = 4 * time.Second

// DomainDNSCheck is one live lookup result.
type DomainDNSCheck struct {
	ResolvedIPs []string
	Nameservers []string
	PointsHere  bool
	LookupError string
}

func checkDomainDNS(domain, serverIP string) DomainDNSCheck {
	ctx, cancel := context.WithTimeout(context.Background(), dnsLookupTimeout)
	defer cancel()

	var check DomainDNSCheck
	resolver := net.DefaultResolver

	ips, err := resolver.LookupHost(ctx, domain)
	if err != nil {
		check.LookupError = err.Error()
		return check
	}
	check.ResolvedIPs = ips
	for _, ip := range ips {
		if serverIP != "" && ip == serverIP {
			check.PointsHere = true
		}
	}

	nsCtx, nsCancel := context.WithTimeout(context.Background(), dnsLookupTimeout)
	defer nsCancel()
	if ns, err := resolver.LookupNS(nsCtx, domain); err == nil {
		for _, n := range ns {
			check.Nameservers = append(check.Nameservers, strings.TrimSuffix(n.Host, "."))
		}
	}
	return check
}

// belongsToDomain reports whether a DNS record name is the domain
// itself or a subdomain of it (never a substring-match false positive
// like "notexample.com" matching "example.com").
func belongsToDomain(recordName, domain string) bool {
	return recordName == domain || strings.HasSuffix(recordName, "."+domain)
}

// DomainRow pairs a registry entry with its live DNS check and whatever
// Site/SSL/DNS records already exist for it.
type DomainRow struct {
	store.Domain
	DNS             DomainDNSCheck
	LinkedSite      *store.Site
	Cert            ksites.CertStatus
	Records         []store.DNSRecord
	ExpiresDaysLeft int
	HasExpiry       bool
}

// DomainsData backs the Domains page.
type DomainsData struct {
	PageData
	ServerIP     string
	DNSInstalled bool
	Rows         []DomainRow
	FormErrorKey string
	ErrorDetail  string
}

func (s *Server) loadDomainsData(w http.ResponseWriter, r *http.Request, sess *store.Session) DomainsData {
	pageData := s.basePageData(w, r, "network-domains", sess)
	domains, _ := s.store.ListDomains()
	allRecords, _ := s.store.ListDNSRecords()

	rows := make([]DomainRow, 0, len(domains))
	for _, d := range domains {
		row := DomainRow{Domain: d, DNS: checkDomainDNS(d.Domain, pageData.ServerIP)}
		if site, err := s.store.GetSiteByDomain(d.Domain); err == nil && site != nil {
			row.LinkedSite = site
			row.Cert = ksites.GetCertStatus(d.Domain)
		}
		for _, rec := range allRecords {
			if belongsToDomain(rec.Name, d.Domain) {
				row.Records = append(row.Records, rec)
			}
		}
		if d.ExpiresAt != "" {
			if t, err := time.Parse("2006-01-02", d.ExpiresAt); err == nil {
				row.HasExpiry = true
				row.ExpiresDaysLeft = int(time.Until(t).Hours() / 24)
			}
		}
		rows = append(rows, row)
	}

	return DomainsData{
		PageData:     pageData,
		ServerIP:     pageData.ServerIP,
		DNSInstalled: kdns.Detect().Installed,
		Rows:         rows,
	}
}

func (s *Server) handleDomainsPage(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	s.render(w, "network_domains", s.loadDomainsData(w, r, sess))
}

func domainFormFields(r *http.Request) store.DomainUpdate {
	return store.DomainUpdate{
		Registrar:    strings.TrimSpace(r.FormValue("registrar")),
		ExpiresAt:    strings.TrimSpace(r.FormValue("expires_at")),
		AutoRenew:    r.FormValue("auto_renew") == "on",
		Notes:        strings.TrimSpace(r.FormValue("notes")),
		WHOISPrivacy: r.FormValue("whois_privacy") == "on",
		DNSSEC:       r.FormValue("dnssec") == "on",
		ContactEmail: strings.TrimSpace(r.FormValue("contact_email")),
		Tags:         strings.TrimSpace(r.FormValue("tags")),
	}
}

func (s *Server) handleDomainCreate(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	renderErr := func(key string) {
		data := s.loadDomainsData(w, r, sess)
		data.FormErrorKey = key
		s.render(w, "network_domains", data)
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		renderErr("login.error.csrf")
		return
	}
	domain := strings.TrimSpace(r.FormValue("domain"))
	if !kmail.ValidDomain(domain) {
		renderErr("domains.error.invalid_domain")
		return
	}
	u := domainFormFields(r)
	if _, err := s.store.CreateDomain(store.NewDomain{
		Domain:       domain,
		Registrar:    u.Registrar,
		ExpiresAt:    u.ExpiresAt,
		AutoRenew:    u.AutoRenew,
		Notes:        u.Notes,
		WHOISPrivacy: u.WHOISPrivacy,
		DNSSEC:       u.DNSSEC,
		ContactEmail: u.ContactEmail,
		Tags:         u.Tags,
	}); err != nil {
		renderErr("domains.error.duplicate")
		return
	}
	http.Redirect(w, r, "/network/domains", http.StatusSeeOther)
}

func (s *Server) handleDomainUpdate(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		http.Redirect(w, r, "/network/domains", http.StatusSeeOther)
		return
	}
	_ = s.store.UpdateDomain(id, domainFormFields(r))
	http.Redirect(w, r, "/network/domains", http.StatusSeeOther)
}

func (s *Server) handleDomainDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if !auth.ValidCSRF(r) {
		http.Redirect(w, r, "/network/domains", http.StatusSeeOther)
		return
	}
	_ = s.store.DeleteDomain(id)
	http.Redirect(w, r, "/network/domains", http.StatusSeeOther)
}

// handleDomainCreateSubdomain is the "з автоматичними записами" one-shot:
// given a label ("blog") for domain id's "example.com", it creates both
// the Nginx site for blog.example.com (same real ksites.Create path the
// Sites page's own form uses) AND, best-effort, an A record for it in
// Kursor's own DNS (see internal/dns) pointing at this server's IP —
// which only actually affects real-world resolution if this box is the
// domain's delegated nameserver; the page says so next to the button,
// since for a domain whose DNS lives at an external registrar the
// operator still needs to add the same record there.
func (s *Server) handleDomainCreateSubdomain(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	renderErr := func(key, detail string) {
		data := s.loadDomainsData(w, r, sess)
		data.FormErrorKey = key
		data.ErrorDetail = detail
		s.render(w, "network_domains", data)
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		renderErr("login.error.csrf", "")
		return
	}

	domains, _ := s.store.ListDomains()
	var parent string
	for _, d := range domains {
		if d.ID == id {
			parent = d.Domain
			break
		}
	}
	if parent == "" {
		http.Redirect(w, r, "/network/domains", http.StatusSeeOther)
		return
	}

	label := strings.ToLower(strings.TrimSpace(r.FormValue("label")))
	if label == "" || strings.ContainsAny(label, ". \t/@") {
		renderErr("domains.error.invalid_subdomain_label", "")
		return
	}
	fullDomain := label + "." + parent
	if !ksites.ValidDomain(fullDomain) {
		renderErr("sites.error.invalid_domain", "")
		return
	}

	// 1. The site (same path handleSiteCreate uses).
	if existing, err := s.store.GetSiteByDomain(fullDomain); err == nil && existing != nil {
		renderErr("sites.error.duplicate", "")
		return
	}
	result, err := ksites.Create(fullDomain, s.cfg.WWWRoot)
	if err != nil && result.ConfPath == "" {
		renderErr("sites.error.generic", err.Error())
		return
	}
	if _, dbErr := s.store.CreateSite(fullDomain, result.Docroot, result.ConfPath); dbErr != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// 2. The DNS record — best-effort: a site was already created
	// successfully above, so a DNS failure here is a warning, not a
	// reason to undo it.
	pageData := s.basePageData(w, r, "network-domains", sess)
	if pageData.ServerIP != "" {
		if recID, err := s.store.CreateDNSRecord(fullDomain, "A", pageData.ServerIP, 0); err == nil {
			if err := s.applyDNSConfig(); err != nil {
				_ = s.store.DeleteDNSRecord(recID)
			}
		}
	}

	http.Redirect(w, r, "/network/domains", http.StatusSeeOther)
}

// handleDomainAddRecord lets an operator add any DNS record type for a
// domain right from its card, instead of switching to the separate DNS
// page — same validation/apply path as network_dns.html's own form.
func (s *Server) handleDomainAddRecord(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	renderErr := func(key, detail string) {
		data := s.loadDomainsData(w, r, sess)
		data.FormErrorKey = key
		data.ErrorDetail = detail
		s.render(w, "network_domains", data)
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		renderErr("login.error.csrf", "")
		return
	}
	priority, _ := strconv.Atoi(r.FormValue("priority"))
	rec := kdns.Record{
		Name:     strings.TrimSpace(r.FormValue("name")),
		Type:     r.FormValue("type"),
		Value:    strings.TrimSpace(r.FormValue("value")),
		Priority: priority,
	}
	if err := kdns.Validate(rec); err != nil {
		renderErr("dns.error.invalid_record", err.Error())
		return
	}
	recID, err := s.store.CreateDNSRecord(rec.Name, rec.Type, rec.Value, rec.Priority)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := s.applyDNSConfig(); err != nil {
		_ = s.store.DeleteDNSRecord(recID)
		renderErr("dns.error.apply", err.Error())
		return
	}
	http.Redirect(w, r, "/network/domains", http.StatusSeeOther)
}
