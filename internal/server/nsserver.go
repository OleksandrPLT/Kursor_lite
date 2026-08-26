// NS Server: a real authoritative DNS server (PowerDNS) for domains
// that get their own custom nameservers pointed at this box — distinct
// from the existing DNS page (dnsmasq), which is a lightweight LAN/VPN
// resolver, not something a registrar's NS delegation can rely on.
package server

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"kursor/internal/auth"
	kpdns "kursor/internal/powerdns"
	ksites "kursor/internal/sites"
	"kursor/internal/store"
)

// NSZoneRow pairs a PowerDNS zone with its flattened record list.
type NSZoneRow struct {
	Domain  string
	Records []kpdns.Record
}

// NSServerData backs the NS Server page.
type NSServerData struct {
	PageData
	Installed    bool
	ServerIP     string
	SuggestedNS1 string
	SuggestedNS2 string
	Zones        []NSZoneRow
	FormErrorKey string
	ErrorDetail  string
}

func (s *Server) loadNSServerData(w http.ResponseWriter, r *http.Request, sess *store.Session) NSServerData {
	pageData := s.basePageData(w, r, "network-nsserver", sess)
	data := NSServerData{
		PageData:  pageData,
		Installed: kpdns.Detect().Installed,
		ServerIP:  pageData.ServerIP,
	}
	if !data.Installed {
		return data
	}
	apiKey, err := kpdns.LoadOrGenerateAPIKey(s.cfg.DataDir)
	if err != nil {
		data.ErrorDetail = err.Error()
		return data
	}
	zones, err := kpdns.ListZones(apiKey)
	if err != nil {
		// Configured but not reachable (e.g. never started yet) — not a
		// fatal page error, just an empty zone list; the "create zone"
		// flow below calls EnsureConfigured itself before first use.
		return data
	}
	for _, z := range zones {
		domain := strings.TrimSuffix(z.Name, ".")
		records, _ := kpdns.ListRecords(apiKey, domain)
		data.Zones = append(data.Zones, NSZoneRow{Domain: domain, Records: records})
	}
	return data
}

func (s *Server) handleNSServerPage(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	s.render(w, "network_nsserver", s.loadNSServerData(w, r, sess))
}

func (s *Server) handleNSServerInstall(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	renderErr := func(key, detail string) {
		data := s.loadNSServerData(w, r, sess)
		data.FormErrorKey = key
		data.ErrorDetail = detail
		s.render(w, "network_nsserver", data)
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		renderErr("login.error.csrf", "")
		return
	}
	if out, err := ksites.InstallPackage("pdns-server"); err != nil {
		renderErr("nsserver.error.install", out)
		return
	}
	if out, err := ksites.InstallPackage("pdns-backend-sqlite3"); err != nil {
		renderErr("nsserver.error.install", out)
		return
	}
	http.Redirect(w, r, "/network/nsserver", http.StatusSeeOther)
}

// handleNSServerZoneCreate provisions a new zone: SOA+NS records via
// PowerDNS's own zone-creation, plus the "glue" A records the two
// suggested nameserver hostnames need within the zone itself, plus a
// convenience apex A record pointing at this server.
func (s *Server) handleNSServerZoneCreate(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	renderErr := func(key, detail string) {
		data := s.loadNSServerData(w, r, sess)
		data.FormErrorKey = key
		data.ErrorDetail = detail
		s.render(w, "network_nsserver", data)
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		renderErr("login.error.csrf", "")
		return
	}
	domain := strings.ToLower(strings.TrimSpace(r.FormValue("domain")))
	if !kpdns.ValidDomain(domain) {
		renderErr("nsserver.error.invalid_domain", "")
		return
	}

	if err := kpdns.EnsureConfigured(s.cfg.DataDir); err != nil {
		renderErr("nsserver.error.apply", err.Error())
		return
	}
	apiKey, err := kpdns.LoadOrGenerateAPIKey(s.cfg.DataDir)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	ns1, ns2 := "ns1."+domain, "ns2."+domain
	if err := kpdns.CreateZone(apiKey, domain, []string{ns1, ns2}); err != nil {
		renderErr("nsserver.error.apply", err.Error())
		return
	}

	// PowerDNS's own zone-creation default SOA names a placeholder
	// primary ("a.misconfigured.dns.server.invalid.") — replace it with
	// this zone's real primary NS right away, since some registrars/
	// resolvers validate SOA content more strictly than just "present".
	soa := fmt.Sprintf("%s hostmaster.%s %s 10800 3600 604800 3600", ns1, domain, time.Now().UTC().Format("20060102")+"01")
	_ = kpdns.UpsertRecord(apiKey, domain, domain, "SOA", 3600, soa)

	pageData := s.basePageData(w, r, "network-nsserver", sess)
	serverIP := pageData.ServerIP
	if serverIP != "" {
		_ = kpdns.UpsertRecord(apiKey, domain, ns1, "A", 3600, serverIP)
		_ = kpdns.UpsertRecord(apiKey, domain, ns2, "A", 3600, serverIP)
		_ = kpdns.UpsertRecord(apiKey, domain, domain, "A", 3600, serverIP)
	}

	http.Redirect(w, r, "/network/nsserver", http.StatusSeeOther)
}

func (s *Server) handleNSServerZoneDelete(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	renderErr := func(key, detail string) {
		data := s.loadNSServerData(w, r, sess)
		data.FormErrorKey = key
		data.ErrorDetail = detail
		s.render(w, "network_nsserver", data)
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		renderErr("login.error.csrf", "")
		return
	}
	domain := r.FormValue("domain")
	apiKey, err := kpdns.LoadOrGenerateAPIKey(s.cfg.DataDir)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := kpdns.DeleteZone(apiKey, domain); err != nil {
		renderErr("nsserver.error.apply", err.Error())
		return
	}
	http.Redirect(w, r, "/network/nsserver", http.StatusSeeOther)
}

func (s *Server) handleNSServerRecordUpsert(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	renderErr := func(key, detail string) {
		data := s.loadNSServerData(w, r, sess)
		data.FormErrorKey = key
		data.ErrorDetail = detail
		s.render(w, "network_nsserver", data)
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		renderErr("login.error.csrf", "")
		return
	}
	domain := r.FormValue("domain")
	name := strings.TrimSpace(r.FormValue("name"))
	recordType := r.FormValue("type")
	value := strings.TrimSpace(r.FormValue("value"))
	ttl, err := strconv.Atoi(r.FormValue("ttl"))
	if err != nil || ttl <= 0 {
		ttl = 3600
	}
	if name == "" || value == "" {
		renderErr("nsserver.error.invalid_record", "")
		return
	}
	apiKey, err := kpdns.LoadOrGenerateAPIKey(s.cfg.DataDir)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := kpdns.UpsertRecord(apiKey, domain, name, recordType, ttl, value); err != nil {
		renderErr("nsserver.error.apply", err.Error())
		return
	}
	http.Redirect(w, r, "/network/nsserver", http.StatusSeeOther)
}

func (s *Server) handleNSServerRecordDelete(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	renderErr := func(key, detail string) {
		data := s.loadNSServerData(w, r, sess)
		data.FormErrorKey = key
		data.ErrorDetail = detail
		s.render(w, "network_nsserver", data)
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		renderErr("login.error.csrf", "")
		return
	}
	apiKey, err := kpdns.LoadOrGenerateAPIKey(s.cfg.DataDir)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := kpdns.DeleteRecord(apiKey, r.FormValue("domain"), r.FormValue("name"), r.FormValue("type")); err != nil {
		renderErr("nsserver.error.apply", err.Error())
		return
	}
	http.Redirect(w, r, "/network/nsserver", http.StatusSeeOther)
}
