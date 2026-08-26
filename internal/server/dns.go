package server

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"kursor/internal/auth"
	kdns "kursor/internal/dns"
	ksites "kursor/internal/sites"
	"kursor/internal/store"
)

// DNSData backs the DNS records page — real dnsmasq records (see
// internal/dns), not a mockup.
type DNSData struct {
	PageData
	Installed    bool
	Records      []store.DNSRecord
	FormErrorKey string
	ErrorDetail  string
}

func (s *Server) loadDNSData(w http.ResponseWriter, r *http.Request, sess *store.Session) DNSData {
	records, _ := s.store.ListDNSRecords()
	return DNSData{
		PageData:  s.basePageData(w, r, "network-dns", sess),
		Installed: kdns.Detect().Installed,
		Records:   records,
	}
}

func (s *Server) handleDNSPage(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	s.render(w, "network_dns", s.loadDNSData(w, r, sess))
}

func (s *Server) handleDNSInstall(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		data := s.loadDNSData(w, r, sess)
		data.FormErrorKey = "login.error.csrf"
		s.render(w, "network_dns", data)
		return
	}
	out, err := ksites.InstallPackage("dnsmasq")
	data := s.loadDNSData(w, r, sess)
	if err != nil {
		data.FormErrorKey = "dns.error.install"
		data.ErrorDetail = out
		if data.ErrorDetail == "" {
			data.ErrorDetail = err.Error()
		}
	}
	s.render(w, "network_dns", data)
}

// applyDNSConfig regenerates kursor.conf from every stored record and
// reloads dnsmasq — always the full set, never a diff, same discipline
// as internal/cron.Sync and VPN's applyVPNConfig.
func (s *Server) applyDNSConfig() error {
	dbRecords, err := s.store.ListDNSRecords()
	if err != nil {
		return err
	}
	records := make([]kdns.Record, 0, len(dbRecords))
	for _, r := range dbRecords {
		records = append(records, kdns.Record{Name: r.Name, Type: r.Type, Value: r.Value, Priority: r.Priority})
	}
	return kdns.Apply(records)
}

func (s *Server) handleDNSRecordCreate(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	renderErr := func(key, detail string) {
		data := s.loadDNSData(w, r, sess)
		data.FormErrorKey = key
		data.ErrorDetail = detail
		s.render(w, "network_dns", data)
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		renderErr("login.error.csrf", "")
		return
	}

	recordType := r.FormValue("type")
	priority, _ := strconv.Atoi(r.FormValue("priority"))
	rec := kdns.Record{
		Name:     r.FormValue("name"),
		Type:     recordType,
		Value:    r.FormValue("value"),
		Priority: priority,
	}
	if err := kdns.Validate(rec); err != nil {
		renderErr("dns.error.invalid_record", err.Error())
		return
	}

	id, err := s.store.CreateDNSRecord(rec.Name, rec.Type, rec.Value, rec.Priority)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := s.applyDNSConfig(); err != nil {
		// Same "an unrecoverable half-applied change is worse than no
		// change" rollback VPN's peer creation uses — nothing here is a
		// one-time secret, but leaving a record in the DB that never made
		// it into the live dnsmasq config would silently lie to whoever
		// looks at the list next.
		_ = s.store.DeleteDNSRecord(id)
		renderErr("dns.error.apply", err.Error())
		return
	}
	http.Redirect(w, r, "/network/dns", http.StatusSeeOther)
}

func (s *Server) handleDNSRecordDelete(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if !auth.ValidCSRF(r) {
		http.Redirect(w, r, "/network/dns", http.StatusSeeOther)
		return
	}
	_ = s.store.DeleteDNSRecord(id)
	if err := s.applyDNSConfig(); err != nil {
		data := s.loadDNSData(w, r, sess)
		data.FormErrorKey = "dns.error.apply"
		data.ErrorDetail = err.Error()
		s.render(w, "network_dns", data)
		return
	}
	http.Redirect(w, r, "/network/dns", http.StatusSeeOther)
}
