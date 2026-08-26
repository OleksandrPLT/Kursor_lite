package server

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"kursor/internal/auth"
	ksites "kursor/internal/sites"
	"kursor/internal/store"
)

// SiteCertRow pairs a site with its live-parsed certificate status.
type SiteCertRow struct {
	store.Site
	Cert ksites.CertStatus
}

// SSLData backs the SSL certificates page.
type SSLData struct {
	PageData
	CertbotInstalled bool
	Rows             []SiteCertRow
	FormErrorKey     string
	ErrorDetail      string
}

func (s *Server) loadSSLData(w http.ResponseWriter, r *http.Request, sess *store.Session) SSLData {
	sitesList, _ := s.store.ListSites()
	rows := make([]SiteCertRow, 0, len(sitesList))
	for _, site := range sitesList {
		rows = append(rows, SiteCertRow{Site: site, Cert: ksites.GetCertStatus(site.Domain)})
	}
	return SSLData{
		PageData:         s.basePageData(w, r, "server-ssl", sess),
		CertbotInstalled: ksites.DetectCertbot(),
		Rows:             rows,
	}
}

func (s *Server) handleSSLPage(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	s.render(w, "ssl", s.loadSSLData(w, r, sess))
}

// handleSSLInstallCertbot mirrors handleSitesInstallNginx for certbot —
// same synchronous, real package-manager install.
func (s *Server) handleSSLInstallCertbot(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		data := s.loadSSLData(w, r, sess)
		data.FormErrorKey = "login.error.csrf"
		s.render(w, "ssl", data)
		return
	}

	out, err := ksites.InstallCertbot()
	data := s.loadSSLData(w, r, sess)
	if err != nil {
		data.FormErrorKey = "ssl.error.install"
		data.ErrorDetail = out
		if data.ErrorDetail == "" {
			data.ErrorDetail = err.Error()
		}
	}
	s.render(w, "ssl", data)
}

func (s *Server) handleSSLIssue(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}

	renderWithError := func(key, detail string) {
		data := s.loadSSLData(w, r, sess)
		data.FormErrorKey = key
		data.ErrorDetail = detail
		s.render(w, "ssl", data)
	}

	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		renderWithError("login.error.csrf", "")
		return
	}

	site, err := s.store.GetSiteByID(id)
	if err != nil || site == nil {
		http.NotFound(w, r)
		return
	}

	if err := ksites.IssueCertificate(site.Domain, site.Docroot, r.FormValue("email")); err != nil {
		renderWithError("ssl.error.issue", err.Error())
		return
	}
	if err := ksites.EnableSSLVhost(site.Domain, site.Docroot, site.ConfPath); err != nil {
		renderWithError("ssl.error.enable", err.Error())
		return
	}

	s.render(w, "ssl", s.loadSSLData(w, r, sess))
}
