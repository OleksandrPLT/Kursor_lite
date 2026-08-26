package server

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"kursor/internal/auth"
	ksites "kursor/internal/sites"
	"kursor/internal/store"
)

// SitesData backs the site manager page — real Nginx vhosts, not a
// mockup (see internal/sites for the render/validate/reload mechanics).
type SitesData struct {
	PageData
	Sites        []store.Site
	NginxStatus  ksites.Status
	FormErrorKey string
	ErrorDetail  string
	Warning      string
}

func (s *Server) loadSitesData(w http.ResponseWriter, r *http.Request, sess *store.Session) SitesData {
	list, _ := s.store.ListSites()
	return SitesData{
		PageData:    s.basePageData(w, r, "sites", sess),
		Sites:       list,
		NginxStatus: ksites.Detect(),
	}
}

func (s *Server) handleSitesPage(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	s.render(w, "sites", s.loadSitesData(w, r, sess))
}

// handleSitesInstallNginx runs a real, synchronous package-manager
// install (apt/yum/brew, whichever this host has) — see
// internal/sites/install.go. It blocks for as long as the install
// takes; there's no background job queue yet, so a slow apt mirror
// means a slow HTTP response, not a broken one.
func (s *Server) handleSitesInstallNginx(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		data := s.loadSitesData(w, r, sess)
		data.FormErrorKey = "login.error.csrf"
		s.render(w, "sites", data)
		return
	}

	out, err := ksites.InstallNginx()
	data := s.loadSitesData(w, r, sess)
	if err != nil {
		data.FormErrorKey = "sites.error.install"
		data.ErrorDetail = out
		if data.ErrorDetail == "" {
			data.ErrorDetail = err.Error()
		}
	}
	s.render(w, "sites", data)
}

func (s *Server) handleSiteCreate(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)

	renderWithError := func(key, detail string) {
		data := s.loadSitesData(w, r, sess)
		data.FormErrorKey = key
		data.ErrorDetail = detail
		s.render(w, "sites", data)
	}

	if err := r.ParseForm(); err != nil {
		renderWithError("accounts.error.generic", "")
		return
	}
	if !auth.ValidCSRF(r) {
		renderWithError("login.error.csrf", "")
		return
	}

	domain := r.FormValue("domain")
	if !ksites.ValidDomain(domain) {
		renderWithError("sites.error.invalid_domain", "")
		return
	}
	existing, err := s.store.GetSiteByDomain(domain)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if existing != nil {
		renderWithError("sites.error.duplicate", "")
		return
	}

	result, err := ksites.Create(domain, s.cfg.WWWRoot)
	if err != nil && result.ConfPath == "" {
		// Real failure — nothing was left behind to persist.
		renderWithError("sites.error.generic", err.Error())
		return
	}

	if _, dbErr := s.store.CreateSite(domain, result.Docroot, result.ConfPath); dbErr != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	data := s.loadSitesData(w, r, sess)
	if err != nil {
		// Config valid, but the running nginx wasn't reloaded — say so.
		data.Warning = err.Error()
	}
	s.render(w, "sites", data)
}

func (s *Server) handleSiteToggle(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if !auth.ValidCSRF(r) {
		http.Redirect(w, r, "/sites", http.StatusSeeOther)
		return
	}

	site, err := s.store.GetSiteByID(id)
	if err != nil || site == nil {
		http.Redirect(w, r, "/sites", http.StatusSeeOther)
		return
	}
	newStatus := "disabled"
	if site.Status == "disabled" {
		newStatus = "enabled"
	}

	nginxErr := ksites.SetEnabled(site.Domain, site.ConfPath, newStatus == "enabled")
	if nginxErr == nil {
		_ = s.store.SetSiteStatus(id, newStatus)
	}

	data := s.loadSitesData(w, r, sess)
	if nginxErr != nil {
		data.Warning = nginxErr.Error()
	}
	s.render(w, "sites", data)
}

func (s *Server) handleSiteDelete(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if !auth.ValidCSRF(r) {
		http.Redirect(w, r, "/sites", http.StatusSeeOther)
		return
	}

	site, err := s.store.GetSiteByID(id)
	if err != nil || site == nil {
		http.Redirect(w, r, "/sites", http.StatusSeeOther)
		return
	}

	nginxErr := ksites.Delete(site.Domain)
	_ = s.store.DeleteSite(id)

	data := s.loadSitesData(w, r, sess)
	if nginxErr != nil {
		data.Warning = nginxErr.Error()
	}
	s.render(w, "sites", data)
}
