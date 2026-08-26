package server

import (
	"net/http"
	"path/filepath"
	"strconv"

	"kursor/internal/auth"
	kbackups "kursor/internal/backups"
	"kursor/internal/store"
)

func (s *Server) backupsDir() string {
	return filepath.Join(s.cfg.DataDir, "backups")
}

// BackupsData backs the backups page.
type BackupsData struct {
	PageData
	Sites        []store.Site
	Backups      []kbackups.Info
	FormErrorKey string
	ErrorDetail  string
}

func (s *Server) loadBackupsData(w http.ResponseWriter, r *http.Request, sess *store.Session) BackupsData {
	sitesList, _ := s.store.ListSites()
	list, _ := kbackups.List(s.backupsDir())
	return BackupsData{
		PageData: s.basePageData(w, r, "server-backups", sess),
		Sites:    sitesList,
		Backups:  list,
	}
}

func (s *Server) handleBackupsPage(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	s.render(w, "backups", s.loadBackupsData(w, r, sess))
}

func (s *Server) handleBackupCreate(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)

	renderWithError := func(key, detail string) {
		data := s.loadBackupsData(w, r, sess)
		data.FormErrorKey = key
		data.ErrorDetail = detail
		s.render(w, "backups", data)
	}

	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		renderWithError("login.error.csrf", "")
		return
	}

	source := r.FormValue("source") // "wwwroot" or a site ID
	label := "wwwroot"
	sourceDir := s.cfg.WWWRoot

	if source != "" && source != "wwwroot" {
		id, err := strconv.ParseInt(source, 10, 64)
		if err != nil {
			renderWithError("backups.error.create", "")
			return
		}
		site, err := s.store.GetSiteByID(id)
		if err != nil || site == nil {
			renderWithError("backups.error.create", "")
			return
		}
		sourceDir = site.Docroot
		label = site.Domain
	}

	if _, err := kbackups.Create(s.backupsDir(), sourceDir, label); err != nil {
		renderWithError("backups.error.create", err.Error())
		return
	}
	s.render(w, "backups", s.loadBackupsData(w, r, sess))
}

func (s *Server) handleBackupDownload(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	abs, err := kbackups.Path(s.backupsDir(), name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="`+filepath.Base(abs)+`"`)
	http.ServeFile(w, r, abs)
}

func (s *Server) handleBackupDelete(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		s.render(w, "backups", s.loadBackupsData(w, r, sess))
		return
	}
	_ = kbackups.Delete(s.backupsDir(), r.FormValue("name"))
	http.Redirect(w, r, "/server/backups", http.StatusSeeOther)
}
