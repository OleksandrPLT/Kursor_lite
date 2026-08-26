package server

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"kursor/internal/auth"
	kcron "kursor/internal/cron"
	"kursor/internal/store"
)

// CronData backs the cron jobs page — real jobs, synced into the OS
// crontab (see internal/cron), not a mockup.
type CronData struct {
	PageData
	Jobs         []store.CronJob
	FormErrorKey string
	SyncWarning  string
}

func (s *Server) handleCronPage(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	jobs, _ := s.store.ListCronJobs()
	s.render(w, "cron", CronData{
		PageData: s.basePageData(w, r, "server-cron", sess),
		Jobs:     jobs,
	})
}

func (s *Server) handleCronCreate(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)

	renderWithError := func(errKey, syncWarning string) {
		jobs, _ := s.store.ListCronJobs()
		s.render(w, "cron", CronData{
			PageData:     s.basePageData(w, r, "server-cron", sess),
			Jobs:         jobs,
			FormErrorKey: errKey,
			SyncWarning:  syncWarning,
		})
	}

	if err := r.ParseForm(); err != nil {
		renderWithError("accounts.error.generic", "")
		return
	}
	if !auth.ValidCSRF(r) {
		renderWithError("login.error.csrf", "")
		return
	}

	schedule := r.FormValue("schedule")
	command := r.FormValue("command")
	label := r.FormValue("label")

	if err := kcron.ValidateSchedule(schedule); err != nil {
		renderWithError("cron.error.invalid_schedule", "")
		return
	}
	if command == "" {
		renderWithError("cron.error.empty_command", "")
		return
	}

	if _, err := s.store.CreateCronJob(schedule, command, label, sess.UserID); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	s.syncCronOrWarn(w, r, sess)
}

func (s *Server) handleCronToggle(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if !auth.ValidCSRF(r) {
		http.Redirect(w, r, "/server/cron", http.StatusSeeOther)
		return
	}

	job, err := s.store.GetCronJob(id)
	if err != nil || job == nil {
		http.Redirect(w, r, "/server/cron", http.StatusSeeOther)
		return
	}
	_ = s.store.SetCronJobEnabled(id, !job.Enabled)

	s.syncCronOrWarn(w, r, sess)
}

func (s *Server) handleCronDelete(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if !auth.ValidCSRF(r) {
		http.Redirect(w, r, "/server/cron", http.StatusSeeOther)
		return
	}

	_ = s.store.DeleteCronJob(id)

	s.syncCronOrWarn(w, r, sess)
}

// syncCronOrWarn pushes the current job list into the OS crontab and
// re-renders the page — with a warning banner if the sync itself failed
// (the DB change already committed either way, so the UI never lies
// about what Kursor thinks its jobs are; it only warns if the OS
// crontab might now be out of sync with that).
func (s *Server) syncCronOrWarn(w http.ResponseWriter, r *http.Request, sess *store.Session) {
	jobs, _ := s.store.ListCronJobs()
	warning := ""
	if err := kcron.Sync(jobs); err != nil {
		warning = err.Error()
	}
	s.render(w, "cron", CronData{
		PageData:    s.basePageData(w, r, "server-cron", sess),
		Jobs:        jobs,
		SyncWarning: warning,
	})
}
