package server

import (
	"net/http"

	"kursor/internal/auth"
)

func (s *Server) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if auth.CurrentSession(r, s.store) != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, "login", LoginData{Lang: getLang(r), CSRFToken: auth.IssueCSRFToken(w)})
}

func (s *Server) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}

	if !auth.ValidCSRF(r) {
		s.render(w, "login", LoginData{
			Lang:      getLang(r),
			ErrorKey:  "login.error.csrf",
			CSRFToken: auth.IssueCSRFToken(w),
		})
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	user, err := s.store.GetUserByUsername(username)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if user == nil || !auth.CheckPassword(user.PasswordHash, password) {
		s.render(w, "login", LoginData{
			Lang:      getLang(r),
			ErrorKey:  "login.error.invalid",
			CSRFToken: auth.IssueCSRFToken(w),
		})
		return
	}
	if user.Status != "active" {
		s.render(w, "login", LoginData{
			Lang:      getLang(r),
			ErrorKey:  "login.error.disabled",
			CSRFToken: auth.IssueCSRFToken(w),
		})
		return
	}

	if err := auth.StartSession(w, s.store, user.ID, r); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	auth.EndSession(w, r, s.store)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	s.render(w, "dashboard", s.basePageData(w, r, "dashboard", sess))
}

// handlePlaceholder builds a handler for a module that isn't built yet
// (Sites, File Manager, Databases — see the build plan's milestone
// order). Honest "coming soon" beats fake sample data on a page real
// requests hit.
func (s *Server) handlePlaceholder(active, titleKey, descKey string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := sessionFromContext(r)
		s.render(w, "placeholder", PlaceholderData{
			PageData: s.basePageData(w, r, active, sess),
			TitleKey: titleKey,
			DescKey:  descKey,
		})
	}
}

// handleSetLang sets the language cookie and bounces back to wherever
// the visitor was (login page or an authenticated page) — public, no
// auth required, since the login page needs to be localizable too.
func (s *Server) handleSetLang(w http.ResponseWriter, r *http.Request, code string) {
	if code != "uk" && code != "en" {
		code = "uk"
	}
	http.SetCookie(w, &http.Cookie{
		Name:   langCookieName,
		Value:  code,
		Path:   "/",
		MaxAge: 365 * 24 * 3600,
	})
	ref := r.Referer()
	if ref == "" {
		ref = "/"
	}
	http.Redirect(w, r, ref, http.StatusSeeOther)
}
