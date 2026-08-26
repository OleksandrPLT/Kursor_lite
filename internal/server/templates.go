package server

import (
	"html/template"
	"net/http"
	"strings"

	"kursor/internal/auth"
	"kursor/internal/i18n"
	"kursor/internal/store"
	"kursor/web"
)

func loadTemplates() (*template.Template, error) {
	funcs := template.FuncMap{
		"icon":     icon,
		"t":        i18n.T,
		"initials": userInitials,
		"derefID": func(p *int64) int64 {
			if p == nil {
				return 0
			}
			return *p
		},
		"humanSize":  humanSize,
		"topicLabel": topicLabel,
	}
	return template.New("").Funcs(funcs).ParseFS(web.FS, "templates/*.html", "templates/partials/*.html")
}

const langCookieName = "kursor_lang"

// getLang reads the visitor's language preference, defaulting to
// i18n.DefaultLang when no cookie is set (or it names an unsupported
// language).
func getLang(r *http.Request) string {
	c, err := r.Cookie(langCookieName)
	if err != nil || !i18n.Supported(c.Value) {
		return i18n.DefaultLang
	}
	return c.Value
}

// PageData is the common data every authenticated page's layout
// (sidebar + topbar) needs.
type PageData struct {
	Lang         string
	Active       string // "dashboard" | "sites" | "files" | "databases" | "accounts"
	Username     string
	UserInitials string
	Role         string // "admin" | "member"
	IsAdmin      bool
	CanSites     bool
	CanFiles     bool
	CanDatabases bool
	CanNetwork   bool
	CanServer    bool
	CSRFToken    string
	Hostname     string
	ServerIP     string
	Uptime       string
	OS           string
	CPUCores     int
	NetIface     string
}

// LoginData is what the login page template needs. ErrorKey (rather than
// a pre-rendered message) so the same page renders correctly regardless
// of which language cookie the visitor has.
type LoginData struct {
	Lang      string
	ErrorKey  string
	CSRFToken string
}

// PlaceholderData backs the "coming soon" stub pages for modules not
// built yet (Sites, File Manager, Databases — see the build plan's
// milestone order).
type PlaceholderData struct {
	PageData
	TitleKey string
	DescKey  string
}

func (s *Server) basePageData(w http.ResponseWriter, r *http.Request, active string, sess *store.Session) PageData {
	h := getHostSnapshot()
	username, role := "admin", "member"
	var can func(string) bool = func(string) bool { return false }
	if sess != nil {
		username, role = sess.Username, sess.Role
		can = sess.HasModule
	}
	return PageData{
		Lang:         getLang(r),
		Active:       active,
		Username:     username,
		UserInitials: userInitials(username),
		Role:         role,
		IsAdmin:      role == "admin",
		CanSites:     can("sites"),
		CanFiles:     can("files"),
		CanDatabases: can("databases"),
		CanNetwork:   can("network"),
		CanServer:    can("server"),
		CSRFToken:    auth.IssueCSRFToken(w),
		Hostname:     h.Hostname,
		ServerIP:     h.IP,
		Uptime:       h.Uptime,
		OS:           h.OS,
		CPUCores:     h.CPUCores,
		NetIface:     "all interfaces",
	}
}

// userInitials takes the first RUNE (not byte — Cyrillic names are a
// first-class case here, and byte-slicing a UTF-8 string mid-character
// produces a broken replacement glyph).
func userInitials(name string) string {
	r := []rune(name)
	if len(r) == 0 {
		return "?"
	}
	return strings.ToUpper(string(r[0]))
}

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, "template error: "+err.Error(), http.StatusInternalServerError)
	}
}
