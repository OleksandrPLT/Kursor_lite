package server

import (
	"context"
	"net"
	"net/http"

	"kursor/internal/auth"
	"kursor/internal/store"
)

type contextKey int

const (
	sessionContextKey contextKey = iota
	apiKeyContextKey
)

// withAPIKey/apiKeyFromContext mirror sessionFromContext above, for the
// /api/v1/* routes' bearer-token auth (see requireAPIKey in
// integrations.go) — a separate identity axis from the cookie session,
// never both on the same request.
func withAPIKey(ctx context.Context, key *store.APIKey) context.Context {
	return context.WithValue(ctx, apiKeyContextKey, key)
}

func apiKeyFromContext(ctx context.Context) *store.APIKey {
	key, _ := ctx.Value(apiKeyContextKey).(*store.APIKey)
	return key
}

// requireAuth redirects unauthenticated requests to /login, and attaches
// the caller's session to the request context otherwise.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := auth.CurrentSession(r, s.store)
		if sess == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		ctx := context.WithValue(r.Context(), sessionContextKey, sess)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func sessionFromContext(r *http.Request) *store.Session {
	sess, _ := r.Context().Value(sessionContextKey).(*store.Session)
	return sess
}

// statusCapturingWriter records whatever status code the handler
// actually sent, defaulting to 200 (the same assumption net/http
// itself makes when a handler never calls WriteHeader explicitly).
type statusCapturingWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusCapturingWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// auditLog records every state-changing request (POST/PUT/PATCH/
// DELETE) a logged-in user makes — who, what, from where, and whether
// it succeeded. GETs aren't logged: on this panel every real action is
// a non-GET request, and logging every page view would bury the
// signal. Must run after requireAuth (needs the session) — logging
// itself never blocks or fails the actual request, since audit-log
// gaps are far less costly than breaking the feature they're watching.
func (s *Server) auditLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			next.ServeHTTP(w, r)
			return
		}
		sw := &statusCapturingWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)

		sess := sessionFromContext(r)
		if sess == nil {
			return
		}
		ip := r.RemoteAddr
		if h, _, err := net.SplitHostPort(ip); err == nil {
			ip = h
		}
		_ = s.store.CreateAuditEntry(sess.UserID, sess.Username, r.Method, r.URL.Path, sw.status, ip)
	})
}

// requireModule must run after requireAuth. Admins always pass; a member
// without the module in their granted access levels gets a plain 403 —
// their nav hides the link, so reaching this means they typed the URL.
func (s *Server) requireModule(key string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess := sessionFromContext(r)
			if sess == nil || !sess.HasModule(key) {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// requireAdmin must run after requireAuth. Non-admins get a plain 403 —
// the accounts page isn't in their nav, so reaching this means they
// typed the URL directly.
func (s *Server) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := sessionFromContext(r)
		if sess == nil || sess.Role != "admin" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
