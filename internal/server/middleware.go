package server

import (
	"context"
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
