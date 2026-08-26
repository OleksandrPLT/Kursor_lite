// Integrations: API keys for machine-to-machine access, and the small
// public /api/v1/* surface they unlock — the "easy to plug in any
// external platform with open access" ask, distinct from company/sso's
// OAuth2/OIDC (which is for a *person* signing into a third-party app
// as themselves, not a script acting on its own).
package server

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"kursor/internal/auth"
	"kursor/internal/store"
)

// IntegrationsData backs the Integrations page.
type IntegrationsData struct {
	PageData
	Keys         []store.APIKey
	NewKeyName   string
	NewKeyToken  string // shown once, right after creation
	FormErrorKey string
}

func (s *Server) loadIntegrationsData(w http.ResponseWriter, r *http.Request, sess *store.Session) IntegrationsData {
	keys, _ := s.store.ListAPIKeys()
	return IntegrationsData{
		PageData: s.basePageData(w, r, "company-integrations", sess),
		Keys:     keys,
	}
}

func (s *Server) handleIntegrationsPage(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	s.render(w, "integrations", s.loadIntegrationsData(w, r, sess))
}

func (s *Server) handleAPIKeyCreate(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	renderErr := func(key string) {
		data := s.loadIntegrationsData(w, r, sess)
		data.FormErrorKey = key
		s.render(w, "integrations", data)
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		renderErr("login.error.csrf")
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		renderErr("integrations.error.name_required")
		return
	}
	_, token, err := s.store.CreateAPIKey(name, sess.UserID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	data := s.loadIntegrationsData(w, r, sess)
	data.NewKeyName = name
	data.NewKeyToken = token
	s.render(w, "integrations", data)
}

func (s *Server) handleAPIKeyRevoke(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if !auth.ValidCSRF(r) {
		http.Redirect(w, r, "/company/integrations", http.StatusSeeOther)
		return
	}
	_ = s.store.RevokeAPIKey(id)
	http.Redirect(w, r, "/company/integrations", http.StatusSeeOther)
}

// requireAPIKey gates the public /api/v1/* routes: a valid, non-revoked
// bearer token, checked on every request (no session, no CSRF — this is
// the machine-to-machine door, deliberately outside requireAuth).
func (s *Server) requireAPIKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == "" || token == authHeader {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "missing bearer token"})
			return
		}
		key, err := s.store.ValidateAPIKey(token)
		if err != nil || key == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid or revoked API key"})
			return
		}
		r = r.WithContext(withAPIKey(r.Context(), key))
		next.ServeHTTP(w, r)
	})
}

// apiCreateTicketRequest is the JSON body /api/v1/tickets accepts —
// deliberately small: an external platform (a monitoring tool, a
// Slack/Zapier webhook, anything with "open access" the user mentioned)
// files a ticket the same way a person would from the New Ticket form,
// minus every field that only makes sense with a human requester (a
// request_kind workflow, target users, etc.) — those still require a
// person to fill out via the UI.
type apiCreateTicketRequest struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Topic       string `json:"topic"`
	Priority    string `json:"priority"`
}

// handleAPICreateTicket is the first real endpoint on the integrations
// surface: POST /api/v1/tickets with `Authorization: Bearer <key>` and
// a JSON body files a ticket, attributed to whichever admin created the
// API key (there's no human requester on the other end of a webhook).
func (s *Server) handleAPICreateTicket(w http.ResponseWriter, r *http.Request) {
	key := apiKeyFromContext(r.Context())
	w.Header().Set("Content-Type", "application/json")

	var req apiCreateTicketRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON body"})
		return
	}
	if strings.TrimSpace(req.Title) == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "title is required"})
		return
	}
	if !isValidTopic(req.Topic) {
		req.Topic = "other"
	}
	switch req.Priority {
	case "low", "medium", "high", "critical":
	default:
		req.Priority = "medium"
	}

	id, err := s.store.CreateTicket(store.NewTicket{
		Title:       req.Title,
		Description: req.Description,
		Type:        "incident",
		Topic:       req.Topic,
		Priority:    req.Priority,
		RequesterID: key.CreatedByID,
	})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "internal error"})
		return
	}
	ticket, _ := s.store.GetTicket(id)
	displayID := ""
	if ticket != nil {
		displayID = ticket.DisplayID()
	}
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "display_id": displayID})
}
