package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"kursor/internal/auth"
	"kursor/internal/oidc"
	"kursor/internal/store"
)

const (
	authCodeTTL    = 2 * time.Minute
	accessTokenTTL = 1 * time.Hour
	idTokenTTL     = 1 * time.Hour
)

func issuerURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func randomID(prefix string, nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// ---------- project (client) management: /company/sso ----------

// OAuthData backs the SSO/Projects management page.
type OAuthData struct {
	PageData
	Clients         []store.OAuthClient
	NewClientID     string
	NewClientSecret string
	FormErrorKey    string
}

func (s *Server) handleSSOPage(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	clients, _ := s.store.ListOAuthClients()
	s.render(w, "sso", OAuthData{
		PageData: s.basePageData(w, r, "company-sso", sess),
		Clients:  clients,
	})
}

func (s *Server) handleSSOCreate(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)

	renderWithError := func(key string) {
		clients, _ := s.store.ListOAuthClients()
		s.render(w, "sso", OAuthData{
			PageData:     s.basePageData(w, r, "company-sso", sess),
			Clients:      clients,
			FormErrorKey: key,
		})
	}

	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		renderWithError("login.error.csrf")
		return
	}

	name := r.FormValue("name")
	clientType := r.FormValue("client_type")
	if clientType != "confidential" && clientType != "public" && clientType != "service" {
		clientType = "confidential"
	}
	redirectURIs := strings.TrimSpace(r.FormValue("redirect_uris"))
	if name == "" {
		renderWithError("sso.error.name_required")
		return
	}
	if clientType != "service" && redirectURIs == "" {
		renderWithError("sso.error.redirect_required")
		return
	}

	clientID, err := randomID("kc_", 12)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	secretHash := ""
	plainSecret := ""
	if clientType != "public" {
		plainSecret, err = auth.GenerateTempPassword()
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		secretHash, err = auth.HashPassword(plainSecret)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}

	if err := s.store.CreateOAuthClient(clientID, name, secretHash, clientType, redirectURIs, sess.UserID); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	clients, _ := s.store.ListOAuthClients()
	s.render(w, "sso", OAuthData{
		PageData:        s.basePageData(w, r, "company-sso", sess),
		Clients:         clients,
		NewClientID:     clientID,
		NewClientSecret: plainSecret,
	})
}

func (s *Server) handleSSODelete(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err == nil && auth.ValidCSRF(r) {
		_ = s.store.DeleteOAuthClient(r.FormValue("id"))
	}
	http.Redirect(w, r, "/company/sso", http.StatusSeeOther)
}

// ---------- discovery ----------

func (s *Server) handleOIDCDiscovery(w http.ResponseWriter, r *http.Request) {
	base := issuerURL(r)
	doc := map[string]any{
		"issuer":                                base,
		"authorization_endpoint":                base + "/oauth/authorize",
		"token_endpoint":                        base + "/oauth/token",
		"userinfo_endpoint":                     base + "/oauth/userinfo",
		"jwks_uri":                              base + "/oauth/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic", "none"},
		"grant_types_supported":                 []string{"authorization_code", "client_credentials"},
		"code_challenge_methods_supported":      []string{"S256"},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(doc)
}

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.oidc.JWKS())
}

// ---------- authorize ----------

// AuthorizeParams carries one authorization request through the GET
// (show consent) -> POST (decide) round trip as hidden form fields.
type AuthorizeParams struct {
	ClientID            string
	RedirectURI         string
	Scope               string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string
}

// ConsentData backs the consent page.
type ConsentData struct {
	PageData
	Client store.OAuthClient
	Params AuthorizeParams
	Scopes []string
}

func (s *Server) handleAuthorizeGet(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	params := AuthorizeParams{
		ClientID:            q.Get("client_id"),
		RedirectURI:         q.Get("redirect_uri"),
		Scope:               q.Get("scope"),
		State:               q.Get("state"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
		Nonce:               q.Get("nonce"),
	}

	if q.Get("response_type") != "code" {
		http.Error(w, "unsupported response_type — only 'code' is supported", http.StatusBadRequest)
		return
	}

	client, err := s.store.GetOAuthClient(params.ClientID)
	if err != nil || client == nil {
		http.Error(w, "unknown client_id", http.StatusBadRequest)
		return
	}
	// redirect_uri must exact-match a registered URI BEFORE we ever
	// consider redirecting anywhere near it — an unvalidated redirect
	// here is exactly how OAuth open-redirect bugs happen.
	if !client.HasRedirectURI(params.RedirectURI) {
		http.Error(w, "redirect_uri is not registered for this client", http.StatusBadRequest)
		return
	}
	if client.ClientType == "public" && params.CodeChallengeMethod != "S256" {
		http.Error(w, "public clients must use PKCE (code_challenge_method=S256)", http.StatusBadRequest)
		return
	}

	sess := sessionFromContext(r)
	scopes := strings.Fields(params.Scope)
	if len(scopes) == 0 {
		scopes = []string{"openid"}
	}
	s.render(w, "oauth_consent", ConsentData{
		PageData: s.basePageData(w, r, "", sess),
		Client:   *client,
		Params:   params,
		Scopes:   scopes,
	})
}

func (s *Server) handleAuthorizePost(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	sess := sessionFromContext(r)
	if !auth.ValidCSRF(r) {
		http.Error(w, "session expired, go back and try again", http.StatusBadRequest)
		return
	}

	params := AuthorizeParams{
		ClientID:            r.FormValue("client_id"),
		RedirectURI:         r.FormValue("redirect_uri"),
		Scope:               r.FormValue("scope"),
		State:               r.FormValue("state"),
		CodeChallenge:       r.FormValue("code_challenge"),
		CodeChallengeMethod: r.FormValue("code_challenge_method"),
		Nonce:               r.FormValue("nonce"),
	}

	client, err := s.store.GetOAuthClient(params.ClientID)
	if err != nil || client == nil || !client.HasRedirectURI(params.RedirectURI) {
		http.Error(w, "invalid client or redirect_uri", http.StatusBadRequest)
		return
	}

	redirectWith := func(query string) {
		sep := "?"
		if strings.Contains(params.RedirectURI, "?") {
			sep = "&"
		}
		http.Redirect(w, r, params.RedirectURI+sep+query, http.StatusSeeOther)
	}

	if r.FormValue("decision") != "allow" {
		redirectWith("error=access_denied&state=" + url.QueryEscape(params.State))
		return
	}

	code, err := randomID("", 24)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	err = s.store.CreateOAuthCode(store.OAuthCode{
		Code:                code,
		ClientID:            params.ClientID,
		UserID:              sess.UserID,
		RedirectURI:         params.RedirectURI,
		Scope:               params.Scope,
		CodeChallenge:       params.CodeChallenge,
		CodeChallengeMethod: params.CodeChallengeMethod,
		Nonce:               params.Nonce,
	}, authCodeTTL)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	redirectWith("code=" + url.QueryEscape(code) + "&state=" + url.QueryEscape(params.State))
}

// ---------- token ----------

func writeJSONError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": description})
}

func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_request", "couldn't parse form")
		return
	}
	base := issuerURL(r)

	switch r.FormValue("grant_type") {
	case "authorization_code":
		s.tokenAuthCode(w, r, base)
	case "client_credentials":
		s.tokenClientCredentials(w, r, base)
	default:
		writeJSONError(w, http.StatusBadRequest, "unsupported_grant_type", "only authorization_code and client_credentials are supported")
	}
}

func clientCreds(r *http.Request) (id, secret string) {
	if id, secret, ok := r.BasicAuth(); ok {
		return id, secret
	}
	return r.FormValue("client_id"), r.FormValue("client_secret")
}

func (s *Server) tokenAuthCode(w http.ResponseWriter, r *http.Request, base string) {
	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	clientID, clientSecret := clientCreds(r)
	codeVerifier := r.FormValue("code_verifier")

	oc, err := s.store.ConsumeOAuthCode(code)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	if oc == nil || oc.ClientID != clientID || oc.RedirectURI != redirectURI {
		writeJSONError(w, http.StatusBadRequest, "invalid_grant", "code is invalid, expired, already used, or doesn't match")
		return
	}

	client, err := s.store.GetOAuthClient(clientID)
	if err != nil || client == nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_client", "")
		return
	}

	if client.ClientType == "public" {
		if !oidc.VerifyPKCE(codeVerifier, oc.CodeChallenge, oc.CodeChallengeMethod) {
			writeJSONError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
			return
		}
	} else if !auth.CheckPassword(client.SecretHash, clientSecret) {
		writeJSONError(w, http.StatusUnauthorized, "invalid_client", "bad client_secret")
		return
	}

	user, err := s.store.GetUserByID(oc.UserID)
	if err != nil || user == nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_grant", "user no longer exists")
		return
	}

	accessToken, err := s.oidc.IssueAccessToken(base, clientID, strconv.FormatInt(user.ID, 10), oc.Scope, accessTokenTTL)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "server_error", "")
		return
	}

	resp := map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   int(accessTokenTTL.Seconds()),
		"scope":        oc.Scope,
	}
	if strings.Contains(oc.Scope, "openid") {
		idToken, err := s.oidc.IssueIDToken(base, clientID, user, oc.Nonce, idTokenTTL)
		if err == nil {
			resp["id_token"] = idToken
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) tokenClientCredentials(w http.ResponseWriter, r *http.Request, base string) {
	clientID, clientSecret := clientCreds(r)
	client, err := s.store.GetOAuthClient(clientID)
	if err != nil || client == nil || client.ClientType != "service" {
		writeJSONError(w, http.StatusBadRequest, "unauthorized_client", "client is not registered for client_credentials")
		return
	}
	if !auth.CheckPassword(client.SecretHash, clientSecret) {
		writeJSONError(w, http.StatusUnauthorized, "invalid_client", "bad client_secret")
		return
	}

	scope := r.FormValue("scope")
	accessToken, err := s.oidc.IssueAccessToken(base, clientID, clientID, scope, accessTokenTTL)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "server_error", "")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   int(accessTokenTTL.Seconds()),
		"scope":        scope,
	})
}

// ---------- userinfo ----------

func (s *Server) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	authz := r.Header.Get("Authorization")
	if !strings.HasPrefix(authz, "Bearer ") {
		writeJSONError(w, http.StatusUnauthorized, "invalid_token", "missing bearer token")
		return
	}
	tokenStr := strings.TrimPrefix(authz, "Bearer ")
	claims, err := s.oidc.Verify(tokenStr)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "invalid_token", err.Error())
		return
	}
	sub, _ := claims["sub"].(string)

	userID, convErr := strconv.ParseInt(sub, 10, 64)
	if convErr != nil {
		// A client_credentials token — sub is the client_id itself,
		// there's no human user to describe.
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"sub": sub})
		return
	}
	user, err := s.store.GetUserByID(userID)
	if err != nil || user == nil {
		writeJSONError(w, http.StatusNotFound, "invalid_token", "subject no longer exists")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"sub":                sub,
		"preferred_username": user.Username,
		"email":              user.Email,
		"name":               user.DisplayName(),
	})
}
