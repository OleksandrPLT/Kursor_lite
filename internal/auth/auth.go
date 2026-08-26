// Package auth handles Kursor's own login: a single bcrypt-hashed admin
// account (for now — see the project plan's phase-2 SSO note) backed by
// server-side sessions stored in sqlite, plus a small double-submit CSRF
// helper for the login form.
package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"kursor/internal/store"
)

// SessionTTL is how long a login stays valid.
const SessionTTL = 7 * 24 * time.Hour

const sessionCookieName = "kursor_session"
const csrfCookieName = "kursor_csrf"

// randomToken returns a URL-safe random token with nBytes of entropy.
func randomToken(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// cyrillicTranslit mirrors web/static/js/accounts.js's MAP exactly — kept
// in sync deliberately, since one generates username suggestions in the
// browser and the other generates them server-side (ticket -> "Create
// Account"); a mismatch would just be confusing, not unsafe, but there's
// no reason to let them drift.
var cyrillicTranslit = map[rune]string{
	'а': "a", 'б': "b", 'в': "v", 'г': "h", 'ґ': "g", 'д': "d", 'е': "e", 'є': "ie",
	'ж': "zh", 'з': "z", 'и': "y", 'і': "i", 'ї': "i", 'й': "i", 'к': "k", 'л': "l",
	'м': "m", 'н': "n", 'о': "o", 'п': "p", 'р': "r", 'с': "s", 'т': "t", 'у': "u",
	'ф': "f", 'х': "kh", 'ц': "ts", 'ч': "ch", 'ш': "sh", 'щ': "shch", 'ь': "",
	'ю': "iu", 'я': "ia", '\'': "", '’': "", 'ʼ': "",
}

func translit(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if v, ok := cyrillicTranslit[r]; ok {
			b.WriteString(v)
		} else if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
		// anything else (spaces, stray punctuation) is dropped
	}
	return b.String()
}

// SuggestUsername builds a "f.lastname" login suggestion from a name —
// the same rule web/static/js/accounts.js applies live in the create-
// account form, used here server-side when a ticket's "Create Account"
// button generates one without a human typing it in.
func SuggestUsername(firstName, lastName string) string {
	f, l := translit(firstName), translit(lastName)
	if f == "" || l == "" {
		return ""
	}
	return string(f[0]) + "." + l
}

// GenerateTempPassword returns a random ~16-char password, used both for
// the first-run admin bootstrap and for newly created accounts (see
// internal/server/accounts.go) — shown once, never stored in plaintext.
func GenerateTempPassword() (string, error) {
	return randomToken(12)
}

// HashPassword bcrypt-hashes a plaintext password for storage.
func HashPassword(password string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(h), err
}

// CheckPassword reports whether password matches the stored bcrypt hash.
func CheckPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// EnsureAdmin bootstraps the very first admin account when the users
// table is empty (fresh install / fresh local `data/` dir), generating a
// random password the caller is expected to print once. If an admin
// already exists, created is false and password is empty.
func EnsureAdmin(st *store.Store) (username, password string, created bool, err error) {
	n, err := st.CountUsers()
	if err != nil {
		return "", "", false, err
	}
	if n > 0 {
		return "", "", false, nil
	}

	pw, err := GenerateTempPassword()
	if err != nil {
		return "", "", false, err
	}
	hash, err := HashPassword(pw)
	if err != nil {
		return "", "", false, err
	}
	if _, err := st.CreateUser(store.NewUser{
		Username:     "admin",
		PasswordHash: hash,
		Role:         "admin",
	}); err != nil {
		return "", "", false, err
	}
	return "admin", pw, true, nil
}

// StartSession creates a session for userID and sets the session cookie
// on the response.
func StartSession(w http.ResponseWriter, st *store.Store, userID int64, r *http.Request) error {
	token, err := randomToken(32)
	if err != nil {
		return err
	}
	if err := st.CreateSession(token, userID, SessionTTL, r.UserAgent(), r.RemoteAddr); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(SessionTTL),
	})
	return nil
}

// CurrentSession returns the caller's session, or nil if unauthenticated
// or the session has expired.
func CurrentSession(r *http.Request, st *store.Store) *store.Session {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil
	}
	sess, err := st.GetSession(c.Value)
	if err != nil || sess == nil {
		return nil
	}
	return sess
}

// EndSession deletes the session server-side and clears the cookie.
func EndSession(w http.ResponseWriter, r *http.Request, st *store.Store) {
	if c, err := r.Cookie(sessionCookieName); err == nil {
		_ = st.DeleteSession(c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})
}

// IssueCSRFToken sets (or refreshes) the double-submit CSRF cookie and
// returns the token to embed as a hidden form field.
func IssueCSRFToken(w http.ResponseWriter) string {
	token, err := randomToken(16)
	if err != nil {
		// crypto/rand failing is effectively unrecoverable; fall back to
		// a fixed-length but still unpredictable-enough marker rather
		// than panicking the request.
		token = fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: false,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   3600,
	})
	return token
}

// ValidCSRF checks the submitted csrf_token form field against the
// double-submit cookie.
func ValidCSRF(r *http.Request) bool {
	c, err := r.Cookie(csrfCookieName)
	if err != nil || c.Value == "" {
		return false
	}
	return r.FormValue("csrf_token") == c.Value
}
