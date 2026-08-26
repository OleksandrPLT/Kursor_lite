package oidc

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"kursor/internal/store"
)

// Issuer signs and verifies every token Kursor's OIDC provider hands
// out.
type Issuer struct {
	key *rsa.PrivateKey
	kid string
}

// NewIssuer wraps a loaded signing key.
func NewIssuer(key *rsa.PrivateKey) *Issuer {
	return &Issuer{key: key, kid: keyID(&key.PublicKey)}
}

// IDTokenClaims is the OIDC ID token shape — standard claims plus the
// handful of profile fields most clients expect.
type IDTokenClaims struct {
	jwt.RegisteredClaims
	PreferredUsername string `json:"preferred_username,omitempty"`
	Email             string `json:"email,omitempty"`
	Name              string `json:"name,omitempty"`
	Nonce             string `json:"nonce,omitempty"`
}

func (iss *Issuer) sign(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = iss.kid
	return token.SignedString(iss.key)
}

// IssueIDToken signs an OIDC ID token identifying user to clientID.
func (iss *Issuer) IssueIDToken(issuerURL, clientID string, user *store.User, nonce string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := IDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuerURL,
			Subject:   strconv.FormatInt(user.ID, 10),
			Audience:  jwt.ClaimStrings{clientID},
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		PreferredUsername: user.Username,
		Email:             user.Email,
		Name:              user.DisplayName(),
		Nonce:             nonce,
	}
	return iss.sign(claims)
}

// IssueAccessToken signs an access token. subject is the user's ID for
// authorization_code grants, or the client_id itself for
// client_credentials (machine-to-machine) grants — there's no end user
// in that case.
func (iss *Issuer) IssueAccessToken(issuerURL, clientID, subject, scope string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":   issuerURL,
		"sub":   subject,
		"aud":   clientID,
		"scope": scope,
		"exp":   now.Add(ttl).Unix(),
		"iat":   now.Unix(),
	}
	return iss.sign(claims)
}

// Verify checks a token's signature and standard claims (exp, etc — via
// jwt.Parse's own validation) and returns its claims.
func (iss *Issuer) Verify(tokenStr string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
		}
		return &iss.key.PublicKey, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return claims, nil
}

// JWKS renders the public key set clients use to verify tokens without
// ever needing a shared secret.
func (iss *Issuer) JWKS() map[string]any {
	pub := iss.key.PublicKey
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	return map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": iss.kid,
				"n":   n,
				"e":   e,
			},
		},
	}
}

// VerifyPKCE checks a code_verifier against the code_challenge recorded
// at the /authorize step. Only S256 is supported (the "plain" PKCE
// method is a discouraged legacy fallback — RFC 7636 §7.2 recommends
// clients never use it, so Kursor doesn't accept it). A challenge/method
// pair that's empty on both sides means the authorization request never
// used PKCE at all (fine for a confidential client authenticating with
// a client_secret instead).
func VerifyPKCE(verifier, challenge, method string) bool {
	if challenge == "" && method == "" {
		return true
	}
	if method != "S256" || verifier == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:]) == challenge
}
