package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"kursor/internal/store"
)

func testIssuer(t *testing.T) *Issuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return NewIssuer(key)
}

func TestIssueAndVerifyAccessToken(t *testing.T) {
	iss := testIssuer(t)
	tok, err := iss.IssueAccessToken("https://kursor.local", "kc_abc", "42", "openid profile", time.Hour)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}
	claims, err := iss.Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims["sub"] != "42" {
		t.Errorf("sub: got %v, want 42", claims["sub"])
	}
	if claims["aud"] != "kc_abc" {
		t.Errorf("aud: got %v, want kc_abc", claims["aud"])
	}
	if claims["scope"] != "openid profile" {
		t.Errorf("scope: got %v", claims["scope"])
	}
}

func TestVerify_RejectsTokenFromDifferentKey(t *testing.T) {
	iss1 := testIssuer(t)
	iss2 := testIssuer(t) // a different signing key — simulates a forged/foreign token

	tok, err := iss1.IssueAccessToken("https://kursor.local", "kc_abc", "42", "openid", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := iss2.Verify(tok); err == nil {
		t.Error("expected verification to fail against a different key, but it succeeded")
	}
}

func TestVerify_RejectsExpiredToken(t *testing.T) {
	iss := testIssuer(t)
	// issue a token that already expired
	tok, err := iss.IssueAccessToken("https://kursor.local", "kc_abc", "42", "openid", -time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := iss.Verify(tok); err == nil {
		t.Error("expected an expired token to fail verification")
	}
}

func TestIssueIDToken_ContainsProfileClaims(t *testing.T) {
	iss := testIssuer(t)
	user := &store.User{ID: 7, Username: "t.shevchenko", Email: "t@intech.org.ua", LastName: "Шевченко", FirstName: "Тарас"}

	tok, err := iss.IssueIDToken("https://kursor.local", "kc_abc", user, "nonce-123", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := iss.Verify(tok)
	if err != nil {
		t.Fatal(err)
	}
	if claims["preferred_username"] != "t.shevchenko" {
		t.Errorf("preferred_username: got %v", claims["preferred_username"])
	}
	if claims["email"] != "t@intech.org.ua" {
		t.Errorf("email: got %v", claims["email"])
	}
	if claims["nonce"] != "nonce-123" {
		t.Errorf("nonce: got %v", claims["nonce"])
	}
	if claims["sub"] != "7" {
		t.Errorf("sub: got %v, want 7", claims["sub"])
	}
}

func TestJWKS_MatchesSigningKey(t *testing.T) {
	iss := testIssuer(t)
	jwks := iss.JWKS()
	keys, ok := jwks["keys"].([]map[string]any)
	if !ok || len(keys) != 1 {
		t.Fatalf("expected exactly one key in JWKS, got %#v", jwks)
	}
	if keys[0]["kid"] != iss.kid {
		t.Errorf("kid mismatch: %v != %v", keys[0]["kid"], iss.kid)
	}
	if keys[0]["kty"] != "RSA" || keys[0]["alg"] != "RS256" {
		t.Errorf("unexpected key type/alg: %#v", keys[0])
	}
}

func TestVerifyPKCE(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	if !VerifyPKCE(verifier, challenge, "S256") {
		t.Error("expected matching verifier/challenge to pass")
	}
	if VerifyPKCE("wrong-verifier", challenge, "S256") {
		t.Error("expected mismatched verifier to fail")
	}
	if VerifyPKCE(verifier, challenge, "plain") {
		t.Error("expected the discouraged 'plain' method to be rejected")
	}
	if !VerifyPKCE("", "", "") {
		t.Error("expected no-PKCE-used (both empty) to pass — confidential clients may skip PKCE")
	}
}
