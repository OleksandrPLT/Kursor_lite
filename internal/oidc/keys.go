// Package oidc is Kursor's own OAuth2/OIDC identity provider — the
// "single login for every connected project" piece of the account
// manager module. Tokens are real signed JWTs (RS256), verifiable by
// any standard OIDC client library via the JWKS endpoint, not a
// proprietary scheme.
package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
)

const keyFileName = "oidc_signing_key.pem"

// LoadOrGenerateKey loads the persistent RSA signing key from dataDir,
// generating (and saving, mode 0600) a fresh 2048-bit key on first run.
// The key must stay stable across restarts — regenerating it would
// invalidate every token and JWKS entry already handed out.
func LoadOrGenerateKey(dataDir string) (*rsa.PrivateKey, error) {
	path := filepath.Join(dataDir, keyFileName)

	if data, err := os.ReadFile(path); err == nil {
		if block, _ := pem.Decode(data); block != nil {
			if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
				return key, nil
			}
		}
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

// keyID derives a short, stable identifier for a public key (for the
// JWT "kid" header and the matching JWKS entry) from the key material
// itself, so it naturally changes if the key ever does.
func keyID(pub *rsa.PublicKey) string {
	sum := sha256.Sum256(pub.N.Bytes())
	return hex.EncodeToString(sum[:])[:16]
}
