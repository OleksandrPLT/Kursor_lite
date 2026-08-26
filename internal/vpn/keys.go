// Package vpn manages a real WireGuard VPN: server + peer keypairs,
// config rendering, and service reload — the same render→validate→apply
// discipline internal/sites uses for Nginx, applied to `wg`/`wg-quick`
// instead. A Homebrew/macOS variant (wg installed differently, no
// systemd) is deferred the same way the Nginx macOS patch is — see the
// project notes.
package vpn

import (
	"crypto/rand"
	"encoding/base64"
	"errors"

	"golang.org/x/crypto/curve25519"
)

// GeneratePrivateKey returns a fresh WireGuard-format private key: 32
// random bytes clamped per the Curve25519 spec and base64-encoded —
// bit-for-bit what `wg genkey` produces, so keys this package generates
// interoperate with any real WireGuard client or server.
func GeneratePrivateKey() (string, error) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		return "", err
	}
	key[0] &= 248
	key[31] &= 127
	key[31] |= 64
	return base64.StdEncoding.EncodeToString(key[:]), nil
}

// PublicKey derives the WireGuard public key for a base64 private key —
// the same X25519 scalar multiplication `wg pubkey` performs.
func PublicKey(privateKeyB64 string) (string, error) {
	priv, err := base64.StdEncoding.DecodeString(privateKeyB64)
	if err != nil {
		return "", err
	}
	if len(priv) != 32 {
		return "", errors.New("vpn: invalid private key length")
	}
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(pub), nil
}
