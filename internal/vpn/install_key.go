package vpn

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
)

// LoadOrGenerateInstallKey returns this host's AES-256 key for
// encrypting a peer's private key at rest (see EncryptPrivateKey) —
// generated once and persisted, same on-disk lifecycle as
// LoadOrGenerateServerKey. Losing this file makes every stored
// encrypted private key permanently unrecoverable (same trade-off as
// losing wg_server_key breaking every existing peer's config).
func LoadOrGenerateInstallKey(dataDir string) ([]byte, error) {
	path := filepath.Join(dataDir, "vpn_install_key")
	if b, err := os.ReadFile(path); err == nil {
		if key, err := base64.StdEncoding.DecodeString(string(b)); err == nil && len(key) == 32 {
			return key, nil
		}
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(key)), 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

// EncryptPrivateKey/DecryptPrivateKey wrap a peer's WireGuard private
// key for storage — AES-256-GCM, a fresh random nonce per call
// prepended to the returned ciphertext. This is the one place in the
// codebase a peer's private key is ever persisted; every other path
// (the one-time reveal at creation) treats it as shown-once-never-
// stored. Install links are the deliberate, opt-in exception — and
// only whoever holds this host's key file can ever decrypt it back.
func EncryptPrivateKey(key []byte, plaintext string) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, []byte(plaintext), nil), nil
}

func DecryptPrivateKey(key []byte, ciphertext []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return "", errors.New("vpn: encrypted private key is corrupt (too short)")
	}
	nonce, ct := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}
