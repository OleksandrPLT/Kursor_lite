package vpn

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptDecryptPrivateKeyRoundtrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	priv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}

	ct, err := EncryptPrivateKey(key, priv)
	if err != nil {
		t.Fatalf("EncryptPrivateKey: %v", err)
	}
	if string(ct) == priv {
		t.Fatal("ciphertext must not equal the plaintext")
	}

	got, err := DecryptPrivateKey(key, ct)
	if err != nil {
		t.Fatalf("DecryptPrivateKey: %v", err)
	}
	if got != priv {
		t.Fatalf("roundtrip mismatch: got %q, want %q", got, priv)
	}
}

func TestDecryptPrivateKeyWrongKeyFails(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	key2[0] = 1 // differ from key1's all-zero bytes
	priv, _ := GeneratePrivateKey()

	ct, err := EncryptPrivateKey(key1, priv)
	if err != nil {
		t.Fatalf("EncryptPrivateKey: %v", err)
	}
	if _, err := DecryptPrivateKey(key2, ct); err == nil {
		t.Fatal("expected decryption with the wrong key to fail")
	}
}

func TestDecryptPrivateKeyCorruptCiphertext(t *testing.T) {
	key := make([]byte, 32)
	if _, err := DecryptPrivateKey(key, []byte("too short")); err == nil {
		t.Fatal("expected an error on a too-short ciphertext")
	}
}

func TestLoadOrGenerateInstallKeyPersists(t *testing.T) {
	dir := t.TempDir()
	k1, err := LoadOrGenerateInstallKey(dir)
	if err != nil {
		t.Fatalf("LoadOrGenerateInstallKey: %v", err)
	}
	if len(k1) != 32 {
		t.Fatalf("expected a 32-byte key, got %d bytes", len(k1))
	}
	k2, err := LoadOrGenerateInstallKey(dir)
	if err != nil {
		t.Fatalf("LoadOrGenerateInstallKey (second call): %v", err)
	}
	if string(k1) != string(k2) {
		t.Fatal("expected the same key to be loaded back, not regenerated")
	}

	// Sanity: the file really exists where documented and only readable
	// by its owner (0600), same convention as the other secret files
	// this package persists (wg_server_key).
	info, err := os.Stat(filepath.Join(dir, "vpn_install_key"))
	if err != nil {
		t.Fatalf("expected vpn_install_key to exist: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected 0600 permissions, got %o", info.Mode().Perm())
	}
}
