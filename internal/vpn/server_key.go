package vpn

import (
	"os"
	"path/filepath"
	"strings"
)

// LoadOrGenerateServerKey returns this host's WireGuard server private
// key, generating and persisting one on first use — mirrors internal/
// oidc's signing-key lifecycle. It has to stay stable across restarts:
// every peer config already handed out embeds the server's *public*
// key, so regenerating it on every boot would silently break every
// existing client.
func LoadOrGenerateServerKey(dataDir string) (string, error) {
	path := filepath.Join(dataDir, "wg_server_key")
	if b, err := os.ReadFile(path); err == nil {
		key := strings.TrimSpace(string(b))
		if key != "" {
			return key, nil
		}
	}
	key, err := GeneratePrivateKey()
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(key+"\n"), 0o600); err != nil {
		return "", err
	}
	return key, nil
}
