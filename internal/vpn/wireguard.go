package vpn

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const (
	configPath    = "/etc/wireguard/wg0.conf"
	interfaceName = "wg0"
)

// Status reports what this host actually has, so the UI can show an
// honest banner instead of pretending VPN management just works — same
// idea as internal/sites.Detect for Nginx.
type Status struct {
	Installed bool // `wg` binary found on PATH
}

func Detect() Status {
	_, err := exec.LookPath("wg")
	return Status{Installed: err == nil}
}

// ServerConfig is this host's [Interface] section — the WireGuard
// server itself, one per box.
type ServerConfig struct {
	PrivateKey string
	Address    string // e.g. "10.8.0.1/24"
	ListenPort int
}

// Peer is one [Peer] block — a person or device allowed to connect.
// Only Enabled peers are ever written to disk; disabling one removes it
// from the live config the same way an unchecked cron job is commented
// out — reversible, but with zero effect while off.
type Peer struct {
	Name      string
	PublicKey string
	AllowedIP string // e.g. "10.8.0.2/32"
	Enabled   bool
}

// RenderConfig produces wg0.conf content from a server config and its
// peers — pure string building, unit-testable without touching the
// filesystem or the `wg` binary.
func RenderConfig(server ServerConfig, peers []Peer) string {
	var b strings.Builder
	fmt.Fprintf(&b, "[Interface]\nPrivateKey = %s\nAddress = %s\nListenPort = %d\n", server.PrivateKey, server.Address, server.ListenPort)
	for _, p := range peers {
		if !p.Enabled {
			continue
		}
		fmt.Fprintf(&b, "\n# %s\n[Peer]\nPublicKey = %s\nAllowedIPs = %s\n", p.Name, p.PublicKey, p.AllowedIP)
	}
	return b.String()
}

// reload applies whatever is now on disk. It prefers `wg syncconf` — a
// live, non-disruptive reconfigure that only touches what changed, so
// peers who are already connected and unaffected by this change never
// get dropped — and falls back to a full `wg-quick up` for the
// first-ever apply, when the interface isn't up yet for syncconf to
// target. The syncconf command needs a shell for process substitution;
// that's safe here because the command string is fixed (configPath is a
// constant, not user input), never built from a request.
func reload() error {
	syncCmd := exec.Command("sh", "-c", "wg syncconf "+interfaceName+" <(wg-quick strip "+configPath+")")
	if out, err := syncCmd.CombinedOutput(); err == nil {
		return nil
	} else {
		lastErr := fmt.Errorf("wg syncconf: %s", out)
		if out2, err2 := exec.Command("wg-quick", "up", interfaceName).CombinedOutput(); err2 == nil {
			return nil
		} else {
			return fmt.Errorf("%v; wg-quick up also failed: %s", lastErr, out2)
		}
	}
}

// Apply renders server+peers to wg0.conf and reloads the interface.
// Like Nginx's Create/SetEnabled, this always regenerates the whole
// file from the given data — the file is a view of the database, never
// hand-edited — so a caller never needs to diff peers themselves.
func Apply(server ServerConfig, peers []Peer) error {
	if !Detect().Installed {
		return fmt.Errorf("wireguard-tools (wg) not detected on this host")
	}
	content := RenderConfig(server, peers)
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		return err
	}
	return reload()
}
