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
// target.
//
// `wg syncconf` needs its input pre-stripped of wg-quick-only
// directives (Address, ListenPort's alternate forms, etc.) via
// `wg-quick strip`, routed through a real temp file rather than shell
// process substitution (`wg syncconf wg0 <(wg-quick strip ...)`) — that
// syntax needs bash, and `/bin/sh` on Debian/Ubuntu is dash, which
// doesn't support it and fails with a plain "Syntax error" on every
// reload after the very first (that first one only ever worked because
// the interface wasn't up yet, so it took the wg-quick-up fallback
// path below instead — this bashism was never actually exercised until
// a second reload was attempted on a server where the interface was
// already up, silently blocking every future peer change).
func reload() error {
	if err := syncViaStrippedConfig(); err == nil {
		return nil
	} else if out, err2 := exec.Command("wg-quick", "up", interfaceName).CombinedOutput(); err2 == nil {
		return nil
	} else if strings.Contains(string(out), "already exists") {
		// wg-quick up refuses because the interface is already up, but
		// syncconf (the non-disruptive path) just failed for some other
		// reason — down+up is the blunt last resort: it briefly drops
		// every currently-connected peer, unlike syncconf, but that's
		// still better than silently leaving a newly added/edited peer
		// unable to connect at all.
		_, _ = exec.Command("wg-quick", "down", interfaceName).CombinedOutput()
		if out3, err3 := exec.Command("wg-quick", "up", interfaceName).CombinedOutput(); err3 == nil {
			return nil
		} else {
			return fmt.Errorf("%v; wg-quick down+up also failed: %s", err, out3)
		}
	} else {
		return fmt.Errorf("%v; wg-quick up also failed: %s", err, out)
	}
}

// syncViaStrippedConfig runs `wg-quick strip` (which understands
// wg0.conf's wg-quick-only directives and drops them) into a temp
// file, then feeds that to `wg syncconf` — the two real commands the
// old process-substitution one-liner ran, just without needing a shell
// that supports `<()`.
func syncViaStrippedConfig() error {
	stripped, err := exec.Command("wg-quick", "strip", configPath).Output()
	if err != nil {
		return fmt.Errorf("wg-quick strip: %w", err)
	}
	tmp, err := os.CreateTemp("", "wg0-strip-*.conf")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(stripped); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if out, err := exec.Command("wg", "syncconf", interfaceName, tmp.Name()).CombinedOutput(); err != nil {
		return fmt.Errorf("wg syncconf: %s", out)
	}
	return nil
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
