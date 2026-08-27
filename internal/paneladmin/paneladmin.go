// Package paneladmin manages the running kursord process's own
// systemd unit — specifically, changing the port it listens on. This
// is the one setting in the whole panel where a mistake can lock the
// operator out of the very tool they'd use to fix it, so every safety
// rail applies: never touch the currently-working port, the caller
// (internal/server/panelsettings.go) is required to open the new port
// in the firewall BEFORE calling SetPort (same discipline
// internal/sshadmin's SetPort already documents), and applying the
// change is a separate, explicit RestartPanel call the caller only
// makes after it has already sent the operator a response explaining
// what's about to happen.
package paneladmin

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

const unitPath = "/etc/systemd/system/kursor.service"

var addrLineRe = regexp.MustCompile(`(?m)^Environment=KURSOR_ADDR=.*$`)

// CurrentPort reads the port kursord's own unit file currently
// specifies — not what this running process happens to be bound to
// right now (cfg.Addr, already known to the caller), but what it WILL
// be bound to after the next restart, so the settings page can tell
// the two apart if a previous change never got applied.
func CurrentPort() (int, error) {
	content, err := os.ReadFile(unitPath)
	if err != nil {
		return 0, err
	}
	m := addrLineRe.FindString(string(content))
	if m == "" {
		return 0, errors.New("paneladmin: KURSOR_ADDR not found in the unit file")
	}
	return parsePortFromAddrLine(m)
}

// parsePortFromAddrLine pulls the numeric port out of a line like
// "Environment=KURSOR_ADDR=:8888" — split out from CurrentPort so the
// parsing itself is unit-testable without a real unit file on disk.
func parsePortFromAddrLine(line string) (int, error) {
	i := strings.LastIndex(line, ":")
	if i < 0 || i == len(line)-1 {
		return 0, fmt.Errorf("paneladmin: couldn't find a port in %q", line)
	}
	port, err := strconv.Atoi(line[i+1:])
	if err != nil {
		return 0, fmt.Errorf("paneladmin: invalid port in %q: %w", line, err)
	}
	return port, nil
}

// SetPort rewrites the unit file's KURSOR_ADDR line and reloads
// systemd's view of it — it does NOT restart the service. The new port
// only takes effect once the caller explicitly calls RestartPanel,
// after the current request has already told the operator a restart
// is coming.
func SetPort(port int) error {
	if port < 1 || port > 65535 {
		return errors.New("invalid port")
	}
	content, err := os.ReadFile(unitPath)
	if err != nil {
		return err
	}
	if !addrLineRe.Match(content) {
		return errors.New("paneladmin: KURSOR_ADDR not found in the unit file — refusing to guess where to add it")
	}
	updated := addrLineRe.ReplaceAll(content, []byte(fmt.Sprintf("Environment=KURSOR_ADDR=:%d", port)))
	if err := os.WriteFile(unitPath, updated, 0o644); err != nil {
		return err
	}
	if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		// Roll back — a unit file systemd itself can't even reload is
		// worse than not having tried, and daemon-reload failing at all
		// almost always means the file is now malformed.
		_ = os.WriteFile(unitPath, content, 0o644)
		_, _ = exec.Command("systemctl", "daemon-reload").CombinedOutput()
		return fmt.Errorf("systemctl daemon-reload rejected the change, rolled back: %s", out)
	}
	return nil
}

// RestartPanel restarts kursord itself, picking up whatever SetPort (or
// any other unit-file edit) last wrote — this WILL drop the current
// connection; only call it after the request that triggered it has
// already responded.
func RestartPanel() error {
	if out, err := exec.Command("systemctl", "restart", "kursor.service").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl restart kursor.service: %s", out)
	}
	return nil
}
