// Package firewall manages real host firewall rules via ufw or
// firewalld — whichever this host actually has. Unlike cron/vpn/dns,
// there's no Kursor-owned config file here: ufw/firewalld's own live
// rule set IS the truth, queried fresh on every page load and changed
// directly through their own CLIs, the same way an operator would by
// hand.
package firewall

import (
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

type Backend string

const (
	BackendUFW       Backend = "ufw"
	BackendFirewalld Backend = "firewalld"
	BackendNone      Backend = ""
)

// Detect prefers ufw (Debian/Ubuntu's default, and this project's
// "general Linux first" convention) over firewalld, and only reports a
// backend as usable if it's actually active — a present-but-inactive
// firewall means "not managing this host's ports right now" as far as
// the operator is concerned.
func Detect() Backend {
	if _, err := exec.LookPath("ufw"); err == nil {
		out, _ := exec.Command("ufw", "status").CombinedOutput()
		if strings.Contains(string(out), "Status: active") {
			return BackendUFW
		}
	}
	if _, err := exec.LookPath("firewall-cmd"); err == nil {
		if err := exec.Command("firewall-cmd", "--state").Run(); err == nil {
			return BackendFirewalld
		}
	}
	return BackendNone
}

// Installed reports whether ufw is present at all (even inactive) — the
// UI uses this to offer "install" vs. "enable" distinctly.
func UFWInstalled() bool {
	_, err := exec.LookPath("ufw")
	return err == nil
}

// Rule is one allowed port.
type Rule struct {
	Port  int
	Proto string // "tcp" | "udp"
	Raw   string // the backend's own label for this rule, shown as-is for anything this package's parser doesn't fully understand
}

// ValidPort/ValidProto guard every value that reaches a shell command —
// the real injection boundary here, same role as dbmanager.ValidIdentifier.
func ValidPort(p int) bool     { return p >= 1 && p <= 65535 }
func ValidProto(p string) bool { return p == "tcp" || p == "udp" }

var ufwRuleRe = regexp.MustCompile(`^(\d+)/(tcp|udp)\s*(?:\(v6\))?\s+ALLOW`)

// ListRules returns every currently-allowed port, parsed from the
// backend's own live status output.
func ListRules(backend Backend) ([]Rule, error) {
	switch backend {
	case BackendUFW:
		out, err := exec.Command("ufw", "status").CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("ufw status: %s", out)
		}
		var rules []Rule
		seen := map[string]bool{}
		for _, line := range strings.Split(string(out), "\n") {
			m := ufwRuleRe.FindStringSubmatch(strings.TrimSpace(line))
			if m == nil {
				continue
			}
			key := m[1] + "/" + m[2]
			if seen[key] {
				continue // ufw lists v4/v6 as separate lines for the same rule
			}
			seen[key] = true
			port, _ := strconv.Atoi(m[1])
			rules = append(rules, Rule{Port: port, Proto: m[2], Raw: strings.TrimSpace(line)})
		}
		return rules, nil
	case BackendFirewalld:
		out, err := exec.Command("firewall-cmd", "--list-ports").CombinedOutput()
		if err != nil {
			return nil, fmt.Errorf("firewall-cmd --list-ports: %s", out)
		}
		var rules []Rule
		for _, tok := range strings.Fields(string(out)) {
			parts := strings.SplitN(tok, "/", 2)
			if len(parts) != 2 {
				continue
			}
			port, err := strconv.Atoi(parts[0])
			if err != nil {
				continue
			}
			rules = append(rules, Rule{Port: port, Proto: parts[1], Raw: tok})
		}
		return rules, nil
	default:
		return nil, fmt.Errorf("no active firewall backend detected")
	}
}

// OpenPort/ClosePort validate first (the only real defense — these
// values reach a real shell command) then run the backend's own real
// command, surfacing its actual output on failure.
func OpenPort(backend Backend, port int, proto string) error {
	if !ValidPort(port) || !ValidProto(proto) {
		return fmt.Errorf("invalid port/protocol")
	}
	switch backend {
	case BackendUFW:
		out, err := exec.Command("ufw", "allow", fmt.Sprintf("%d/%s", port, proto)).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s", out)
		}
		return nil
	case BackendFirewalld:
		if out, err := exec.Command("firewall-cmd", "--permanent", "--add-port="+fmt.Sprintf("%d/%s", port, proto)).CombinedOutput(); err != nil {
			return fmt.Errorf("%s", out)
		}
		out, err := exec.Command("firewall-cmd", "--reload").CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s", out)
		}
		return nil
	default:
		return fmt.Errorf("no active firewall backend detected")
	}
}

func ClosePort(backend Backend, port int, proto string) error {
	if !ValidPort(port) || !ValidProto(proto) {
		return fmt.Errorf("invalid port/protocol")
	}
	switch backend {
	case BackendUFW:
		out, err := exec.Command("ufw", "delete", "allow", fmt.Sprintf("%d/%s", port, proto)).CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s", out)
		}
		return nil
	case BackendFirewalld:
		if out, err := exec.Command("firewall-cmd", "--permanent", "--remove-port="+fmt.Sprintf("%d/%s", port, proto)).CombinedOutput(); err != nil {
			return fmt.Errorf("%s", out)
		}
		out, err := exec.Command("firewall-cmd", "--reload").CombinedOutput()
		if err != nil {
			return fmt.Errorf("%s", out)
		}
		return nil
	default:
		return fmt.Errorf("no active firewall backend detected")
	}
}

// EnableUFW turns ufw on — `ufw --force enable` skips its interactive
// "this may disrupt SSH" confirmation prompt, which would otherwise hang
// forever with no TTY attached (same non-interactive posture as every
// other install/apply command in this codebase).
func EnableUFW() error {
	out, err := exec.Command("ufw", "--force", "enable").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", out)
	}
	return nil
}
