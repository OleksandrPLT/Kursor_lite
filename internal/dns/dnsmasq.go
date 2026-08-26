// Package dns manages real DNS records via dnsmasq — the same
// render→validate→reload discipline internal/sites uses for Nginx and
// internal/vpn uses for WireGuard, applied to `dnsmasq` instead.
// dnsmasq (not BIND/PowerDNS) is the deliberate choice here: it's a
// single small config file and a single binary already present on most
// Debian/Ubuntu boxes, which fits Kursor's single-binary/no-extra-infra
// philosophy far better than running a full authoritative nameserver.
package dns

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

const configPath = "/etc/dnsmasq.d/kursor.conf"

// Status reports what this host actually has.
type Status struct {
	Installed bool // `dnsmasq` binary found on PATH
}

func Detect() Status {
	_, err := exec.LookPath("dnsmasq")
	return Status{Installed: err == nil}
}

// domainRe mirrors internal/sites.ValidDomain (kept local — a DNS
// record's name/target is conceptually the same "safe as a hostname"
// check, and this package has no reason to import internal/sites).
var domainRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$`)

func ValidName(d string) bool { return domainRe.MatchString(d) }

// Record is one DNS entry. Priority is only meaningful for MX.
type Record struct {
	Name     string
	Type     string // "A" | "AAAA" | "CNAME" | "MX" | "TXT"
	Value    string
	Priority int
}

// Validate checks a record's shape before it's ever handed to Apply —
// every field ends up as a literal in a dnsmasq config line, so this is
// the injection boundary (a newline or stray comma in a text value
// could otherwise smuggle in a whole extra directive).
func Validate(r Record) error {
	if !ValidName(r.Name) {
		return errors.New("invalid record name")
	}
	switch r.Type {
	case "A":
		ip := net.ParseIP(r.Value)
		if ip == nil || ip.To4() == nil {
			return errors.New("invalid IPv4 address")
		}
	case "AAAA":
		ip := net.ParseIP(r.Value)
		if ip == nil || ip.To4() != nil {
			return errors.New("invalid IPv6 address")
		}
	case "CNAME", "MX":
		if !ValidName(r.Value) {
			return errors.New("invalid target hostname")
		}
	case "TXT":
		if r.Value == "" || strings.ContainsAny(r.Value, ",\n\r") {
			return errors.New("invalid TXT value (no commas or newlines)")
		}
	default:
		return fmt.Errorf("unsupported record type %q", r.Type)
	}
	return nil
}

// RenderConfig produces kursor.conf content — pure string building,
// unit-testable without touching the filesystem or dnsmasq itself.
func RenderConfig(records []Record) string {
	var b strings.Builder
	for _, r := range records {
		switch r.Type {
		case "A", "AAAA":
			fmt.Fprintf(&b, "address=/%s/%s\n", r.Name, r.Value)
		case "CNAME":
			fmt.Fprintf(&b, "cname=%s,%s\n", r.Name, r.Value)
		case "MX":
			fmt.Fprintf(&b, "mx-host=%s,%s,%d\n", r.Name, r.Value, r.Priority)
		case "TXT":
			fmt.Fprintf(&b, "txt-record=%s,%s\n", r.Name, r.Value)
		}
	}
	return b.String()
}

// testConfig runs `dnsmasq --test`, which parses the full effective
// config (including conf-dir, so it does exercise our dropped-in file)
// without starting the daemon.
func testConfig() error {
	out, err := exec.Command("dnsmasq", "--test").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", string(out))
	}
	return nil
}

func reload() error {
	if _, err := exec.LookPath("systemctl"); err == nil {
		if out, err := exec.Command("systemctl", "restart", "dnsmasq").CombinedOutput(); err == nil {
			return nil
		} else {
			lastErr := fmt.Errorf("systemctl restart dnsmasq: %s", out)
			if _, err2 := exec.LookPath("service"); err2 == nil {
				if out2, err2 := exec.Command("service", "dnsmasq", "restart").CombinedOutput(); err2 == nil {
					return nil
				} else {
					lastErr = fmt.Errorf("service dnsmasq restart: %s", out2)
				}
			}
			return lastErr
		}
	}
	return errors.New("no systemctl/service found to restart dnsmasq")
}

// Apply renders every record to kursor.conf, validates with
// `dnsmasq --test`, and reloads — rolling back the file on validation
// failure so a bad record can never take down the box's DNS resolution,
// same discipline as Nginx's Create/SetEnabled.
func Apply(records []Record) error {
	if !Detect().Installed {
		return errors.New("dnsmasq not detected on this host")
	}
	var previous []byte
	hadPrevious := false
	if b, err := os.ReadFile(configPath); err == nil {
		previous = b
		hadPrevious = true
	}

	content := RenderConfig(records)
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(configPath, []byte(content), 0o644); err != nil {
		return err
	}

	if err := testConfig(); err != nil {
		if hadPrevious {
			_ = os.WriteFile(configPath, previous, 0o644)
		} else {
			_ = os.Remove(configPath)
		}
		return fmt.Errorf("dnsmasq --test failed, rolled back: %w", err)
	}
	return reload()
}
