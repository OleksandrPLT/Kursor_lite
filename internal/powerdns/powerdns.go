// Package powerdns manages a real authoritative DNS server — PowerDNS
// Authoritative Server with its SQLite backend — for domains that get
// their own custom nameservers pointed at this box. This is a
// different job from internal/dns (dnsmasq): that one is a lightweight
// forwarder/resolver for a LAN/VPN, this one has to answer correctly
// for anyone on the internet asking about a delegated zone (proper
// SOA/NS handling), which dnsmasq was never built for.
//
// PowerDNS's own REST API (its "webserver", bound to 127.0.0.1 only) is
// the management surface here, not a config file this package renders
// — zone/record changes take effect immediately through the API, no
// restart needed per change, unlike every other module in this
// codebase. The one-time setup (config drop-in + SQLite schema load +
// service start) is the only file-touching/restart step.
package powerdns

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	_ "modernc.org/sqlite" // pure-Go driver — same one internal/store uses, so loading PowerDNS's schema needs no external `sqlite3` CLI (which pdns-backend-sqlite3 doesn't pull in as a dependency)
)

const (
	confDropIn    = "/etc/powerdns/pdns.d/kursor.conf"
	sqlitePath    = "/var/lib/powerdns/pdns.sqlite3"
	apiBase       = "http://127.0.0.1:8081/api/v1/servers/localhost"
	webserverPort = "8081"
)

// schemaSearchPaths covers where Debian/Ubuntu's pdns-backend-sqlite3
// package puts the schema to load into a fresh database — tried in
// order, first one found wins.
var schemaSearchPaths = []string{
	"/usr/share/pdns-backend-sqlite3/schema/schema.sqlite3.sql",
	"/usr/share/doc/pdns-backend-sqlite3/schema.sqlite3.sql",
	"/usr/share/doc/pdns-backend-sqlite3/schema.sqlite3.sql.gz",
}

// Status reports what this host actually has.
type Status struct {
	Installed bool // `pdns_server` binary found on PATH
}

func Detect() Status {
	_, err := exec.LookPath("pdns_server")
	return Status{Installed: err == nil}
}

// LoadOrGenerateAPIKey returns Kursor's PowerDNS API key, generating and
// persisting one on first use — same lifecycle as every other
// Kursor-owned service credential (WireGuard server key, OIDC signing
// key, mail master password): root-only on disk, never shown to a user.
func LoadOrGenerateAPIKey(dataDir string) (string, error) {
	path := filepath.Join(dataDir, "powerdns_api_key")
	if b, err := os.ReadFile(path); err == nil {
		if key := strings.TrimSpace(string(b)); key != "" {
			return key, nil
		}
	}
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	key := base64.RawURLEncoding.EncodeToString(buf)
	if err := os.WriteFile(path, []byte(key+"\n"), 0o600); err != nil {
		return "", err
	}
	return key, nil
}

func renderConfDropIn(apiKey string) string {
	return fmt.Sprintf(`# Managed by Kursor — do not edit by hand. Additive drop-in (pdns.conf's
# own include-dir picks this up); never touches the rest of this
# host's PowerDNS config.
launch=gsqlite3
gsqlite3-database=%s
api=yes
api-key=%s
webserver=yes
webserver-address=127.0.0.1
webserver-port=%s
webserver-allow-from=127.0.0.1
`, sqlitePath, apiKey, webserverPort)
}

func findSchema() (string, error) {
	for _, p := range schemaSearchPaths {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", errors.New("PowerDNS SQLite schema file not found (is pdns-backend-sqlite3 installed?)")
}

// EnsureConfigured writes the conf.d drop-in (idempotent — always
// regenerated, same as every other module's managed config), loads the
// SQLite schema into a fresh database if one doesn't exist yet, and
// (re)starts the service. Safe to call before every apply, the same
// way applyDNSConfig/applyVPNConfig always regenerate their files.
func EnsureConfigured(dataDir string) error {
	if !Detect().Installed {
		return errors.New("PowerDNS not detected on this host")
	}
	apiKey, err := LoadOrGenerateAPIKey(dataDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(confDropIn), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(confDropIn, []byte(renderConfDropIn(apiKey)), 0o640); err != nil {
		return err
	}
	// Written as root, but pdns_server runs as its own unprivileged
	// "pdns" user/group (same as the package's own pdns.conf, which is
	// root:pdns 0640 — matched here so the daemon can actually read a
	// file Kursor just wrote) — without this it fails to start with
	// "Unable to open ... could not be parsed", which reads like a
	// syntax error but is really a permissions error.
	_, _ = exec.Command("chown", "root:pdns", confDropIn).CombinedOutput()

	// The package installs its own example drop-in (pdns.d/bind.conf,
	// launch=bind) alongside ours — not a real operator config (a fresh
	// install has no bind zones defined at all), but its `launch=bind`
	// conflicts with our `launch=gsqlite3`: PowerDNS ends up with
	// bind-only settings active while the bind backend itself isn't
	// launched, which is a fatal "unknown setting" at startup. Disabled
	// by rename (recoverable), not deleted, and only once.
	defaultBindConf := filepath.Join(filepath.Dir(confDropIn), "bind.conf")
	if _, err := os.Stat(defaultBindConf); err == nil {
		_ = os.Rename(defaultBindConf, defaultBindConf+".disabled-by-kursor")
	}

	if _, err := os.Stat(sqlitePath); os.IsNotExist(err) {
		if err := loadSchema(); err != nil {
			return err
		}
	}

	return restart()
}

// loadSchema creates a fresh PowerDNS SQLite database and loads its
// schema — via database/sql + the pure-Go sqlite driver (already a
// dependency for Kursor's own store), not the `sqlite3` CLI, which
// pdns-backend-sqlite3 doesn't pull in and so isn't guaranteed present.
func loadSchema() error {
	schema, err := findSchema()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(sqlitePath), 0o755); err != nil {
		return err
	}
	schemaSQL, err := os.ReadFile(schema)
	if err != nil {
		return fmt.Errorf("read schema: %w", err)
	}

	db, err := sql.Open("sqlite", sqlitePath)
	if err != nil {
		return fmt.Errorf("create sqlite db: %w", err)
	}
	defer db.Close()
	if _, err := db.Exec(string(schemaSQL)); err != nil {
		return fmt.Errorf("load pdns schema: %w", err)
	}

	// Kursor runs as root and just created this file — PowerDNS itself
	// runs as its own unprivileged "pdns" user (same as the directory
	// its package install already created), so without this chown the
	// daemon can create the file's *parent* dir but can never open the
	// database Kursor just wrote.
	_, _ = exec.Command("chown", "pdns:pdns", sqlitePath).CombinedOutput()
	return nil
}

func restart() error {
	for _, unit := range []string{"pdns", "pdns-server", "powerdns"} {
		if out, err := exec.Command("systemctl", "restart", unit).CombinedOutput(); err == nil {
			return nil
		} else if !strings.Contains(string(out), "not loaded") && !strings.Contains(string(out), "not found") {
			// A real failure on a unit that does exist — surface it
			// rather than silently trying the next guessed name.
			return fmt.Errorf("systemctl restart %s: %s", unit, out)
		}
	}
	return errors.New("no PowerDNS systemd unit found (tried pdns, pdns-server, powerdns)")
}

var domainRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$`)

func ValidDomain(d string) bool { return domainRe.MatchString(d) }

// canonical appends the trailing dot PowerDNS's API expects everywhere
// a domain/hostname appears.
func canonical(name string) string {
	name = strings.TrimSpace(name)
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	return name
}
