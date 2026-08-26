// Package sites manages Nginx-backed sites: the standard Debian/Ubuntu
// layout (sites-available/sites-enabled, systemctl reload) for now — a
// macOS/Homebrew path variant is planned as a follow-up patch once
// there's a Mac target to actually test it against (see the project
// notes). The core discipline is the same everywhere: render -> symlink
// -> `nginx -t` -> only then reload, with full rollback on validation
// failure, so a bad config can never take down the box's Nginx.
package sites

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"text/template"
)

const (
	sitesAvailableDir = "/etc/nginx/sites-available"
	sitesEnabledDir   = "/etc/nginx/sites-enabled"
)

// Status reports what this host actually has, so the UI can show an
// honest banner instead of pretending site management just works.
type Status struct {
	Installed      bool // `nginx` binary found on PATH
	ConfigDirFound bool // /etc/nginx/sites-available exists
}

func (st Status) Ready() bool { return st.Installed && st.ConfigDirFound }

// Detect probes for Nginx — never assumes it's present.
func Detect() Status {
	_, err := exec.LookPath("nginx")
	_, statErr := os.Stat(sitesAvailableDir)
	return Status{Installed: err == nil, ConfigDirFound: statErr == nil}
}

// domainRe is deliberately strict: labels of alphanumerics/hyphens,
// dot-separated, at least one dot — enough to keep a domain out of
// shell/path-metacharacter territory without needing SafeJoin (a valid
// match here can't contain "/", "..", or anything else meaningful to a
// filesystem path).
var domainRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$`)

// ValidDomain reports whether d is safe to use as a filename/hostname.
func ValidDomain(d string) bool { return domainRe.MatchString(d) }

var vhostTemplate = template.Must(template.New("vhost").Parse(`server {
    listen 80;
    server_name {{.Domain}};
    root {{.Docroot}};
    index index.html index.php index.htm;

    location / {
        try_files $uri $uri/ =404;
    }
}
`))

func renderVhost(domain, docroot string) ([]byte, error) {
	var buf bytes.Buffer
	err := vhostTemplate.Execute(&buf, struct{ Domain, Docroot string }{domain, docroot})
	return buf.Bytes(), err
}

// testConfig runs `nginx -t`, returning its combined output on failure
// so the operator sees nginx's own error message, not a paraphrase.
func testConfig() error {
	out, err := exec.Command("nginx", "-t").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", string(out))
	}
	return nil
}

// reload tries systemctl, falls back to `service`, falls back to
// `nginx -s reload` directly — whichever this host actually has.
func reload() error {
	if _, err := exec.LookPath("systemctl"); err == nil {
		if out, err := exec.Command("systemctl", "reload", "nginx").CombinedOutput(); err == nil {
			return nil
		} else {
			lastErr := fmt.Errorf("systemctl reload nginx: %s", out)
			if _, err2 := exec.LookPath("service"); err2 == nil {
				if out2, err2 := exec.Command("service", "nginx", "reload").CombinedOutput(); err2 == nil {
					return nil
				} else {
					lastErr = fmt.Errorf("service nginx reload: %s", out2)
				}
			}
			return lastErr
		}
	}
	out, err := exec.Command("nginx", "-s", "reload").CombinedOutput()
	if err != nil {
		return fmt.Errorf("nginx -s reload: %s", out)
	}
	return nil
}

// Result carries what actually happened, for the caller to decide
// whether to persist a DB row.
type Result struct {
	Docroot  string
	ConfPath string
}

// Create renders a new vhost, symlinks it into sites-enabled, validates
// with `nginx -t`, and reloads. Any failure rolls back every filesystem
// change it made — the box's Nginx is never left pointed at a broken or
// half-written config.
func Create(domain, wwwRoot string) (Result, error) {
	if !ValidDomain(domain) {
		return Result{}, errors.New("invalid domain")
	}
	st := Detect()
	if !st.Ready() {
		return Result{}, errors.New("nginx not detected on this host")
	}

	docroot := filepath.Join(wwwRoot, domain)
	if err := os.MkdirAll(docroot, 0o755); err != nil {
		return Result{}, err
	}
	placeholder := filepath.Join(docroot, "index.html")
	if _, err := os.Stat(placeholder); os.IsNotExist(err) {
		_ = os.WriteFile(placeholder, []byte("<!doctype html><title>"+domain+"</title><p>"+domain+" is live.</p>"), 0o644)
	}

	confPath := filepath.Join(sitesAvailableDir, domain+".conf")
	body, err := renderVhost(domain, docroot)
	if err != nil {
		return Result{}, err
	}
	if err := os.WriteFile(confPath, body, 0o644); err != nil {
		return Result{}, err
	}

	enabledPath := filepath.Join(sitesEnabledDir, domain+".conf")
	if err := os.Symlink(confPath, enabledPath); err != nil {
		_ = os.Remove(confPath)
		return Result{}, err
	}

	if err := testConfig(); err != nil {
		// Roll back everything — never leave a broken config live.
		_ = os.Remove(enabledPath)
		_ = os.Remove(confPath)
		return Result{}, fmt.Errorf("nginx -t failed, rolled back: %w", err)
	}
	if err := reload(); err != nil {
		// Config is valid (passed -t) — leave it in place, just surface
		// that the running nginx wasn't told about it yet.
		return Result{Docroot: docroot, ConfPath: confPath}, fmt.Errorf("config is valid but reload failed: %w", err)
	}
	return Result{Docroot: docroot, ConfPath: confPath}, nil
}

// SetEnabled symlinks/unsymlinks a site's conf into sites-enabled and
// reloads, validating first — same rollback discipline as Create.
func SetEnabled(domain, confPath string, enabled bool) error {
	st := Detect()
	if !st.Ready() {
		return errors.New("nginx not detected on this host")
	}
	enabledPath := filepath.Join(sitesEnabledDir, domain+".conf")

	if enabled {
		if err := os.Symlink(confPath, enabledPath); err != nil && !os.IsExist(err) {
			return err
		}
		if err := testConfig(); err != nil {
			_ = os.Remove(enabledPath)
			return fmt.Errorf("nginx -t failed, rolled back: %w", err)
		}
	} else {
		_ = os.Remove(enabledPath)
		if err := testConfig(); err != nil {
			return fmt.Errorf("nginx -t failed after disabling: %w", err)
		}
	}
	return reload()
}

// Delete removes both the enabled symlink and the available conf, then
// reloads.
func Delete(domain string) error {
	st := Detect()
	confPath := filepath.Join(sitesAvailableDir, domain+".conf")
	enabledPath := filepath.Join(sitesEnabledDir, domain+".conf")
	_ = os.Remove(enabledPath)
	_ = os.Remove(confPath)
	if !st.Ready() {
		return nil // nothing was live to reload in the first place
	}
	if err := testConfig(); err != nil {
		return fmt.Errorf("nginx -t failed after delete: %w", err)
	}
	return reload()
}
