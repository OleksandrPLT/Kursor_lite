package sites

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"text/template"
)

// panelProxyConfName is the fixed filename this vhost is always saved
// under — unlike a regular site (one conf per domain, since there can
// be many), there's only ever one panel, so renaming the panel's own
// domain replaces this same file rather than leaving an orphaned old
// one behind.
const panelProxyConfName = "kursor-panel.conf"

// PanelChallengeRoot is where the ACME HTTP-01 challenge file
// certbot's webroot plugin drops its token — a plain static directory
// Nginx serves directly, entirely separate from any site's own
// docroot, since the panel itself has none.
func PanelChallengeRoot(dataDir string) string {
	return filepath.Join(dataDir, "acme-challenge")
}

var panelProxyTemplate = template.Must(template.New("panel-proxy").Parse(`server {
    listen 80;
    server_name {{.Domain}};

    location /.well-known/acme-challenge/ {
        root {{.ChallengeRoot}};
    }

    location / {
        proxy_pass http://{{.PanelAddr}};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
`))

var panelProxySSLTemplate = template.Must(template.New("panel-proxy-ssl").Parse(`server {
    listen 80;
    server_name {{.Domain}};

    location /.well-known/acme-challenge/ {
        root {{.ChallengeRoot}};
    }

    location / {
        return 301 https://$host$request_uri;
    }
}
server {
    listen 443 ssl;
    server_name {{.Domain}};

    ssl_certificate     /etc/letsencrypt/live/{{.Domain}}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{{.Domain}}/privkey.pem;

    location / {
        proxy_pass http://{{.PanelAddr}};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
`))

type panelProxyVars struct {
	Domain        string
	PanelAddr     string // e.g. "127.0.0.1:8888" — the panel's own real listen address, on the SAME box, so the proxy target never depends on external DNS/routing
	ChallengeRoot string
}

// CreatePanelProxyVhost sets up an HTTP-only (port 80) reverse proxy
// from domain to the panel's own address, so a real Let's Encrypt
// HTTP-01 challenge (see EnablePanelProxySSL) has something to answer
// it on port 80 before a certificate exists. Same
// render->symlink->validate->reload discipline, with full rollback on
// failure, as every other vhost this package manages.
func CreatePanelProxyVhost(domain, panelAddr, challengeRoot string) (Result, error) {
	if !ValidDomain(domain) {
		return Result{}, errors.New("invalid domain")
	}
	st := Detect()
	if !st.Ready() {
		return Result{}, errors.New("nginx not detected on this host")
	}
	if err := os.MkdirAll(challengeRoot, 0o755); err != nil {
		return Result{}, err
	}

	var buf bytes.Buffer
	if err := panelProxyTemplate.Execute(&buf, panelProxyVars{Domain: domain, PanelAddr: panelAddr, ChallengeRoot: challengeRoot}); err != nil {
		return Result{}, err
	}

	confPath := filepath.Join(sitesAvailableDir, panelProxyConfName)
	if err := os.WriteFile(confPath, buf.Bytes(), 0o644); err != nil {
		return Result{}, err
	}
	enabledPath := filepath.Join(sitesEnabledDir, panelProxyConfName)
	if err := os.Symlink(confPath, enabledPath); err != nil && !os.IsExist(err) {
		_ = os.Remove(confPath)
		return Result{}, err
	}

	if err := testConfig(); err != nil {
		_ = os.Remove(enabledPath)
		_ = os.Remove(confPath)
		return Result{}, fmt.Errorf("nginx -t failed, rolled back: %w", err)
	}
	if err := reload(); err != nil {
		return Result{ConfPath: confPath}, fmt.Errorf("config is valid but reload failed: %w", err)
	}
	return Result{ConfPath: confPath}, nil
}

// EnablePanelProxySSL rewrites the panel's proxy vhost to redirect
// plain HTTP to HTTPS and reverse-proxy on 443 with the now-issued
// certificate — called only after IssueCertificate has actually placed
// a cert for domain. Restores the previous (HTTP-only) config on
// validation failure, same as EnableSSLVhost.
func EnablePanelProxySSL(domain, panelAddr, challengeRoot, confPath string) error {
	previous, readErr := os.ReadFile(confPath)

	var buf bytes.Buffer
	if err := panelProxySSLTemplate.Execute(&buf, panelProxyVars{Domain: domain, PanelAddr: panelAddr, ChallengeRoot: challengeRoot}); err != nil {
		return err
	}
	if err := os.WriteFile(confPath, buf.Bytes(), 0o644); err != nil {
		return err
	}

	if err := testConfig(); err != nil {
		if readErr == nil {
			_ = os.WriteFile(confPath, previous, 0o644)
		}
		return fmt.Errorf("nginx -t failed, restored previous config: %w", err)
	}
	return reload()
}
