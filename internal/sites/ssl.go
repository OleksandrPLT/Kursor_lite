package sites

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"text/template"
	"time"
)

const certbotLiveDir = "/etc/letsencrypt/live"

// DetectCertbot reports whether the `certbot` CLI is on PATH. Renewal
// is deliberately NOT reimplemented here — a standard certbot install
// ships its own systemd timer / cron job that renews automatically;
// duplicating that would just be a second, worse renewer.
func DetectCertbot() bool {
	_, err := exec.LookPath("certbot")
	return err == nil
}

// CertStatus is what the UI shows for one domain — computed by actually
// reading and parsing the certificate on disk (real crypto/x509
// parsing, not a guess from a file's mtime).
type CertStatus struct {
	Exists    bool
	ExpiresAt time.Time
	DaysLeft  int
	Error     string
}

// GetCertStatus reads /etc/letsencrypt/live/<domain>/fullchain.pem, if
// present, and parses the leaf certificate's real expiry.
func GetCertStatus(domain string) CertStatus {
	certPath := filepath.Join(certbotLiveDir, domain, "fullchain.pem")
	data, err := os.ReadFile(certPath)
	if err != nil {
		return CertStatus{Exists: false}
	}
	return parseCertStatus(data)
}

// parseCertStatus does the actual PEM/x509 parsing, split out from
// GetCertStatus so it's testable with synthetic certificate bytes
// instead of needing a real file on disk (see ssl_test.go).
func parseCertStatus(data []byte) CertStatus {
	block, _ := pem.Decode(data)
	if block == nil {
		return CertStatus{Exists: false, Error: "couldn't parse certificate PEM"}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return CertStatus{Exists: false, Error: err.Error()}
	}
	return CertStatus{
		Exists:    true,
		ExpiresAt: cert.NotAfter,
		DaysLeft:  int(time.Until(cert.NotAfter).Hours() / 24),
	}
}

// IssueCertificate runs certbot in webroot mode — it drops a challenge
// file under docroot/.well-known/acme-challenge/ and Let's Encrypt
// fetches it over the site's existing plain-HTTP vhost, so the site
// must already be reachable on port 80 for this to succeed.
func IssueCertificate(domain, docroot, email string) error {
	if !DetectCertbot() {
		return errors.New("certbot not detected on this host")
	}
	args := []string{"certonly", "--webroot", "-w", docroot, "-d", domain, "-n", "--agree-tos"}
	if email != "" {
		args = append(args, "-m", email, "--no-eff-email")
	} else {
		args = append(args, "--register-unsafely-without-email")
	}
	out, err := exec.Command("certbot", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", out)
	}
	return nil
}

var sslVhostTemplate = template.Must(template.New("ssl-vhost").Parse(`server {
    listen 80;
    server_name {{.Domain}};
    location /.well-known/acme-challenge/ {
        root {{.Docroot}};
    }
    location / {
        return 301 https://$host$request_uri;
    }
}
server {
    listen 443 ssl;
    server_name {{.Domain}};
    root {{.Docroot}};
    index index.html index.php index.htm;

    ssl_certificate     /etc/letsencrypt/live/{{.Domain}}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{{.Domain}}/privkey.pem;

    location / {
        try_files $uri $uri/ =404;
    }
}
`))

func renderSSLVhost(domain, docroot string) ([]byte, error) {
	var buf bytes.Buffer
	err := sslVhostTemplate.Execute(&buf, struct{ Domain, Docroot string }{domain, docroot})
	return buf.Bytes(), err
}

// EnableSSLVhost rewrites a site's vhost to redirect plain HTTP to
// HTTPS and serve on 443 with the issued certificate — same
// validate-before-reload discipline as Create: nginx -t first, and the
// PREVIOUS working config is restored on failure rather than left
// broken.
func EnableSSLVhost(domain, docroot, confPath string) error {
	previous, readErr := os.ReadFile(confPath)

	body, err := renderSSLVhost(domain, docroot)
	if err != nil {
		return err
	}
	if err := os.WriteFile(confPath, body, 0o644); err != nil {
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
