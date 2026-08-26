// Software: a curated catalog of installable engines/runtimes beyond
// what Sites/Databases already install on their own (Nginx, Certbot) —
// answers "ability to install other versions of Apache, DB, etc.". Each
// entry is a real package name; installing it runs the same real
// apt-get/yum/brew command as every other installer in this codebase
// (see internal/sites.InstallPackage) and shows its real output.
//
// This is deliberately package-manager-driven, not a from-scratch
// multi-version runtime manager (no side-by-side PHP-FPM pool wizard,
// no custom apt pinning UI): whichever version strings this host's own
// repos resolve those package names to is what gets installed, exactly
// like every other "detect → install → show real output" flow already
// in Kursor. A distro without a given package (e.g. plain Ubuntu
// without the ondrej/php PPA for older PHP versions) reports that
// honestly via the real command's own error output, not a paraphrase.
package server

import (
	"net/http"
	"os/exec"

	"kursor/internal/auth"
	ksites "kursor/internal/sites"
)

// SoftwareItem is one catalog entry.
type SoftwareItem struct {
	Key     string // stable identifier used in the install URL
	Name    string
	Package string // the actual package name passed to InstallPackage
	Group   string // "web" | "database" | "runtime" | "cache" — groups the catalog in the UI
}

var softwareCatalog = []SoftwareItem{
	{Key: "apache", Name: "Apache HTTP Server", Package: "apache2", Group: "web"},
	{Key: "mysql", Name: "MySQL Server", Package: "mysql-server", Group: "database"},
	{Key: "mariadb", Name: "MariaDB Server", Package: "mariadb-server", Group: "database"},
	{Key: "postgresql", Name: "PostgreSQL (latest for this distro)", Package: "postgresql", Group: "database"},
	{Key: "postgresql15", Name: "PostgreSQL 15", Package: "postgresql-15", Group: "database"},
	{Key: "postgresql16", Name: "PostgreSQL 16", Package: "postgresql-16", Group: "database"},
	{Key: "redis", Name: "Redis", Package: "redis-server", Group: "cache"},
	{Key: "php74", Name: "PHP 7.4", Package: "php7.4", Group: "runtime"},
	{Key: "php81", Name: "PHP 8.1", Package: "php8.1", Group: "runtime"},
	{Key: "php82", Name: "PHP 8.2", Package: "php8.2", Group: "runtime"},
	{Key: "php83", Name: "PHP 8.3", Package: "php8.3", Group: "runtime"},
	{Key: "nodejs", Name: "Node.js", Package: "nodejs", Group: "runtime"},
}

func findSoftware(key string) (SoftwareItem, bool) {
	for _, it := range softwareCatalog {
		if it.Key == key {
			return it, true
		}
	}
	return SoftwareItem{}, false
}

// SoftwareRow pairs a catalog entry with whether it's already installed
// on this host, best-effort — `dpkg -s`/`rpm -q`/`brew list` are each
// cheap, local, and safe to run just to check.
type SoftwareRow struct {
	SoftwareItem
	Installed bool
}

func softwareInstalled(pkg string) bool {
	switch ksites.DetectPackageManager() {
	case ksites.PMApt:
		return exec.Command("dpkg", "-s", pkg).Run() == nil
	case ksites.PMYum:
		return exec.Command("rpm", "-q", pkg).Run() == nil
	case ksites.PMBrew:
		return exec.Command("brew", "list", pkg).Run() == nil
	default:
		return false
	}
}

// softwareGroups fixes the display order of catalog groups — a Go
// slice handed to the template, since html/template's stdlib FuncMap
// (see templates.go) has no built-in "slice" literal helper the way
// sprig does.
var softwareGroups = []string{"web", "database", "cache", "runtime"}

// SoftwareData backs the Software page.
type SoftwareData struct {
	PageData
	PackageManager string
	Groups         []string
	Rows           []SoftwareRow
	FormErrorKey   string
	ErrorDetail    string
	InstalledName  string
}

func (s *Server) handleSoftwarePage(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	rows := make([]SoftwareRow, 0, len(softwareCatalog))
	for _, it := range softwareCatalog {
		rows = append(rows, SoftwareRow{SoftwareItem: it, Installed: softwareInstalled(it.Package)})
	}
	s.render(w, "software", SoftwareData{
		PageData:       s.basePageData(w, r, "server-software", sess),
		PackageManager: string(ksites.DetectPackageManager()),
		Groups:         softwareGroups,
		Rows:           rows,
	})
}

func (s *Server) handleSoftwareInstall(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	renderErr := func(key, detail string) {
		rows := make([]SoftwareRow, 0, len(softwareCatalog))
		for _, it := range softwareCatalog {
			rows = append(rows, SoftwareRow{SoftwareItem: it, Installed: softwareInstalled(it.Package)})
		}
		s.render(w, "software", SoftwareData{
			PageData:       s.basePageData(w, r, "server-software", sess),
			PackageManager: string(ksites.DetectPackageManager()),
			Groups:         softwareGroups,
			Rows:           rows,
			FormErrorKey:   key,
			ErrorDetail:    detail,
		})
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		renderErr("login.error.csrf", "")
		return
	}
	item, ok := findSoftware(r.FormValue("key"))
	if !ok {
		renderErr("software.error.unknown", "")
		return
	}
	out, err := ksites.InstallPackage(item.Package)
	if err != nil {
		renderErr("software.error.install", out)
		return
	}
	rows := make([]SoftwareRow, 0, len(softwareCatalog))
	for _, it := range softwareCatalog {
		rows = append(rows, SoftwareRow{SoftwareItem: it, Installed: softwareInstalled(it.Package)})
	}
	s.render(w, "software", SoftwareData{
		PageData:       s.basePageData(w, r, "server-software", sess),
		PackageManager: string(ksites.DetectPackageManager()),
		Groups:         softwareGroups,
		Rows:           rows,
		InstalledName:  item.Name,
	})
}
