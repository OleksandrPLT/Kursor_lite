package sites

import (
	"errors"
	"os/exec"
)

// PackageManager is whichever of the common ones this host actually has.
type PackageManager string

const (
	PMApt  PackageManager = "apt"  // Debian/Ubuntu
	PMYum  PackageManager = "yum"  // RHEL/CentOS/Fedora (older)
	PMBrew PackageManager = "brew" // macOS (Homebrew) — the deferred "Mac patch" path
	PMNone PackageManager = ""
)

// DetectPackageManager probes for a package manager on PATH, preferring
// apt/yum (the "general first" Linux targets) over brew.
func DetectPackageManager() PackageManager {
	if _, err := exec.LookPath("apt-get"); err == nil {
		return PMApt
	}
	if _, err := exec.LookPath("yum"); err == nil {
		return PMYum
	}
	if _, err := exec.LookPath("brew"); err == nil {
		return PMBrew
	}
	return PMNone
}

// installCommand returns the OS-appropriate command to install pkg
// non-interactively.
func installCommand(pm PackageManager, pkg string) (*exec.Cmd, error) {
	switch pm {
	case PMApt:
		// Kursor runs as root in production (see the project's SECURITY
		// notes) so no `sudo` prefix is needed there; in this dev
		// session it'll fail with a permissions error instead, same as
		// any other command a non-root user can't run — surfaced
		// honestly via the command's own output, not silently retried
		// with a password prompt that could hang the request forever.
		return exec.Command("apt-get", "install", "-y", pkg), nil
	case PMYum:
		return exec.Command("yum", "install", "-y", pkg), nil
	case PMBrew:
		return exec.Command("brew", "install", pkg), nil
	default:
		return nil, errors.New("no supported package manager detected (apt-get, yum, brew)")
	}
}

// InstallPackage runs the install synchronously and returns the
// command's combined output — real command output for the operator to
// read, not a paraphrase, matching testConfig()'s discipline elsewhere
// in this package.
func InstallPackage(pkg string) (output string, err error) {
	pm := DetectPackageManager()
	cmd, err := installCommand(pm, pkg)
	if err != nil {
		return "", err
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// InstallNginx installs the nginx package for this host's package manager.
func InstallNginx() (string, error) { return InstallPackage("nginx") }

// InstallCertbot installs certbot. (On Debian/Ubuntu this is often
// packaged as python3-certbot; plain "certbot" resolves correctly on
// current releases and via Homebrew.)
func InstallCertbot() (string, error) { return InstallPackage("certbot") }

// InstallWireGuard installs the WireGuard tooling (`wg`, `wg-quick`) —
// the package name differs by manager: Debian/Ubuntu ship it as
// "wireguard" (kernel module + tools together), RHEL/Fedora and
// Homebrew ship the userspace tools alone as "wireguard-tools".
func InstallWireGuard() (string, error) {
	pkg := "wireguard"
	if pm := DetectPackageManager(); pm == PMYum || pm == PMBrew {
		pkg = "wireguard-tools"
	}
	return InstallPackage(pkg)
}
