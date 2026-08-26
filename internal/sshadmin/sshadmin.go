// Package sshadmin manages this host's own SSH daemon: authorized_keys
// for key-based login, and the two sshd_config settings an operator
// most often needs to touch (port, password authentication). Unlike
// cron/vpn/dns, sshd_config is never regenerated from scratch — a
// single directive is found-and-replaced (or appended if missing),
// leaving everything else in the file exactly as it was, the same
// "never touch what you don't own" discipline internal/mail applies to
// Dovecot's config.
//
// This is also the single most dangerous module in the codebase to get
// wrong: a bad change here can lock the operator out of the box
// entirely, with no other way in. Every mutating function here is
// deliberately conservative — see the guards on SetPasswordAuth and
// SetPort.
package sshadmin

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const sshdConfigPath = "/etc/ssh/sshd_config"

// authorizedKeysPath returns ~<username>/.ssh/authorized_keys,
// resolving the home directory the same way sshd itself would (via the
// real system user database, not a guessed /home/<user> path — root's
// home is /root, not /home/root).
func authorizedKeysPath(username string) (string, error) {
	u, err := user.Lookup(username)
	if err != nil {
		return "", fmt.Errorf("no such system user %q: %w", username, err)
	}
	return filepath.Join(u.HomeDir, ".ssh", "authorized_keys"), nil
}

// pubKeyRe accepts the standard OpenSSH public key line formats —
// deliberately whitelist-based (the same role ValidDomain/ValidPort
// play elsewhere): this string is about to be appended verbatim into a
// file sshd parses, so anything not matching this shape is rejected
// outright rather than sanitized.
var pubKeyRe = regexp.MustCompile(`^(ssh-rsa|ssh-ed25519|ssh-dss|ecdsa-sha2-nistp(256|384|521)) [A-Za-z0-9+/]+=*( .*)?$`)

func ValidPublicKey(key string) bool {
	return pubKeyRe.MatchString(strings.TrimSpace(key))
}

// ListAuthorizedKeys returns every key currently in the file, in order
// — comment lines are skipped, but their raw form is kept as the
// "Comment" field only when it's the trailing comment ON a key line
// (OpenSSH's own convention: "<type> <base64> <comment>").
type AuthorizedKey struct {
	Type    string
	Comment string
	Raw     string // the full original line — what gets matched for removal
}

func ListAuthorizedKeys(username string) ([]AuthorizedKey, error) {
	path, err := authorizedKeysPath(username)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var out []AuthorizedKey
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		comment := ""
		if len(fields) >= 3 {
			comment = strings.Join(fields[2:], " ")
		}
		out = append(out, AuthorizedKey{Type: fields[0], Comment: comment, Raw: line})
	}
	return out, scanner.Err()
}

// AddAuthorizedKey appends a new key (skipping if it's already present
// verbatim) — creates ~/.ssh with the permissions sshd insists on
// (0700 dir, 0600 file; sshd silently ignores keys in a
// group/world-writable .ssh or authorized_keys, which is the most
// common reason a "successfully added" key mysteriously doesn't work).
func AddAuthorizedKey(username, key string) error {
	key = strings.TrimSpace(key)
	if !ValidPublicKey(key) {
		return errors.New("doesn't look like a valid SSH public key (expected \"ssh-ed25519 AAAA... comment\" or similar)")
	}
	u, err := user.Lookup(username)
	if err != nil {
		return fmt.Errorf("no such system user %q: %w", username, err)
	}
	path, err := authorizedKeysPath(username)
	if err != nil {
		return err
	}

	existing, _ := ListAuthorizedKeys(username)
	for _, k := range existing {
		if k.Raw == key {
			return errors.New("this key is already present")
		}
	}

	sshDir := filepath.Dir(path)
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteString(key + "\n"); err != nil {
		return err
	}

	uid, gid := 0, 0
	fmt.Sscanf(u.Uid, "%d", &uid)
	fmt.Sscanf(u.Gid, "%d", &gid)
	_ = os.Chown(sshDir, uid, gid)
	_ = os.Chown(path, uid, gid)
	return nil
}

// RemoveAuthorizedKey deletes every line matching raw exactly —
// rewrites the whole file (there's no partial-file API for this), same
// "regenerate from the in-memory list" shape as everywhere else, just
// with the list first read back from disk since this file's truth
// lives outside Kursor's own database.
func RemoveAuthorizedKey(username, raw string) error {
	path, err := authorizedKeysPath(username)
	if err != nil {
		return err
	}
	existing, err := ListAuthorizedKeys(username)
	if err != nil {
		return err
	}
	var kept []string
	for _, k := range existing {
		if k.Raw != raw {
			kept = append(kept, k.Raw)
		}
	}
	content := strings.Join(kept, "\n")
	if content != "" {
		content += "\n"
	}
	return os.WriteFile(path, []byte(content), 0o600)
}

// --- sshd_config: port + password auth, found-and-replaced in place ---

var (
	portRe     = regexp.MustCompile(`(?m)^\s*#?\s*Port\s+\d+\s*$`)
	passwordRe = regexp.MustCompile(`(?m)^\s*#?\s*PasswordAuthentication\s+(yes|no)\s*$`)
)

// Config is sshd's current effective settings, as best-parsed from
// sshd_config (an operator relying on an included conf.d file with its
// own override would see the top-level file's value here, not sshd's
// truly effective one — a limitation worth stating plainly rather than
// pretending this always matches `sshd -T`).
type Config struct {
	Port           int
	PasswordAuthOn bool
}

func GetConfig() (Config, error) {
	content, err := os.ReadFile(sshdConfigPath)
	if err != nil {
		return Config{}, err
	}
	cfg := Config{Port: 22, PasswordAuthOn: true} // OpenSSH's own defaults when unset
	if m := portRe.FindString(string(content)); m != "" && !strings.Contains(strings.TrimSpace(m), "#") {
		fields := strings.Fields(m)
		if len(fields) == 2 {
			if p, err := strconv.Atoi(fields[1]); err == nil {
				cfg.Port = p
			}
		}
	}
	if m := passwordRe.FindString(string(content)); m != "" && !strings.Contains(strings.TrimSpace(m), "#") {
		cfg.PasswordAuthOn = strings.HasSuffix(strings.TrimSpace(m), "yes")
	}
	return cfg, nil
}

func replaceOrAppend(content, directive string, re *regexp.Regexp, newLine string) string {
	if re.MatchString(content) {
		return re.ReplaceAllString(content, newLine)
	}
	return strings.TrimRight(content, "\n") + "\n" + newLine + "\n"
}

func testAndReload(newContent string) error {
	previous, err := os.ReadFile(sshdConfigPath)
	if err != nil {
		return err
	}
	if err := os.WriteFile(sshdConfigPath, []byte(newContent), 0o644); err != nil {
		return err
	}
	if out, err := exec.Command("sshd", "-t").CombinedOutput(); err != nil {
		_ = os.WriteFile(sshdConfigPath, previous, 0o644)
		return fmt.Errorf("sshd -t rejected the change, rolled back: %s", out)
	}
	return reload()
}

func reload() error {
	if out, err := exec.Command("systemctl", "reload", "sshd").CombinedOutput(); err == nil {
		return nil
	} else if out2, err2 := exec.Command("systemctl", "reload", "ssh").CombinedOutput(); err2 == nil {
		return nil
	} else {
		return fmt.Errorf("systemctl reload sshd: %s; systemctl reload ssh: %s", out, out2)
	}
}

// SetPort validates the config with `sshd -t` before ever reloading —
// but a config that merely *parses* can still lock someone out if the
// new port isn't reachable through the firewall, which this function
// has no way to know about; the caller (server/sshadmin.go) is
// responsible for opening the new port first.
func SetPort(port int) error {
	if port < 1 || port > 65535 {
		return errors.New("invalid port")
	}
	content, err := os.ReadFile(sshdConfigPath)
	if err != nil {
		return err
	}
	updated := replaceOrAppend(string(content), "Port", portRe, fmt.Sprintf("Port %d", port))
	return testAndReload(updated)
}

// SetPasswordAuth refuses to turn password auth off unless the target
// user already has at least one authorized key — the one guard that
// actually matters here, since turning this off with no key configured
// is an unrecoverable lockout with no console/rescue path assumed.
func SetPasswordAuth(enabled bool, guardUsername string) error {
	if !enabled {
		keys, err := ListAuthorizedKeys(guardUsername)
		if err != nil {
			return fmt.Errorf("couldn't verify %s has an SSH key configured first: %w", guardUsername, err)
		}
		if len(keys) == 0 {
			return fmt.Errorf("refusing to disable password login: %s has no authorized SSH key yet — add one first", guardUsername)
		}
	}
	content, err := os.ReadFile(sshdConfigPath)
	if err != nil {
		return err
	}
	value := "no"
	if enabled {
		value = "yes"
	}
	updated := replaceOrAppend(string(content), "PasswordAuthentication", passwordRe, "PasswordAuthentication "+value)
	return testAndReload(updated)
}
