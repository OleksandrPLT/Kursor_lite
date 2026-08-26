// Package sysusers manages real Linux system accounts (/etc/passwd,
// /etc/shadow) — a different layer entirely from Kursor's own
// panel accounts (internal/store.User): these are the accounts that
// can actually log into the box (SSH, local console, cron, services),
// managed with the standard useradd/usermod/chpasswd tools rather than
// hand-edited files, the same "shell out to the real tool" discipline
// as every other host-management package in this codebase.
package sysusers

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// usernameRe mirrors useradd's own default constraint (see
// `useradd(8)`'s NAME_REGEX) — the injection boundary here, since this
// value reaches useradd/usermod/chpasswd command lines directly.
var usernameRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

func ValidUsername(u string) bool { return usernameRe.MatchString(u) }

// SystemUser is one row from /etc/passwd, cross-referenced against
// /etc/shadow for lock status.
type SystemUser struct {
	Username string
	UID      int
	GID      int
	HomeDir  string
	Shell    string
	Locked   bool
}

// minHumanUID filters out system/service accounts (daemon, www-data,
// nobody, ...) from the list — this page is for real human logins, not
// every account the OS ships with. 1000 is the standard Debian/Ubuntu/
// RHEL threshold for "a real user account."
const minHumanUID = 1000

// ListSystemUsers parses /etc/passwd (real accounts only, UID >=
// minHumanUID, root always included since it's the one every one of
// these boxes actually logs in as) and /etc/shadow for lock status.
func ListSystemUsers() ([]SystemUser, error) {
	passwd, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, err
	}
	defer passwd.Close()

	locked := map[string]bool{}
	if shadow, err := os.Open("/etc/shadow"); err == nil {
		defer shadow.Close()
		scanner := bufio.NewScanner(shadow)
		for scanner.Scan() {
			fields := strings.Split(scanner.Text(), ":")
			if len(fields) < 2 {
				continue
			}
			// A locked account's hash is prefixed with "!" (usermod -L)
			// or is exactly "*"/"!!" (no password set / never had one).
			locked[fields[0]] = strings.HasPrefix(fields[1], "!") || fields[1] == "*"
		}
	}
	// A missing/unreadable /etc/shadow (e.g. not running as root) just
	// means every user shows as unlocked — a reasonable degrade, not
	// worth failing the whole list over.

	var out []SystemUser
	scanner := bufio.NewScanner(passwd)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) < 7 {
			continue
		}
		uid, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}
		// uid 65534 is the conventional "nobody" sentinel (nfs-nobody,
		// unmapped-uid fallback, ...) — technically >= minHumanUID but
		// never a real login, so it'd otherwise slip through the filter
		// above that's specifically trying to exclude exactly this kind
		// of account.
		if (uid != 0 && uid < minHumanUID) || uid == 65534 {
			continue
		}
		gid, _ := strconv.Atoi(fields[3])
		out = append(out, SystemUser{
			Username: fields[0],
			UID:      uid,
			GID:      gid,
			HomeDir:  fields[5],
			Shell:    fields[6],
			Locked:   locked[fields[0]],
		})
	}
	return out, scanner.Err()
}

// CreateSystemUser adds a real login-capable account (own home
// directory, bash shell) and sets its initial password via chpasswd —
// the same non-interactive path ResetPassword uses, since `passwd`
// itself expects a real TTY for its prompts.
func CreateSystemUser(username, password string) error {
	if !ValidUsername(username) {
		return errors.New("invalid username")
	}
	if out, err := exec.Command("useradd", "-m", "-s", "/bin/bash", username).CombinedOutput(); err != nil {
		return fmt.Errorf("useradd: %s", out)
	}
	return ResetPassword(username, password)
}

// ResetPassword sets username's password non-interactively.
func ResetPassword(username, password string) error {
	if !ValidUsername(username) {
		return errors.New("invalid username")
	}
	cmd := exec.Command("chpasswd")
	cmd.Stdin = strings.NewReader(username + ":" + password + "\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("chpasswd: %s", out)
	}
	return nil
}

// guardRoot is Lock's one safety rail: this whole codebase runs as
// root and every install script assumes root SSH access works, so
// locking it out here has no "are you sure" step to save the operator
// the way, say, canDeactivate protects the last Kursor admin.
func guardRoot(username string) error {
	if username == "root" {
		return errors.New("refusing to lock the root account — this would be an unrecoverable lockout for a box managed this way")
	}
	return nil
}

// Lock disables password login for username (usermod -L) — SSH key
// login, if any key is already authorized for that user, still works;
// this only removes the password-based path in, same distinction
// internal/sshadmin.SetPasswordAuth draws at the sshd level.
func Lock(username string) error {
	if err := guardRoot(username); err != nil {
		return err
	}
	if !ValidUsername(username) {
		return errors.New("invalid username")
	}
	if out, err := exec.Command("usermod", "-L", username).CombinedOutput(); err != nil {
		return fmt.Errorf("usermod -L: %s", out)
	}
	return nil
}

func Unlock(username string) error {
	if !ValidUsername(username) {
		return errors.New("invalid username")
	}
	if out, err := exec.Command("usermod", "-U", username).CombinedOutput(); err != nil {
		return fmt.Errorf("usermod -U: %s", out)
	}
	return nil
}
