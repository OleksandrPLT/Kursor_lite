// Package mail manages a real virtual-mailbox mail server: Postfix as
// the MTA (accepts/delivers mail for managed domains) and Dovecot as
// the IMAP/auth side, wired together the standard way — a shared
// crypt-hashed password file — without touching either daemon's own
// core config. Dovecot in particular only ever gets an *additive*
// drop-in under conf.d/ (same reasoning as Nginx's sites-enabled or
// dnsmasq's conf.d: never rewrite a third-party service's main config,
// only add a Kursor-owned file it already knows to include), so an
// existing Dovecot setup (if any) is never at risk of being clobbered.
package mail

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/client"
)

const (
	vmailboxPath      = "/etc/postfix/vmailbox"
	dovecotUsersPath  = "/etc/dovecot/kursor-users"
	dovecotMasterPath = "/etc/dovecot/kursor-master-users"
	dovecotConfPath   = "/etc/dovecot/conf.d/90-kursor-auth.conf"
	mailboxBase       = "/var/mail/vhosts"
	vmailUser         = "vmail"
	vmailUID          = "5000"
	vmailGID          = "5000"
	// vmailGroupName is deliberately NOT "vmail" — some distros' own
	// mail-related packages already claim a system group literally
	// named "vmail" for their own purposes, with whatever GID happened
	// to be free at package-install time (confirmed live: GID 988 on a
	// real box). Dovecot's userdb config below hardcodes the bare
	// number vmailGID, not a name, so what matters is that SOME group
	// has that exact GID — colliding on the name while needing an exact
	// GID would either fail outright or silently reuse the wrong group.
	vmailGroupName = "kursor-vmail"
	masterUsername    = "kursor-master"
	masterUserSep     = "*"
	imapAddr          = "127.0.0.1:143"
)

// Status reports what this host actually has.
type Status struct {
	PostfixInstalled bool
	DovecotInstalled bool
}

func Detect() Status {
	_, postfixErr := exec.LookPath("postfix")
	_, dovecotErr := exec.LookPath("doveadm")
	return Status{PostfixInstalled: postfixErr == nil, DovecotInstalled: dovecotErr == nil}
}

var (
	domainRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$`)
	// A deliberately conservative local-part charset (no quoted-strings,
	// no raw special characters) — this local-part becomes a literal
	// path segment (mailboxBase/domain/local/) and a literal line in two
	// config files, so keeping it to the boring, common subset is the
	// injection boundary here, the same role ValidDomain plays in
	// internal/sites.
	localPartRe = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9._+-]{0,63})?$`)
)

func ValidDomain(d string) bool { return domainRe.MatchString(d) }

// ValidAddress reports whether addr is a safe, well-formed
// "local@domain" mailbox address.
func ValidAddress(addr string) bool {
	local, domain, ok := strings.Cut(addr, "@")
	if !ok {
		return false
	}
	return localPartRe.MatchString(local) && domainRe.MatchString(domain)
}

// Mailbox is one virtual mailbox. PasswordHash is whatever
// HashPassword returned — a Dovecot-format crypt string already
// carrying its own "{SCHEME}" prefix, stored as-is.
type Mailbox struct {
	Address      string
	PasswordHash string
}

// HashPassword shells out to `doveadm pw`, the same tool a real
// Dovecot admin would use — there's no SHA512-CRYPT in Go's stdlib, and
// hand-rolling crypt(3) would be exactly the kind of homegrown crypto
// this project avoids elsewhere (see bcrypt for the panel's own logins).
func HashPassword(plain string) (string, error) {
	out, err := exec.Command("doveadm", "pw", "-s", "SHA512-CRYPT", "-p", plain).Output()
	if err != nil {
		return "", fmt.Errorf("doveadm pw: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

func addressParts(addr string) (local, domain string) {
	local, domain, _ = strings.Cut(addr, "@")
	return
}

// renderVMailbox is Postfix's address→Maildir map (hash: lookup table,
// built with `postmap` before Postfix will read it).
func renderVMailbox(mailboxes []Mailbox) string {
	var b strings.Builder
	for _, m := range mailboxes {
		local, domain := addressParts(m.Address)
		fmt.Fprintf(&b, "%s\t%s/%s/\n", m.Address, domain, local)
	}
	return b.String()
}

// renderDovecotUsers is the passwd-file passdb Dovecot's drop-in below
// points at.
func renderDovecotUsers(mailboxes []Mailbox) string {
	var b strings.Builder
	for _, m := range mailboxes {
		fmt.Fprintf(&b, "%s:%s\n", m.Address, m.PasswordHash)
	}
	return b.String()
}

// dovecotAuthConf's master passdb is what lets Kursor itself read a
// mailbox's inbox (see FetchInbox/FetchMessageRaw) without ever knowing
// that mailbox's real password: Dovecot's standard "master user"
// mechanism logs in as "<mailbox>*kursor-master" with a *separate*
// service credential Kursor generates for itself (LoadOrGenerateMasterPassword)
// — the same trust tier as the WireGuard server key or OIDC signing
// key, never a real person's secret.
const dovecotAuthConf = `# Managed by Kursor — do not edit by hand (regenerated on every mailbox
# change). Additive only: this is a conf.d drop-in, so it never touches
# whatever passdb/userdb this host's Dovecot already had configured.
auth_master_user_separator = ` + masterUserSep + `
passdb {
  driver = passwd-file
  args = scheme=SHA512-CRYPT username_format=%u ` + dovecotUsersPath + `
}
passdb {
  driver = passwd-file
  master = yes
  pass = yes
  args = username_format=%u ` + dovecotMasterPath + `
}
userdb {
  driver = static
  args = uid=` + vmailUID + ` gid=` + vmailGID + ` home=` + mailboxBase + `/%d/%n
}
`

// ensureVMailUser creates the dedicated, privilege-less system account
// virtual mail delivery runs as, if it doesn't already exist — the
// standard real-world setup (a shared uid/gid across every virtual
// mailbox, since none of them are real Unix accounts).
//
// The group is created explicitly, checked by numeric GID rather than
// name (see vmailGroupName's comment), before the user — useradd's own
// "create a same-named group automatically" default isn't guaranteed
// to land on vmailGID, and the Dovecot userdb config above (userdb {
// args = uid=... gid=vmailGID ... }) hardcodes that numeric GID
// regardless of whatever the OS actually assigned. If vmailUser
// already exists from before this fix, its primary group is
// corrected too — this runs on every ApplyPostfix, so a box that hit
// the bug self-heals the next time any mail setting changes.
func ensureVMailUser() error {
	if !groupIDExists(vmailGID) {
		if out, err := exec.Command("groupadd", "-r", "-g", vmailGID, vmailGroupName).CombinedOutput(); err != nil {
			return fmt.Errorf("groupadd %s: %s", vmailGroupName, out)
		}
	}
	if _, err := user.Lookup(vmailUser); err != nil {
		out, err := exec.Command("useradd", "-r", "-u", vmailUID, "-g", vmailGID, "-d", mailboxBase, "-s", "/usr/sbin/nologin", vmailUser).CombinedOutput()
		if err != nil {
			return fmt.Errorf("useradd %s: %s", vmailUser, out)
		}
		return nil
	}
	_, _ = exec.Command("usermod", "-g", vmailGID, vmailUser).CombinedOutput()
	return nil
}

// groupIDExists checks /etc/group by numeric GID, not name — a group
// literally named "vmail" may already exist under a different GID
// (see vmailGroupName), so a name-based check would wrongly conclude
// there's nothing to do.
func groupIDExists(gid string) bool {
	out, err := exec.Command("getent", "group").Output()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) >= 3 && fields[2] == gid {
			return true
		}
	}
	return false
}

func postfixReload() error {
	if _, err := exec.LookPath("systemctl"); err == nil {
		if out, err := exec.Command("systemctl", "reload", "postfix").CombinedOutput(); err == nil {
			return nil
		} else {
			if out2, err2 := exec.Command("service", "postfix", "reload").CombinedOutput(); err2 == nil {
				return nil
			} else {
				return fmt.Errorf("systemctl reload postfix: %s; service postfix reload: %s", out, out2)
			}
		}
	}
	out, err := exec.Command("postfix", "reload").CombinedOutput()
	if err != nil {
		return fmt.Errorf("postfix reload: %s", out)
	}
	return nil
}

func dovecotRestart() error {
	if _, err := exec.LookPath("systemctl"); err == nil {
		if out, err := exec.Command("systemctl", "restart", "dovecot").CombinedOutput(); err == nil {
			return nil
		} else {
			if out2, err2 := exec.Command("service", "dovecot", "restart").CombinedOutput(); err2 == nil {
				return nil
			} else {
				return fmt.Errorf("systemctl restart dovecot: %s; service dovecot restart: %s", out, out2)
			}
		}
	}
	return errors.New("no systemctl/service found to restart dovecot")
}

// ApplyPostfix regenerates every Postfix-side file from the given
// domains/mailboxes, validates with `postfix check`, and reloads —
// same render→validate→reload discipline as Nginx/WireGuard/dnsmasq.
// Rolls the vmailbox file back to what it was on validation failure.
func ApplyPostfix(domains []string, mailboxes []Mailbox) error {
	if !Detect().PostfixInstalled {
		return errors.New("postfix not detected on this host")
	}
	if err := ensureVMailUser(); err != nil {
		return err
	}
	if err := os.MkdirAll(mailboxBase, 0o750); err != nil {
		return err
	}
	// /var/mail is a standard setgid-"mail" directory on most distros,
	// so anything MkdirAll creates under it inherits group "mail" (GID
	// 8) — not vmail's own group — regardless of the 0750 passed above.
	// Confirmed live: exactly this left vmail (uid/gid 5000) unable to
	// even chdir into its own mailbox tree. Numeric ids here, not the
	// "vmail" name, since this runs right after ensureVMailUser may have
	// just created it and nsswitch caching shouldn't be relied on.
	_, _ = exec.Command("chown", "-R", vmailUID+":"+vmailGID, mailboxBase).CombinedOutput()

	if out, err := exec.Command("postconf", "-e",
		"virtual_mailbox_domains="+strings.Join(domains, ", "),
		"virtual_mailbox_base="+mailboxBase,
		"virtual_mailbox_maps=hash:"+vmailboxPath,
		"virtual_uid_maps=static:"+vmailUID,
		"virtual_gid_maps=static:"+vmailGID,
	).CombinedOutput(); err != nil {
		return fmt.Errorf("postconf -e: %s", out)
	}

	var previous []byte
	hadPrevious := false
	if b, err := os.ReadFile(vmailboxPath); err == nil {
		previous = b
		hadPrevious = true
	}
	if err := os.WriteFile(vmailboxPath, []byte(renderVMailbox(mailboxes)), 0o640); err != nil {
		return err
	}
	if out, err := exec.Command("postmap", vmailboxPath).CombinedOutput(); err != nil {
		if hadPrevious {
			_ = os.WriteFile(vmailboxPath, previous, 0o640)
			_, _ = exec.Command("postmap", vmailboxPath).CombinedOutput()
		}
		return fmt.Errorf("postmap: %s", out)
	}

	if out, err := exec.Command("postfix", "check").CombinedOutput(); err != nil {
		return fmt.Errorf("postfix check failed: %s", out)
	}
	return postfixReload()
}

// ApplyDovecot regenerates the Kursor-owned passwd-file, master-user
// file, and conf.d drop-in from the given mailboxes, validates with
// `doveconf -n`, and restarts Dovecot. masterPasswordHash is
// HashPassword's output for LoadOrGenerateMasterPassword's plaintext —
// see FetchInbox for why Kursor needs its own login into every mailbox.
func ApplyDovecot(mailboxes []Mailbox, masterPasswordHash string) error {
	if !Detect().DovecotInstalled {
		return errors.New("dovecot not detected on this host")
	}
	if err := os.MkdirAll(filepath.Dir(dovecotConfPath), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(dovecotConfPath, []byte(dovecotAuthConf), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(dovecotUsersPath, []byte(renderDovecotUsers(mailboxes)), 0o640); err != nil {
		return err
	}
	if err := os.WriteFile(dovecotMasterPath, []byte(masterUsername+":"+masterPasswordHash+"\n"), 0o640); err != nil {
		return err
	}
	// Dovecot's auth worker runs as its own unprivileged "dovecot" user,
	// not root — os.WriteFile leaves both files owned by root:root, so
	// even at mode 0640 the dovecot group can't actually read them
	// (confirmed live: "auth: Error: passwd-file ... Permission denied
	// ... we're not in group 0(root)"). Same fix internal/powerdns's own
	// conf.d drop-in needed for the identical reason — chown to the
	// service's own group right after writing.
	_, _ = exec.Command("chown", "root:dovecot", dovecotUsersPath).CombinedOutput()
	_, _ = exec.Command("chown", "root:dovecot", dovecotMasterPath).CombinedOutput()

	if out, err := exec.Command("doveconf", "-n").CombinedOutput(); err != nil {
		return fmt.Errorf("doveconf -n failed: %s", out)
	}
	return dovecotRestart()
}

// LoadOrGenerateMasterPassword returns Kursor's own Dovecot master-user
// password, generating and persisting one on first use — same
// lifecycle as internal/vpn.LoadOrGenerateServerKey and internal/oidc's
// signing key: a Kursor-owned service credential, root-only on disk,
// never shown to any user and never mailed anywhere.
func LoadOrGenerateMasterPassword(dataDir string) (string, error) {
	path := filepath.Join(dataDir, "mail_master_password")
	if b, err := os.ReadFile(path); err == nil {
		if pw := strings.TrimSpace(string(b)); pw != "" {
			return pw, nil
		}
	}
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	pw := base64.RawURLEncoding.EncodeToString(buf)
	if err := os.WriteFile(path, []byte(pw+"\n"), 0o600); err != nil {
		return "", err
	}
	return pw, nil
}

// InboxMessage is one envelope-level summary — enough for a message
// list, not the body.
type InboxMessage struct {
	UID     uint32
	Subject string
	From    string
	Date    time.Time
}

// imapLogin dials Dovecot's plain IMAP port and logs in as address via
// Kursor's master-user credential — never the mailbox's own password,
// which Kursor never has. Plain (non-TLS) is deliberate: this traffic
// never leaves the box (127.0.0.1), the same "local socket is the trust
// boundary" posture internal/dbmanager takes connecting to MySQL/
// Postgres over their own unix sockets.
func imapLogin(address, masterPassword string) (*client.Client, error) {
	if !Detect().DovecotInstalled {
		return nil, errors.New("dovecot not detected on this host")
	}
	c, err := client.Dial(imapAddr)
	if err != nil {
		return nil, fmt.Errorf("dial dovecot imap: %w", err)
	}
	if err := c.Login(address+masterUserSep+masterUsername, masterPassword); err != nil {
		_ = c.Logout()
		return nil, fmt.Errorf("imap master login: %w", err)
	}
	return c, nil
}

// FetchInbox returns up to limit of a mailbox's most recent INBOX
// messages, newest first — real IMAP, not a mock, via the master-user
// login above.
func FetchInbox(address, masterPassword string, limit uint32) ([]InboxMessage, error) {
	c, err := imapLogin(address, masterPassword)
	if err != nil {
		return nil, err
	}
	defer c.Logout()

	mbox, err := c.Select("INBOX", true)
	if err != nil {
		return nil, fmt.Errorf("select INBOX: %w", err)
	}
	if mbox.Messages == 0 {
		return nil, nil
	}

	from := uint32(1)
	to := mbox.Messages
	if mbox.Messages > limit {
		from = mbox.Messages - limit + 1
	}
	seqset := new(imap.SeqSet)
	seqset.AddRange(from, to)
	items := []imap.FetchItem{imap.FetchEnvelope, imap.FetchUid}

	messages := make(chan *imap.Message, limit)
	done := make(chan error, 1)
	go func() { done <- c.Fetch(seqset, items, messages) }()

	var out []InboxMessage
	for msg := range messages {
		var fromAddr string
		if msg.Envelope != nil && len(msg.Envelope.From) > 0 {
			fromAddr = msg.Envelope.From[0].Address()
		}
		subject := ""
		var date time.Time
		if msg.Envelope != nil {
			subject = msg.Envelope.Subject
			date = msg.Envelope.Date
		}
		out = append(out, InboxMessage{UID: msg.Uid, Subject: subject, From: fromAddr, Date: date})
	}
	if err := <-done; err != nil {
		return nil, fmt.Errorf("fetch: %w", err)
	}

	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

// FetchMessageRaw returns one message's full raw source (headers +
// body, MIME and all) by UID — a deliberately minimal "view", not a
// full MIME-rendering webmail: real content, shown as-is rather than
// guessed-at HTML rendering of a multipart message this package doesn't
// parse.
func FetchMessageRaw(address, masterPassword string, uid uint32) (string, error) {
	c, err := imapLogin(address, masterPassword)
	if err != nil {
		return "", err
	}
	defer c.Logout()

	if _, err := c.Select("INBOX", true); err != nil {
		return "", fmt.Errorf("select INBOX: %w", err)
	}

	seqset := new(imap.SeqSet)
	seqset.AddNum(uid)
	section := &imap.BodySectionName{}
	items := []imap.FetchItem{section.FetchItem()}

	messages := make(chan *imap.Message, 1)
	done := make(chan error, 1)
	go func() { done <- c.UidFetch(seqset, items, messages) }()

	var raw string
	for msg := range messages {
		if body := msg.GetBody(section); body != nil {
			b, err := io.ReadAll(body)
			if err != nil {
				return "", err
			}
			raw = string(b)
		}
	}
	if err := <-done; err != nil {
		return "", fmt.Errorf("uid fetch: %w", err)
	}
	if raw == "" {
		return "", errors.New("message not found")
	}
	return raw, nil
}
