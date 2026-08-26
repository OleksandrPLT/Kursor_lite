package mail

import (
	"strings"
	"testing"
)

func TestValidAddress(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"user@example.com", true},
		{"first.last+tag@example.com", true},
		{"user", false},
		{"@example.com", false},
		{"user@", false},
		{"user@not a domain", false},
		{"../../etc/passwd@example.com", false},
		{"user@example.com/../../etc", false},
		{"", false},
	}
	for _, c := range cases {
		if got := ValidAddress(c.addr); got != c.want {
			t.Errorf("ValidAddress(%q) = %v, want %v", c.addr, got, c.want)
		}
	}
}

func TestRenderVMailboxOneLinePerMailbox(t *testing.T) {
	mailboxes := []Mailbox{
		{Address: "taras@example.com", PasswordHash: "{SHA512-CRYPT}x"},
		{Address: "olena@example.org", PasswordHash: "{SHA512-CRYPT}y"},
	}
	out := renderVMailbox(mailboxes)
	if !strings.Contains(out, "taras@example.com\texample.com/taras/") {
		t.Errorf("missing taras mailbox line:\n%s", out)
	}
	if !strings.Contains(out, "olena@example.org\texample.org/olena/") {
		t.Errorf("missing olena mailbox line:\n%s", out)
	}
}

func TestRenderDovecotUsersEmbedsHashVerbatim(t *testing.T) {
	mailboxes := []Mailbox{{Address: "taras@example.com", PasswordHash: "{SHA512-CRYPT}$6$abc"}}
	out := renderDovecotUsers(mailboxes)
	if out != "taras@example.com:{SHA512-CRYPT}$6$abc\n" {
		t.Errorf("unexpected dovecot-users line: %q", out)
	}
}

func TestValidDomain(t *testing.T) {
	for _, good := range []string{"example.com", "mail.example.co.uk"} {
		if !ValidDomain(good) {
			t.Errorf("ValidDomain(%q) = false, want true", good)
		}
	}
	for _, bad := range []string{"not a domain", "-leading.com", "a/b.com", ""} {
		if ValidDomain(bad) {
			t.Errorf("ValidDomain(%q) = true, want false", bad)
		}
	}
}
