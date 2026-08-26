package sshadmin

import (
	"strings"
	"testing"
)

func TestValidPublicKey(t *testing.T) {
	cases := []struct {
		key  string
		want bool
	}{
		{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKey user@host", true},
		{"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB", true},
		{"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY=", true},
		{"not a key", false},
		{"", false},
		{"ssh-ed25519", false},
		{"rm -rf / ssh-rsa AAAA", false},
	}
	for _, c := range cases {
		if got := ValidPublicKey(c.key); got != c.want {
			t.Errorf("ValidPublicKey(%q) = %v, want %v", c.key, got, c.want)
		}
	}
}

func TestReplaceOrAppendReplacesExistingDirective(t *testing.T) {
	content := "SomeOption yes\nPort 22\nAnotherOption no\n"
	updated := replaceOrAppend(content, "Port", portRe, "Port 2222")
	if strings.Contains(updated, "Port 22\n") {
		t.Errorf("old Port directive should be gone:\n%s", updated)
	}
	if !strings.Contains(updated, "Port 2222") {
		t.Errorf("new Port directive missing:\n%s", updated)
	}
	if !strings.Contains(updated, "SomeOption yes") || !strings.Contains(updated, "AnotherOption no") {
		t.Errorf("unrelated directives should survive untouched:\n%s", updated)
	}
}

func TestReplaceOrAppendAppends(t *testing.T) {
	content := "SomeOption yes\n"
	updated := replaceOrAppend(content, "Port", portRe, "Port 2222")
	if !strings.Contains(updated, "SomeOption yes") || !strings.Contains(updated, "Port 2222") {
		t.Errorf("expected both old content and appended directive:\n%s", updated)
	}
}

func TestReplaceOrAppendHandlesCommentedDirective(t *testing.T) {
	content := "#Port 22\nOtherOption x\n"
	updated := replaceOrAppend(content, "Port", portRe, "Port 2222")
	if !strings.Contains(updated, "Port 2222") {
		t.Errorf("expected the commented-out directive to be replaced:\n%s", updated)
	}
	if strings.Contains(updated, "#Port 22") {
		t.Errorf("commented directive should have been replaced, not left behind:\n%s", updated)
	}
}
