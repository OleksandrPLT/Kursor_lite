package powerdns

import (
	"strings"
	"testing"
)

func TestCanonicalAddsTrailingDot(t *testing.T) {
	cases := map[string]string{
		"example.com":     "example.com.",
		"example.com.":    "example.com.",
		"ns1.example.com": "ns1.example.com.",
	}
	for in, want := range cases {
		if got := canonical(in); got != want {
			t.Errorf("canonical(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidDomain(t *testing.T) {
	for _, good := range []string{"example.com", "sub.example.co.uk"} {
		if !ValidDomain(good) {
			t.Errorf("ValidDomain(%q) = false, want true", good)
		}
	}
	for _, bad := range []string{"not a domain", "-bad.com", "a/b.com", ""} {
		if ValidDomain(bad) {
			t.Errorf("ValidDomain(%q) = true, want false", bad)
		}
	}
}

func TestRenderConfDropInEmbedsKeyAndPaths(t *testing.T) {
	out := renderConfDropIn("test-key-123")
	for _, want := range []string{"launch=gsqlite3", sqlitePath, "api-key=test-key-123", "webserver-port=" + webserverPort, "127.0.0.1"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered conf missing %q:\n%s", want, out)
		}
	}
}
