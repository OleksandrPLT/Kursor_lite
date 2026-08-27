package netcheck

import "testing"

// TestResolveALiveInternet is a real DNS lookup against a domain that's
// extremely unlikely to ever stop existing/resolving — this package's
// whole job is talking to real DNS/HTTP, so unlike the rest of this
// codebase's pure-logic unit tests, this one is a light integration
// check. Skips itself (rather than failing the suite) if this
// environment has no working DNS/outbound network at all, since a
// sandboxed CI runner might not.
func TestResolveALiveInternet(t *testing.T) {
	ips, err := ResolveA("dns.google")
	if err != nil {
		t.Skipf("no usable DNS in this environment: %v", err)
	}
	if len(ips) == 0 {
		t.Skip("dns.google resolved to nothing — unusual, skipping rather than failing on a network fluke")
	}
	found := false
	for _, ip := range ips {
		if ip == "8.8.8.8" || ip == "8.8.4.4" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected dns.google to resolve to one of Google's public DNS IPs, got %v", ips)
	}
}

func TestResolveANonexistentDomain(t *testing.T) {
	ips, err := ResolveA("this-domain-should-never-exist-kursor-test.invalid")
	if err != nil {
		t.Skipf("no usable DNS in this environment: %v", err)
	}
	if len(ips) != 0 {
		t.Errorf("expected no addresses for a nonexistent domain, got %v", ips)
	}
}
