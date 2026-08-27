package server

import "testing"

func TestIPAllowedEmptyListAllowsEveryone(t *testing.T) {
	if !ipAllowed("203.0.113.5", "") {
		t.Fatal("an empty allow-list must allow everyone (the off/default state)")
	}
}

func TestIPAllowedLoopbackAlwaysPasses(t *testing.T) {
	// Even against a list that would otherwise exclude it — this is the
	// one hard safety rail: shell access to the box itself must never
	// be lockable-out via a settings-page mistake.
	if !ipAllowed("127.0.0.1", "203.0.113.0/24") {
		t.Fatal("loopback must always be allowed regardless of the configured list")
	}
	if !ipAllowed("::1", "203.0.113.0/24") {
		t.Fatal("IPv6 loopback must always be allowed regardless of the configured list")
	}
}

func TestIPAllowedMatchesCIDR(t *testing.T) {
	if !ipAllowed("203.0.113.42", "203.0.113.0/24") {
		t.Fatal("expected an IP inside the configured CIDR to be allowed")
	}
	if ipAllowed("198.51.100.1", "203.0.113.0/24") {
		t.Fatal("expected an IP outside every configured CIDR to be denied")
	}
}

func TestIPAllowedBareIPTreatedAsSingleHost(t *testing.T) {
	if !ipAllowed("203.0.113.5", "203.0.113.5") {
		t.Fatal("a bare IP entry should allow exactly that address")
	}
	if ipAllowed("203.0.113.6", "203.0.113.5") {
		t.Fatal("a bare IP entry must not allow a different address")
	}
}

func TestIPAllowedMultipleEntries(t *testing.T) {
	list := "203.0.113.5, 198.51.100.0/24"
	if !ipAllowed("203.0.113.5", list) {
		t.Fatal("expected the first entry to match")
	}
	if !ipAllowed("198.51.100.9", list) {
		t.Fatal("expected the second (CIDR) entry to match")
	}
	if ipAllowed("192.0.2.1", list) {
		t.Fatal("expected an IP matching neither entry to be denied")
	}
}

func TestIPAllowedGarbageEntryIsSkippedNotFatal(t *testing.T) {
	// A malformed saved entry must not make the whole list fail open —
	// other valid entries still apply, and it's just this one won't
	// ever match anything.
	if !ipAllowed("203.0.113.5", "not-an-ip, 203.0.113.5") {
		t.Fatal("expected a valid entry to still match despite a garbage sibling entry")
	}
	if ipAllowed("198.51.100.1", "not-an-ip") {
		t.Fatal("a list of only garbage must not accidentally allow everyone")
	}
}

func TestNormalizeIPEntry(t *testing.T) {
	cases := map[string]string{
		"203.0.113.5":    "203.0.113.5/32",
		"203.0.113.0/24": "203.0.113.0/24",
		"::1":            "::1/128",
		"2001:db8::/32":  "2001:db8::/32",
	}
	for in, want := range cases {
		if got := normalizeIPEntry(in); got != want {
			t.Errorf("normalizeIPEntry(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSplitAllowedIPs(t *testing.T) {
	got := splitAllowedIPs(" 203.0.113.5 , , 198.51.100.0/24 ,")
	want := []string{"203.0.113.5", "198.51.100.0/24"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}
