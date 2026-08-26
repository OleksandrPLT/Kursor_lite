package firewall

import "testing"

func TestValidPort(t *testing.T) {
	cases := []struct {
		port int
		want bool
	}{
		{0, false}, {-1, false}, {1, true}, {8888, true}, {65535, true}, {65536, false}, {100000, false},
	}
	for _, c := range cases {
		if got := ValidPort(c.port); got != c.want {
			t.Errorf("ValidPort(%d) = %v, want %v", c.port, got, c.want)
		}
	}
}

func TestValidProto(t *testing.T) {
	cases := []struct {
		proto string
		want  bool
	}{
		{"tcp", true}, {"udp", true}, {"TCP", false}, {"icmp", false}, {"", false}, {"tcp;rm -rf /", false},
	}
	for _, c := range cases {
		if got := ValidProto(c.proto); got != c.want {
			t.Errorf("ValidProto(%q) = %v, want %v", c.proto, got, c.want)
		}
	}
}

func TestUFWRuleRegexParsesAllowLines(t *testing.T) {
	lines := []string{
		"8888/tcp                   ALLOW       Anywhere",
		"51820/udp                  ALLOW       Anywhere",
		"8888/tcp (v6)              ALLOW       Anywhere (v6)",
		"Status: active",
		"",
	}
	var matched int
	for _, l := range lines {
		if ufwRuleRe.MatchString(l) {
			matched++
		}
	}
	if matched != 3 {
		t.Errorf("expected 3 matching ALLOW lines, got %d", matched)
	}
}
