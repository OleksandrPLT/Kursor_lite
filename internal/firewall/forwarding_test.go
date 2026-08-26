package firewall

import (
	"strings"
	"testing"
)

func TestValidInternalIP(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"10.0.0.5", true},
		{"192.168.1.1", true},
		{"::1", true},
		{"not-an-ip", false},
		{"", false},
		{"10.0.0.5; rm -rf /", false},
	}
	for _, c := range cases {
		if got := ValidInternalIP(c.ip); got != c.want {
			t.Errorf("ValidInternalIP(%q) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestRenderAndParseUFWNatBlockRoundTrip(t *testing.T) {
	forwards := []Forward{
		{ExternalPort: 8080, ExternalProto: "tcp", InternalIP: "10.0.0.5", InternalPort: 80},
		{ExternalPort: 51820, ExternalProto: "udp", InternalIP: "10.0.0.6", InternalPort: 51820},
	}
	block := renderUFWNatBlock(forwards)
	if !strings.Contains(block, "*nat") || !strings.Contains(block, "COMMIT") {
		t.Fatalf("rendered block missing table markers:\n%s", block)
	}

	parsed := parseUFWNatBlock(block)
	if len(parsed) != len(forwards) {
		t.Fatalf("expected to parse both forwards back, got %d: %+v", len(parsed), parsed)
	}
	for i, want := range forwards {
		if parsed[i] != want {
			t.Errorf("forward %d round-tripped as %+v, want %+v", i, parsed[i], want)
		}
	}
}

func TestRenderUFWNatBlockEmptyWhenNoForwards(t *testing.T) {
	if got := renderUFWNatBlock(nil); got != "" {
		t.Errorf("expected empty block for no forwards, got %q", got)
	}
}

func TestSpliceBlockReplacesOnlyMarkedRegion(t *testing.T) {
	begin, end := "# BEGIN", "# END"
	existing := "before\n# BEGIN\nold content\n# END\nafter\n"
	updated := spliceBlock(existing, begin, end, "# BEGIN\nnew content\n# END\n")
	if !strings.Contains(updated, "before") || !strings.Contains(updated, "after") {
		t.Errorf("splice lost content outside the marked block:\n%s", updated)
	}
	if strings.Contains(updated, "old content") {
		t.Errorf("splice left old block content behind:\n%s", updated)
	}
	if !strings.Contains(updated, "new content") {
		t.Errorf("splice didn't insert new block content:\n%s", updated)
	}
}

func TestSpliceBlockAppendsWhenNoExistingBlock(t *testing.T) {
	existing := "some file content\n"
	updated := spliceBlock(existing, "# BEGIN", "# END", "# BEGIN\nnew\n# END\n")
	if !strings.Contains(updated, "some file content") || !strings.Contains(updated, "new") {
		t.Errorf("expected both old content and new block, got:\n%s", updated)
	}
}

func TestSpliceBlockRemovesWhenNewBlockEmpty(t *testing.T) {
	existing := "before\n# BEGIN\nold\n# END\nafter\n"
	updated := spliceBlock(existing, "# BEGIN", "# END", "")
	if strings.Contains(updated, "# BEGIN") || strings.Contains(updated, "old") {
		t.Errorf("expected the marked block fully removed, got:\n%s", updated)
	}
}
