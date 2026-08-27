package paneladmin

import (
	"strings"
	"testing"
)

func TestParsePortFromAddrLine(t *testing.T) {
	cases := []struct {
		line    string
		want    int
		wantErr bool
	}{
		{"Environment=KURSOR_ADDR=:8888", 8888, false},
		{"Environment=KURSOR_ADDR=0.0.0.0:9000", 9000, false},
		{"Environment=KURSOR_ADDR=127.0.0.1:80", 80, false},
		{"Environment=KURSOR_ADDR=", 0, true},
		{"Environment=KURSOR_ADDR=:notanumber", 0, true},
	}
	for _, c := range cases {
		got, err := parsePortFromAddrLine(c.line)
		if c.wantErr {
			if err == nil {
				t.Errorf("parsePortFromAddrLine(%q): expected an error, got port %d", c.line, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parsePortFromAddrLine(%q): unexpected error: %v", c.line, err)
			continue
		}
		if got != c.want {
			t.Errorf("parsePortFromAddrLine(%q) = %d, want %d", c.line, got, c.want)
		}
	}
}

func TestAddrLineRegexReplace(t *testing.T) {
	content := "[Service]\nExecStart=/opt/kursor/bin/kursord\nEnvironment=KURSOR_ADDR=:8888\nEnvironment=KURSOR_DATA_DIR=/var/lib/kursor\n"
	updated := addrLineRe.ReplaceAllString(content, "Environment=KURSOR_ADDR=:9999")
	if want := "Environment=KURSOR_ADDR=:9999"; !strings.Contains(updated, want) {
		t.Fatalf("expected updated content to contain %q, got:\n%s", want, updated)
	}
	if strings.Contains(updated, "KURSOR_ADDR=:8888") {
		t.Fatal("old port line should have been fully replaced, not left alongside the new one")
	}
	// Every other line must survive untouched.
	for _, want := range []string{"ExecStart=/opt/kursor/bin/kursord", "KURSOR_DATA_DIR=/var/lib/kursor"} {
		if !strings.Contains(updated, want) {
			t.Errorf("expected unrelated line %q to survive the replace, got:\n%s", want, updated)
		}
	}
}
