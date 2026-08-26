package dns

import (
	"strings"
	"testing"
)

func TestValidateAcceptsGoodRecords(t *testing.T) {
	cases := []Record{
		{Name: "www.example.com", Type: "A", Value: "10.0.0.1"},
		{Name: "www.example.com", Type: "AAAA", Value: "2001:db8::1"},
		{Name: "shop.example.com", Type: "CNAME", Value: "example.com"},
		{Name: "example.com", Type: "MX", Value: "mail.example.com", Priority: 10},
		{Name: "example.com", Type: "TXT", Value: "v=spf1 -all"},
	}
	for _, r := range cases {
		if err := Validate(r); err != nil {
			t.Errorf("Validate(%+v) = %v, want nil", r, err)
		}
	}
}

func TestValidateRejectsBadRecords(t *testing.T) {
	cases := []Record{
		{Name: "not a domain", Type: "A", Value: "10.0.0.1"},
		{Name: "www.example.com", Type: "A", Value: "not-an-ip"},
		{Name: "www.example.com", Type: "A", Value: "2001:db8::1"}, // IPv6 in an A record
		{Name: "www.example.com", Type: "AAAA", Value: "10.0.0.1"}, // IPv4 in an AAAA record
		{Name: "www.example.com", Type: "CNAME", Value: "not valid"},
		{Name: "www.example.com", Type: "TXT", Value: "injected\ntxt-record=evil,x"}, // newline injection
		{Name: "www.example.com", Type: "TXT", Value: "a,b"},                         // comma breaks dnsmasq's field syntax
		{Name: "www.example.com", Type: "TXT", Value: ""},
		{Name: "www.example.com", Type: "BOGUS", Value: "x"},
	}
	for _, r := range cases {
		if err := Validate(r); err == nil {
			t.Errorf("Validate(%+v) = nil, want an error", r)
		}
	}
}

func TestRenderConfigProducesOneLinePerRecord(t *testing.T) {
	records := []Record{
		{Name: "www.example.com", Type: "A", Value: "10.0.0.1"},
		{Name: "example.com", Type: "MX", Value: "mail.example.com", Priority: 10},
	}
	out := RenderConfig(records)
	if !strings.Contains(out, "address=/www.example.com/10.0.0.1") {
		t.Errorf("missing A record line:\n%s", out)
	}
	if !strings.Contains(out, "mx-host=example.com,mail.example.com,10") {
		t.Errorf("missing MX record line:\n%s", out)
	}
}

func TestValidNameRejectsInjectionAttempts(t *testing.T) {
	for _, bad := range []string{"a/b", "a,b", "a\nb", "", "-leading-hyphen.com"} {
		if ValidName(bad) {
			t.Errorf("ValidName(%q) = true, want false", bad)
		}
	}
}
