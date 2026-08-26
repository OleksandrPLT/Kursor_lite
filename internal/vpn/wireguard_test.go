package vpn

import (
	"strings"
	"testing"
)

func exampleServer() ServerConfig {
	return ServerConfig{PrivateKey: "SERVERPRIVKEY", Address: "10.8.0.1/24", ListenPort: 51820}
}

func TestRenderConfigIncludesServerInterface(t *testing.T) {
	out := RenderConfig(exampleServer(), nil)
	for _, want := range []string{"[Interface]", "PrivateKey = SERVERPRIVKEY", "Address = 10.8.0.1/24", "ListenPort = 51820"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered config missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "[Peer]") {
		t.Error("no peers given, but rendered config contains a [Peer] block")
	}
}

func TestRenderConfigIncludesEnabledPeersOnly(t *testing.T) {
	peers := []Peer{
		{Name: "alice-laptop", PublicKey: "ALICEPUB", AllowedIP: "10.8.0.2/32", Enabled: true},
		{Name: "bob-phone", PublicKey: "BOBPUB", AllowedIP: "10.8.0.3/32", Enabled: false},
	}
	out := RenderConfig(exampleServer(), peers)

	if !strings.Contains(out, "ALICEPUB") {
		t.Error("enabled peer's public key missing from rendered config")
	}
	if strings.Contains(out, "BOBPUB") {
		t.Error("disabled peer's public key must not appear in the live config")
	}
	if strings.Count(out, "[Peer]") != 1 {
		t.Errorf("expected exactly one [Peer] block (only the enabled peer), got %d", strings.Count(out, "[Peer]"))
	}
}
