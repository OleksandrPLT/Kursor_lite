package vpn

import "fmt"

// PeerClientConfig holds everything needed to render a ready-to-import
// client .conf — the file a person drops straight into the WireGuard
// app on their laptop/phone.
type PeerClientConfig struct {
	PeerPrivateKey  string
	PeerAddress     string // e.g. "10.8.0.2/24" — /24 so the client's own routing table knows the whole VPN subnet, not just its own IP
	ServerPublicKey string
	Endpoint        string // host or host:port the client dials
	Port            int
	AllowedIPs      string // what the client routes through the tunnel — see RenderPeerConfig
}

// RenderPeerConfig renders a client .conf. AllowedIPs defaults to just
// the VPN subnet (split-tunnel: only office resources go through the
// VPN, everything else stays on the client's normal internet) rather
// than "0.0.0.0/0" — a deliberate, safer default for an internal
// company VPN than routing every byte of someone's traffic through this
// one box; an operator who wants full-tunnel can still write "0.0.0.0/0, ::/0" when creating the peer.
func RenderPeerConfig(c PeerClientConfig) string {
	return fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s

[Peer]
PublicKey = %s
Endpoint = %s:%d
AllowedIPs = %s
PersistentKeepalive = 25
`, c.PeerPrivateKey, c.PeerAddress, c.ServerPublicKey, c.Endpoint, c.Port, c.AllowedIPs)
}
