package server

import (
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"kursor/internal/auth"
	ksites "kursor/internal/sites"
	"kursor/internal/store"
	kvpn "kursor/internal/vpn"
)

// VPNData backs the VPN peers page — real WireGuard peers (see
// internal/vpn), not a mockup.
type VPNData struct {
	PageData
	Installed       bool
	Peers           []store.VPNPeer
	AllUsers        []store.User
	Settings        store.VPNSettings
	ServerPublicKey string
	NewPeerName     string
	NewPeerConfig   string // shown once, right after creation — see handleVPNPeerCreate
	FormErrorKey    string
	ErrorDetail     string
}

// serverVPNConfig assembles this host's [Interface] section from its
// persisted private key + the admin-set endpoint/subnet — shared by
// every handler that needs to re-render wg0.conf.
func (s *Server) serverVPNConfig() (kvpn.ServerConfig, store.VPNSettings, error) {
	settings, err := s.store.GetVPNSettings()
	if err != nil {
		return kvpn.ServerConfig{}, settings, err
	}
	priv, err := kvpn.LoadOrGenerateServerKey(s.cfg.DataDir)
	if err != nil {
		return kvpn.ServerConfig{}, settings, err
	}
	return kvpn.ServerConfig{PrivateKey: priv, Address: settings.ServerAddress, ListenPort: settings.Port}, settings, nil
}

// applyVPNConfig regenerates wg0.conf from every enabled peer and
// reloads — same "always regenerate the whole file from the database"
// discipline as internal/cron.Sync and Nginx's Create/SetEnabled.
func (s *Server) applyVPNConfig() error {
	server, _, err := s.serverVPNConfig()
	if err != nil {
		return err
	}
	dbPeers, err := s.store.ListVPNPeers()
	if err != nil {
		return err
	}
	peers := make([]kvpn.Peer, 0, len(dbPeers))
	for _, p := range dbPeers {
		peers = append(peers, kvpn.Peer{Name: p.Name, PublicKey: p.PublicKey, AllowedIP: p.AllowedIP, Enabled: p.Enabled})
	}
	return kvpn.Apply(server, peers)
}

// subnetPrefix turns "10.8.0.1/24" into "10.8.0." for NextVPNIP/peer
// address rendering — the settings row only stores the server's own
// address, not the prefix separately, so every caller derives it here.
func subnetPrefix(serverAddress string) string {
	host, _, _ := strings.Cut(serverAddress, "/")
	i := strings.LastIndex(host, ".")
	if i < 0 {
		return "10.8.0."
	}
	return host[:i+1]
}

func (s *Server) loadVPNData(w http.ResponseWriter, r *http.Request, sess *store.Session) VPNData {
	peers, _ := s.store.ListVPNPeers()
	users, _ := s.store.ListUsers()
	server, settings, _ := s.serverVPNConfig()
	pub, _ := kvpn.PublicKey(server.PrivateKey)
	return VPNData{
		PageData:        s.basePageData(w, r, "network-vpn", sess),
		Installed:       kvpn.Detect().Installed,
		Peers:           peers,
		AllUsers:        users,
		Settings:        settings,
		ServerPublicKey: pub,
	}
}

func (s *Server) handleVPNPage(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	s.render(w, "network_vpn", s.loadVPNData(w, r, sess))
}

func (s *Server) handleVPNInstall(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		data := s.loadVPNData(w, r, sess)
		data.FormErrorKey = "login.error.csrf"
		s.render(w, "network_vpn", data)
		return
	}
	out, err := ksites.InstallWireGuard()
	data := s.loadVPNData(w, r, sess)
	if err != nil {
		data.FormErrorKey = "vpn.error.install"
		data.ErrorDetail = out
		if data.ErrorDetail == "" {
			data.ErrorDetail = err.Error()
		}
	}
	s.render(w, "network_vpn", data)
}

func (s *Server) handleVPNSettingsUpdate(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	renderErr := func(key string) {
		data := s.loadVPNData(w, r, sess)
		data.FormErrorKey = key
		s.render(w, "network_vpn", data)
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		renderErr("login.error.csrf")
		return
	}
	endpoint := strings.TrimSpace(r.FormValue("endpoint"))
	port, err := strconv.Atoi(r.FormValue("port"))
	if err != nil || port < 1 || port > 65535 {
		renderErr("vpn.error.invalid_port")
		return
	}
	if err := s.store.UpdateVPNSettings(endpoint, port); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/network/vpn", http.StatusSeeOther)
}

// handleVPNPeerCreate generates a fresh keypair + IP for a new peer,
// stores it, and re-applies wg0.conf. The peer's private key is never
// stored (only its public key is — that's all the server ever needs) so
// the client .conf can only ever be shown here, once, right after
// creation — same "shown once" discipline as a ticket-generated
// temporary account password.
func (s *Server) handleVPNPeerCreate(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	renderErr := func(key, detail string) {
		data := s.loadVPNData(w, r, sess)
		data.FormErrorKey = key
		data.ErrorDetail = detail
		s.render(w, "network_vpn", data)
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		renderErr("login.error.csrf", "")
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		renderErr("vpn.error.name_required", "")
		return
	}

	var userID *int64
	if username := strings.TrimSpace(r.FormValue("target_username")); username != "" {
		if user, err := s.store.GetUserByUsername(username); err == nil && user != nil {
			userID = &user.ID
		}
	}

	server, settings, err := s.serverVPNConfig()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	prefix := subnetPrefix(settings.ServerAddress)

	peerPriv, err := kvpn.GeneratePrivateKey()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	peerPub, err := kvpn.PublicKey(peerPriv)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	allowedIP, err := s.store.NextVPNIP(prefix)
	if err != nil {
		renderErr("vpn.error.no_free_ip", "")
		return
	}

	peerID, err := s.store.CreateVPNPeer(name, userID, peerPub, allowedIP)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := s.applyVPNConfig(); err != nil {
		// Roll back: the peer's private key only ever lived in this
		// request's memory (never stored — see the comment above), so a
		// row that never made it into the live wg0.conf is unrecoverable
		// dead weight, not a peer the operator could still use. Same
		// "never leave a broken half-applied change behind" discipline
		// as Nginx's Create rolling back its symlink on a failed `nginx -t`.
		_ = s.store.DeleteVPNPeer(peerID)
		renderErr("vpn.error.apply", err.Error())
		return
	}

	serverPub, _ := kvpn.PublicKey(server.PrivateKey)
	peerAddress := strings.TrimSuffix(allowedIP, "/32") + "/24"
	endpoint := settings.Endpoint
	if endpoint == "" {
		endpoint = r.Host
		if h, _, err := net.SplitHostPort(endpoint); err == nil {
			endpoint = h
		}
	}
	clientConfig := kvpn.RenderPeerConfig(kvpn.PeerClientConfig{
		PeerPrivateKey:  peerPriv,
		PeerAddress:     peerAddress,
		ServerPublicKey: serverPub,
		Endpoint:        endpoint,
		Port:            settings.Port,
		AllowedIPs:      strings.TrimSuffix(settings.ServerAddress, "/24") + "/24", // split-tunnel: just the VPN subnet
	})

	data := s.loadVPNData(w, r, sess)
	data.NewPeerName = name
	data.NewPeerConfig = clientConfig
	s.render(w, "network_vpn", data)
}

func (s *Server) handleVPNPeerToggle(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if !auth.ValidCSRF(r) {
		http.Redirect(w, r, "/network/vpn", http.StatusSeeOther)
		return
	}
	peer, err := s.store.GetVPNPeer(id)
	if err != nil || peer == nil {
		http.Redirect(w, r, "/network/vpn", http.StatusSeeOther)
		return
	}
	_ = s.store.SetVPNPeerEnabled(id, !peer.Enabled)
	if err := s.applyVPNConfig(); err != nil {
		data := s.loadVPNData(w, r, sess)
		data.FormErrorKey = "vpn.error.apply"
		data.ErrorDetail = err.Error()
		s.render(w, "network_vpn", data)
		return
	}
	http.Redirect(w, r, "/network/vpn", http.StatusSeeOther)
}

func (s *Server) handleVPNPeerDelete(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if !auth.ValidCSRF(r) {
		http.Redirect(w, r, "/network/vpn", http.StatusSeeOther)
		return
	}
	_ = s.store.DeleteVPNPeer(id)
	if err := s.applyVPNConfig(); err != nil {
		data := s.loadVPNData(w, r, sess)
		data.FormErrorKey = "vpn.error.apply"
		data.ErrorDetail = err.Error()
		s.render(w, "network_vpn", data)
		return
	}
	http.Redirect(w, r, "/network/vpn", http.StatusSeeOther)
}
