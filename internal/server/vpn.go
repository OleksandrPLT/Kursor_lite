package server

import (
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"kursor/internal/auth"
	ksites "kursor/internal/sites"
	"kursor/internal/store"
	kvpn "kursor/internal/vpn"
)

// errNoInstallKeyOnFile means a peer has no encrypted private key
// stored — either it predates install links entirely, or (in theory)
// its row was created outside the normal creation path. Either way,
// no config can be rendered for it without a real new peer.
var errNoInstallKeyOnFile = errors.New("vpn: peer has no install key on file")

// vpnInstallLinkTTL is how long a generated install link stays valid.
// Long enough that handing it to someone by chat/email and having them
// open it later in the day isn't a race, short enough that a link
// nobody used doesn't sit as a standing bearer credential forever —
// the admin can always mint a fresh one anytime, existing peer or not.
const vpnInstallLinkTTL = 24 * time.Hour

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

	// InstallLinkExpiry maps peer ID -> its current link's expiry, for
	// peers that have one — a *time.Time (not time.Time) so the
	// template's {{if}} can tell "no link" from "expires at the zero
	// time" (Go templates treat every non-pointer struct as truthy,
	// zero value or not).
	InstallLinkExpiry map[int64]*time.Time
	// NewInstallLinkPeerID/URL are shown once, right after generating
	// a link — same reveal-once treatment as NewPeerConfig, since the
	// raw token (unlike the peer's own address) is never shown again.
	NewInstallLinkPeerID int64
	NewInstallLinkURL    string
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

	expiries := make(map[int64]*time.Time, len(peers))
	for _, p := range peers {
		if exp, _ := s.store.GetVPNInstallLinkExpiry(p.ID); exp != nil {
			expiries[p.ID] = exp
		}
	}

	return VPNData{
		PageData:          s.basePageData(w, r, "network-vpn", sess),
		Installed:         kvpn.Detect().Installed,
		Peers:             peers,
		AllUsers:          users,
		Settings:          settings,
		ServerPublicKey:   pub,
		InstallLinkExpiry: expiries,
	}
}

// renderVPNClientConfig builds a peer's client .conf from its
// currently stored name/address/routes plus the CURRENT server
// settings — the one rendering path used by peer creation's one-time
// reveal and every install-link fetch, so they can never drift from
// each other, and an edited peer's next-opened link always reflects
// the edit without needing its private key again.
func (s *Server) renderVPNClientConfig(peer store.VPNPeer, peerPrivateKey, fallbackHost string) (string, error) {
	server, settings, err := s.serverVPNConfig()
	if err != nil {
		return "", err
	}
	serverPub, err := kvpn.PublicKey(server.PrivateKey)
	if err != nil {
		return "", err
	}
	endpoint := settings.Endpoint
	if endpoint == "" {
		endpoint = fallbackHost
		if h, _, err := net.SplitHostPort(endpoint); err == nil {
			endpoint = h
		}
	}
	allowedIPs := peer.ClientAllowedIPs
	if allowedIPs == "" {
		allowedIPs = strings.TrimSuffix(settings.ServerAddress, "/24") + "/24" // split-tunnel default: just the VPN subnet
	}
	return kvpn.RenderPeerConfig(kvpn.PeerClientConfig{
		PeerPrivateKey:  peerPrivateKey,
		PeerAddress:     strings.TrimSuffix(peer.AllowedIP, "/32") + "/24",
		ServerPublicKey: serverPub,
		Endpoint:        endpoint,
		Port:            settings.Port,
		AllowedIPs:      allowedIPs,
	}), nil
}

// vpnInstallConfigFor decrypts peerID's stored private key and renders
// its current client config — shared by the public install page and
// its config-download route so they always show byte-identical
// content, and by nothing else (this is the one place the encrypted
// key is ever decrypted back to plaintext).
func (s *Server) vpnInstallConfigFor(peerID int64, fallbackHost string) (config, peerName string, err error) {
	peer, err := s.store.GetVPNPeer(peerID)
	if err != nil {
		return "", "", err
	}
	if peer == nil || len(peer.EncryptedPrivateKey) == 0 {
		return "", "", errNoInstallKeyOnFile
	}
	installKey, err := kvpn.LoadOrGenerateInstallKey(s.cfg.DataDir)
	if err != nil {
		return "", "", err
	}
	priv, err := kvpn.DecryptPrivateKey(installKey, peer.EncryptedPrivateKey)
	if err != nil {
		return "", "", err
	}
	config, err = s.renderVPNClientConfig(*peer, priv, fallbackHost)
	return config, peer.Name, err
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
// stores it, and re-applies wg0.conf. The client .conf is shown here
// once, right after creation, the same "shown once" discipline as a
// ticket-generated temporary account password — but unlike a password,
// the underlying private key is ALSO kept, AES-256-GCM–encrypted (see
// internal/vpn.EncryptPrivateKey), specifically so an admin can come
// back later and generate a fresh install link without needing this
// exact response ever again.
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
	clientAllowedIPs := strings.TrimSpace(r.FormValue("client_allowed_ips"))

	var userID *int64
	if username := strings.TrimSpace(r.FormValue("target_username")); username != "" {
		if user, err := s.store.GetUserByUsername(username); err == nil && user != nil {
			userID = &user.ID
		}
	}

	_, settings, err := s.serverVPNConfig()
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

	installKey, err := kvpn.LoadOrGenerateInstallKey(s.cfg.DataDir)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	encPriv, err := kvpn.EncryptPrivateKey(installKey, peerPriv)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	peerID, err := s.store.CreateVPNPeer(name, userID, peerPub, allowedIP, encPriv, clientAllowedIPs)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if err := s.applyVPNConfig(); err != nil {
		// Roll back: a row that never made it into the live wg0.conf is
		// unrecoverable dead weight, not a peer the operator could still
		// use. Same "never leave a broken half-applied change behind"
		// discipline as Nginx's Create rolling back its symlink on a
		// failed `nginx -t`.
		_ = s.store.DeleteVPNPeer(peerID)
		renderErr("vpn.error.apply", err.Error())
		return
	}

	peer, err := s.store.GetVPNPeer(peerID)
	if err != nil || peer == nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	clientConfig, err := s.renderVPNClientConfig(*peer, peerPriv, r.Host)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	data := s.loadVPNData(w, r, sess)
	data.NewPeerName = name
	data.NewPeerConfig = clientConfig
	s.render(w, "network_vpn", data)
}

// handleVPNPeerEdit updates a peer's name, assigned user, and
// client-side routes. No wg0.conf reapply needed — none of these
// fields exist in the server's own config, only in the client .conf
// rendered on demand (see renderVPNClientConfig), so an edit takes
// effect the moment the peer's install link is next opened.
func (s *Server) handleVPNPeerEdit(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		http.Redirect(w, r, "/network/vpn", http.StatusSeeOther)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		data := s.loadVPNData(w, r, sess)
		data.FormErrorKey = "vpn.error.name_required"
		s.render(w, "network_vpn", data)
		return
	}
	var userID *int64
	if username := strings.TrimSpace(r.FormValue("target_username")); username != "" {
		if user, err := s.store.GetUserByUsername(username); err == nil && user != nil {
			userID = &user.ID
		}
	}
	clientAllowedIPs := strings.TrimSpace(r.FormValue("client_allowed_ips"))
	if err := s.store.UpdateVPNPeer(id, name, userID, clientAllowedIPs); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/network/vpn", http.StatusSeeOther)
}

// handleVPNInstallLinkCreate mints a fresh, time-limited install link
// for an existing peer — the moment that makes "give someone a link
// that installs their VPN config" actually work for peers created
// before right now, not just brand new ones, since the encrypted
// private key (unlike the plaintext shown at creation) sticks around.
func (s *Server) handleVPNInstallLinkCreate(w http.ResponseWriter, r *http.Request) {
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
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if peer == nil || len(peer.EncryptedPrivateKey) == 0 {
		// Nothing to generate a link from (peer predates this feature,
		// or lookup failed) — same silent no-op every other bad-id
		// action on this page falls back to.
		http.Redirect(w, r, "/network/vpn", http.StatusSeeOther)
		return
	}
	token, _, err := s.store.CreateVPNInstallLink(id, vpnInstallLinkTTL)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	data := s.loadVPNData(w, r, sess)
	data.NewInstallLinkPeerID = id
	data.NewInstallLinkURL = installLinkURL(r, token)
	s.render(w, "network_vpn", data)
}

func (s *Server) handleVPNInstallLinkRevoke(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if !auth.ValidCSRF(r) {
		http.Redirect(w, r, "/network/vpn", http.StatusSeeOther)
		return
	}
	_ = s.store.RevokeVPNInstallLink(id)
	http.Redirect(w, r, "/network/vpn", http.StatusSeeOther)
}

// installLinkURL builds the full, absolute URL to hand out — a bare
// path wouldn't be shareable outside the browser tab it was copied
// from.
func installLinkURL(r *http.Request, token string) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host + "/vpn/install/" + token
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
