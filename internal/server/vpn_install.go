// vpn_install.go: the public, unauthenticated side of a VPN install
// link — /vpn/install/{token}. Deliberately outside every auth
// middleware group (see server.go): whoever holds the link is meant to
// be able to open it on whatever device they're setting up, without a
// Kursor account of their own. The token itself (32 random bytes,
// checked by its hash — see store.ResolveVPNInstallToken) is the only
// thing standing in for a session here, same trust model as a signed
// download URL.
package server

import (
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/skip2/go-qrcode"
)

// VPNInstallData backs the public install landing page.
type VPNInstallData struct {
	Lang       string
	Token      string // the URL's own token, so the page can link to its /config sibling without guessing the path
	PeerName   string
	ConfigText string
	QRDataURI  string // "" if QR generation failed — the page falls back to the download button + raw text
	Expired    bool
	NotFound   bool
}

func (s *Server) handleVPNInstallPage(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	lang := getLang(r)

	peerID, expiresAt, found, err := s.store.ResolveVPNInstallToken(token)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !found {
		w.WriteHeader(http.StatusNotFound)
		s.render(w, "vpn_install", VPNInstallData{Lang: lang, NotFound: true})
		return
	}
	if time.Now().After(expiresAt) {
		s.render(w, "vpn_install", VPNInstallData{Lang: lang, Expired: true})
		return
	}

	config, peerName, err := s.vpnInstallConfigFor(peerID, r.Host)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	var qrURI string
	if png, err := qrcode.Encode(config, qrcode.Medium, 320); err == nil {
		qrURI = "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)
	}

	s.render(w, "vpn_install", VPNInstallData{
		Lang:       lang,
		Token:      token,
		PeerName:   peerName,
		ConfigText: config,
		QRDataURI:  qrURI,
	})
}

// handleVPNInstallConfigDownload serves the raw .conf — WireGuard's
// desktop apps (Windows/macOS/Linux) accept this directly via "Import
// tunnel(s) from file," and mobile apps take it through the share
// sheet, when scanning the landing page's QR code isn't the easier
// path (e.g. installing on the same device that's viewing the page).
func (s *Server) handleVPNInstallConfigDownload(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")
	peerID, expiresAt, found, err := s.store.ResolveVPNInstallToken(token)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !found || time.Now().After(expiresAt) {
		http.NotFound(w, r)
		return
	}
	config, peerName, err := s.vpnInstallConfigFor(peerID, r.Host)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+sanitizeConfigFilename(peerName)+`.conf"`)
	_, _ = w.Write([]byte(config))
}

// sanitizeConfigFilename strips characters that would break (or
// inject into) a Content-Disposition header — peer names are set by
// whoever created the peer, an authenticated admin, but this value
// still ends up in an HTTP header on a route anyone with the link can
// hit, so it gets the same treatment as an uploaded attachment's
// original filename (see attachments.go).
func sanitizeConfigFilename(name string) string {
	name = strings.ReplaceAll(name, `"`, "")
	name = strings.ReplaceAll(name, "\n", "")
	name = strings.ReplaceAll(name, "\r", "")
	name = strings.TrimSpace(name)
	if name == "" {
		name = "kursor-vpn"
	}
	return name
}
