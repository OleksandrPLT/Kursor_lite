// Package server wires Kursor's HTTP surface together: routing,
// middleware, template rendering, and the handlers for auth and the
// dashboard shell. Feature modules (sites, files, databases) register
// their own handlers here as they're built — see the project plan's
// milestone order.
package server

import (
	"html/template"
	"io/fs"
	"net/http"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"kursor/internal/config"
	"kursor/internal/monitor"
	"kursor/internal/oidc"
	"kursor/internal/store"
	"kursor/web"
)

// Server holds everything the HTTP handlers need.
type Server struct {
	cfg     config.Config
	store   *store.Store
	monitor *monitor.Collector
	oidc    *oidc.Issuer
	tmpl    *template.Template
}

// New builds the full router.
func New(cfg config.Config, st *store.Store, mon *monitor.Collector, issuer *oidc.Issuer) (http.Handler, error) {
	tmpl, err := loadTemplates()
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, store: st, monitor: mon, oidc: issuer, tmpl: tmpl}

	r := chi.NewRouter()
	r.Use(chimw.Logger)
	r.Use(chimw.Recoverer)

	staticFS, err := fs.Sub(web.FS, "static")
	if err != nil {
		return nil, err
	}
	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

	r.Get("/login", s.handleLoginPage)
	r.Post("/login", s.handleLoginSubmit)
	r.Post("/logout", s.handleLogout)

	// The Service Desk portal — a minimal, sidebar-free surface for
	// accounts that only ever need to submit/track their own tickets.
	// Same accounts/session cookie as the main panel (see portal.go's
	// doc comment), just a different login page and a stricter,
	// always-"my own tickets" set of routes.
	r.Get("/portal/login", s.handlePortalLoginPage)
	r.Post("/portal/login", s.handlePortalLoginSubmit)
	r.Post("/portal/logout", s.handlePortalLogout)
	r.Group(func(r chi.Router) {
		r.Use(s.requirePortalAuth)
		r.Get("/portal", s.handlePortalPage)
		r.Post("/portal/tickets", s.handlePortalTicketCreate)
		r.Get("/portal/tickets/{id}", s.handlePortalTicketPage)
		r.Post("/portal/tickets/{id}/comments", s.handlePortalTicketComment)
		r.Get("/portal/tickets/{id}/attachments/{attachment_id}", s.handlePortalAttachmentDownload)
	})

	r.Get("/lang/{code}", func(w http.ResponseWriter, r *http.Request) {
		s.handleSetLang(w, r, chi.URLParam(r, "code"))
	})

	// OIDC endpoints consumed by external apps, not browsers with a
	// Kursor session — no auth middleware; each authenticates its own
	// way (client_secret, PKCE, or a bearer token).
	r.Get("/.well-known/openid-configuration", s.handleOIDCDiscovery)
	r.Get("/oauth/jwks", s.handleJWKS)
	r.Post("/oauth/token", s.handleToken)
	r.Get("/oauth/userinfo", s.handleUserInfo)
	r.Post("/oauth/userinfo", s.handleUserInfo)

	// Integrations API — bearer-token auth (requireAPIKey), not a cookie
	// session: this is the door for external platforms/webhooks, not
	// browsers. See internal/server/integrations.go.
	r.Group(func(r chi.Router) {
		r.Use(s.requireAPIKey)
		r.Post("/api/v1/tickets", s.handleAPICreateTicket)
	})

	r.Group(func(r chi.Router) {
		r.Use(s.requireAuth)
		r.Use(s.auditLog)

		r.Get("/", s.handleDashboard)

		// Any logged-in user can authorize a registered project as
		// themselves — this isn't gated by a module permission the way
		// Sites/Files/etc. are.
		r.Get("/oauth/authorize", s.handleAuthorizeGet)
		r.Post("/oauth/authorize", s.handleAuthorizePost)

		r.Group(func(r chi.Router) {
			r.Use(s.requireModule("sites"))
			r.Get("/sites", s.handleSitesPage)
			r.Post("/sites/install-nginx", s.handleSitesInstallNginx)
			r.Post("/sites", s.handleSiteCreate)
			r.Post("/sites/{id}/status", s.handleSiteToggle)
			r.Post("/sites/{id}/delete", s.handleSiteDelete)
		})
		r.Group(func(r chi.Router) {
			r.Use(s.requireModule("files"))
			r.Get("/files", s.handleFilesPage)
			r.Get("/files/download", s.handleFileDownload)
			r.Get("/files/edit", s.handleFileEditPage)
			r.Post("/files/edit", s.handleFileEditSave)
			r.Post("/files/upload", s.handleFileUpload)
			r.Post("/files/create", s.handleFileCreate)
			r.Post("/files/rename", s.handleFileRename)
			r.Post("/files/move", s.handleFileMove)
			r.Post("/files/copy", s.handleFileCopy)
			r.Post("/files/chmod", s.handleFileChmod)
			r.Post("/files/delete", s.handleFileDelete)
		})
		r.Group(func(r chi.Router) {
			r.Use(s.requireModule("databases"))
			r.Get("/databases", s.handleDatabasesPage)
			r.Post("/databases", s.handleDatabaseCreate)
			r.Post("/databases/drop", s.handleDatabaseDrop)
		})

		r.Group(func(r chi.Router) {
			r.Use(s.requireModule("server"))
			r.Get("/server/ssl", s.handleSSLPage)
			r.Post("/server/ssl/install-certbot", s.handleSSLInstallCertbot)
			r.Post("/server/ssl/{id}/issue", s.handleSSLIssue)
			r.Get("/server/cron", s.handleCronPage)
			r.Post("/server/cron", s.handleCronCreate)
			r.Post("/server/cron/{id}/toggle", s.handleCronToggle)
			r.Post("/server/cron/{id}/delete", s.handleCronDelete)
			r.Get("/server/backups", s.handleBackupsPage)
			r.Post("/server/backups", s.handleBackupCreate)
			r.Get("/server/backups/download", s.handleBackupDownload)
			r.Post("/server/backups/delete", s.handleBackupDelete)
			r.Get("/server/terminal", s.handleTerminalPage)
			r.Get("/server/terminal/ws", s.handleTerminalWS)
			r.Get("/server/software", s.handleSoftwarePage)
			r.Post("/server/software/install", s.handleSoftwareInstall)
		})

		r.Group(func(r chi.Router) {
			r.Use(s.requireModule("network"))
			r.Get("/network/domains", s.handleDomainsPage)
			r.Post("/network/domains", s.handleDomainCreate)
			r.Post("/network/domains/{id}/update", s.handleDomainUpdate)
			r.Post("/network/domains/{id}/delete", s.handleDomainDelete)
			r.Post("/network/domains/{id}/create-subdomain", s.handleDomainCreateSubdomain)
			r.Post("/network/domains/records", s.handleDomainAddRecord)
			r.Get("/network/nsserver", s.handleNSServerPage)
			r.Post("/network/nsserver/install", s.handleNSServerInstall)
			r.Post("/network/nsserver/zones", s.handleNSServerZoneCreate)
			r.Post("/network/nsserver/zones/delete", s.handleNSServerZoneDelete)
			r.Post("/network/nsserver/records", s.handleNSServerRecordUpsert)
			r.Post("/network/nsserver/records/delete", s.handleNSServerRecordDelete)
			r.Get("/network/dns", s.handleDNSPage)
			r.Post("/network/dns/install", s.handleDNSInstall)
			r.Post("/network/dns", s.handleDNSRecordCreate)
			r.Post("/network/dns/{id}/delete", s.handleDNSRecordDelete)
			r.Get("/network/ports", s.handlePortsPage)
			r.Post("/network/ports/install-ufw", s.handlePortsInstallUFW)
			r.Post("/network/ports/enable-ufw", s.handlePortsEnableUFW)
			r.Post("/network/ports/open", s.handlePortOpen)
			r.Post("/network/ports/close", s.handlePortClose)
			r.Post("/network/ports/close-many", s.handlePortsCloseMany)
			r.Post("/network/ports/label", s.handlePortLabelSet)
			r.Post("/network/ports/forwards", s.handlePortForwardCreate)
			r.Post("/network/ports/forwards/delete", s.handlePortForwardDelete)
			r.Get("/network/vpn", s.handleVPNPage)
			r.Post("/network/vpn/install", s.handleVPNInstall)
			r.Post("/network/vpn/settings", s.handleVPNSettingsUpdate)
			r.Post("/network/vpn/peers", s.handleVPNPeerCreate)
			r.Post("/network/vpn/peers/{id}/toggle", s.handleVPNPeerToggle)
			r.Post("/network/vpn/peers/{id}/delete", s.handleVPNPeerDelete)
			r.Get("/network/ssh", s.handleSSHPage)
			r.Post("/network/ssh/keys", s.handleSSHKeyAdd)
			r.Post("/network/ssh/keys/delete", s.handleSSHKeyDelete)
			r.Post("/network/ssh/port", s.handleSSHPortUpdate)
			r.Post("/network/ssh/password-auth", s.handleSSHPasswordAuthUpdate)
		})

		r.Get("/monitor/stream", s.monitor.ServeStream)

		// Service Desk: every authenticated user can submit/see their
		// own tickets; the "servicedesk" permission (or admin) unlocks
		// seeing and triaging everyone's — enforced inside the handlers
		// themselves (isAgent/loadTicket in servicedesk.go), not by a
		// requireModule gate, since baseline access isn't all-or-nothing
		// here the way it is for Sites/Files/etc.
		r.Get("/company/servicedesk", s.handleServiceDeskPage)
		r.Post("/company/servicedesk", s.handleTicketCreate)
		r.Get("/company/servicedesk/{id}", s.handleTicketPage)
		r.Post("/company/servicedesk/{id}/status", s.handleTicketStatus)
		r.Post("/company/servicedesk/{id}/group", s.handleTicketSetGroup)
		r.Post("/company/servicedesk/{id}/escalate", s.handleTicketEscalate)
		r.Post("/company/servicedesk/{id}/assign-me", s.handleTicketAssignToMe)
		r.Post("/company/servicedesk/{id}/assign", s.handleTicketAssign)
		r.Post("/company/servicedesk/{id}/create-account", s.handleTicketCreateAccount)
		r.Post("/company/servicedesk/{id}/grant-access", s.handleTicketGrantAccess)
		r.Post("/company/servicedesk/{id}/terminate-target", s.handleTicketTerminateTarget)
		r.Post("/company/servicedesk/{id}/comments", s.handleTicketComment)
		r.Get("/company/servicedesk/{id}/attachments/{attachment_id}", s.handleTicketAttachmentDownload)

		// Notifications: every logged-in user has their own — not gated
		// by any module permission, same reasoning as Service Desk above.
		r.Get("/system/notifications", s.handleNotificationsPage)
		r.Get("/system/notifications/open", s.handleNotificationRead)
		r.Post("/system/notifications/mark-all-read", s.handleNotificationsMarkAllRead)

		r.Get("/accounts/{id}/avatar", s.handleAccountAvatar)

		// Viewing a profile (read-only) is open to every logged-in
		// user, not just admins — "who is this person" is reasonable to
		// know regardless of module access; editing (below, inside the
		// requireAdmin group) stays admin-only.
		r.Get("/accounts/{id}", s.handleAccountProfile)

		r.Group(func(r chi.Router) {
			r.Use(s.requireAdmin)
			r.Get("/accounts", s.handleAccountsPage)
			r.Post("/accounts", s.handleAccountsCreate)
			r.Get("/accounts/{id}/edit", s.handleAccountEditPage)
			r.Post("/accounts/{id}/edit", s.handleAccountEditSubmit)
			r.Post("/accounts/{id}/reset-password", s.handleAccountResetPassword)
			r.Post("/accounts/{id}/status", s.handleAccountStatus)
			r.Post("/accounts/{id}/terminate", s.handleAccountTerminate)
			r.Post("/accounts/{id}/delete", s.handleAccountDelete)

			r.Get("/departments", s.handleOrgPage)
			r.Post("/departments", s.handleDepartmentCreate)
			r.Post("/departments/{id}/delete", s.handleDepartmentDelete)
			r.Post("/positions", s.handlePositionCreate)
			r.Post("/positions/{id}/delete", s.handlePositionDelete)

			r.Get("/company/mail", s.handleMailPage)
			r.Post("/company/mail/install", s.handleMailInstall)
			r.Post("/company/mail/domains", s.handleMailDomainCreate)
			r.Post("/company/mail/domains/{id}/delete", s.handleMailDomainDelete)
			r.Post("/company/mail/mailboxes", s.handleMailboxCreate)
			r.Post("/company/mail/mailboxes/{id}/delete", s.handleMailboxDelete)
			r.Post("/company/mail/mailboxes/{id}/reset-password", s.handleMailboxResetPassword)
			r.Get("/company/mail/mailboxes/{id}/inbox", s.handleMailboxInbox)
			r.Get("/company/mail/mailboxes/{id}/inbox/{uid}", s.handleMailboxMessage)
			r.Get("/company/sso", s.handleSSOPage)
			r.Post("/company/sso", s.handleSSOCreate)
			r.Post("/company/sso/delete", s.handleSSODelete)

			r.Get("/company/integrations", s.handleIntegrationsPage)
			r.Post("/company/integrations/keys", s.handleAPIKeyCreate)
			r.Post("/company/integrations/keys/{id}/revoke", s.handleAPIKeyRevoke)

			r.Get("/company/approvals", s.handleApprovalsPage)
			r.Post("/company/servicedesk/{id}/approval", s.handleTicketApproval)

			r.Get("/system/audit-log", s.handleAuditLogPage)
			r.Get("/system/updates", s.handleUpdatesPage)
			// API keys live under Integrations now (see internal/server/integrations.go) — redirect the old nav slot rather than 404 anyone with it bookmarked.
			r.Get("/system/api-keys", func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "/company/integrations", http.StatusMovedPermanently)
			})
		})
	})

	return r, nil
}
