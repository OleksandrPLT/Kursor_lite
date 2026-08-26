package server

import (
	"net/http"
	"strconv"

	"kursor/internal/auth"
	"kursor/internal/store"
)

// NotificationsData backs the full System > Notifications page (the
// topbar bell dropdown shows the same data, trimmed to 8 — see
// basePageData).
type NotificationsData struct {
	PageData
	Notifications []store.Notification
}

func (s *Server) handleNotificationsPage(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	notifications, _ := s.store.ListNotifications(sess.UserID, 100)
	s.render(w, "system_notifications", NotificationsData{
		PageData:      s.basePageData(w, r, "system-notifications", sess),
		Notifications: notifications,
	})
}

// handleNotificationRead marks one notification read then redirects to
// its link — this is what the bell dropdown / list actually navigates
// through (see network_notifications' links), so opening a
// notification always also clears it.
func (s *Server) handleNotificationRead(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	link := r.URL.Query().Get("link")
	if link == "" {
		link = "/system/notifications"
	}
	if err == nil {
		_ = s.store.MarkNotificationRead(id, sess.UserID)
	}
	http.Redirect(w, r, link, http.StatusSeeOther)
}

func (s *Server) handleNotificationsMarkAllRead(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		http.Redirect(w, r, "/system/notifications", http.StatusSeeOther)
		return
	}
	_ = s.store.MarkAllNotificationsRead(sess.UserID)
	referer := r.Header.Get("Referer")
	if referer == "" {
		referer = "/system/notifications"
	}
	http.Redirect(w, r, referer, http.StatusSeeOther)
}
