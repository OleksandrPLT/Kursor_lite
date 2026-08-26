package server

import (
	"net/http"

	"kursor/internal/store"
)

// AuditLogData backs the System > Audit Log page.
type AuditLogData struct {
	PageData
	Entries []store.AuditEntry
	Q       string
}

func (s *Server) handleAuditLogPage(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	q := r.URL.Query().Get("q")
	entries, _ := s.store.ListAuditLog(q, 200)
	s.render(w, "system_audit", AuditLogData{
		PageData: s.basePageData(w, r, "system-audit", sess),
		Entries:  entries,
		Q:        q,
	})
}
