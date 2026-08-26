package server

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"kursor/internal/auth"
	"kursor/internal/store"
)

// OrgData backs the departments & positions management page.
type OrgData struct {
	PageData
	Departments []store.Department
	// DeptNames is the id->name lookup Department.Path needs to render
	// "Parent / Child" without an extra query per row.
	DeptNames map[int64]string
	Positions []store.Position
}

func (s *Server) loadOrgData(w http.ResponseWriter, r *http.Request, sess *store.Session) OrgData {
	departments, _ := s.store.ListDepartments()
	positions, _ := s.store.ListPositions()
	names := make(map[int64]string, len(departments))
	for _, d := range departments {
		names[d.ID] = d.Name
	}
	return OrgData{
		PageData:    s.basePageData(w, r, "departments", sess),
		Departments: departments,
		DeptNames:   names,
		Positions:   positions,
	}
}

func (s *Server) handleOrgPage(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	s.render(w, "organization", s.loadOrgData(w, r, sess))
}

func (s *Server) handleDepartmentCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err == nil && auth.ValidCSRF(r) {
		name := r.FormValue("name")
		if name != "" {
			_, _ = s.store.CreateDepartment(name, parseOptionalID(r.FormValue("parent_id")))
		}
	}
	http.Redirect(w, r, "/departments", http.StatusSeeOther)
}

func (s *Server) handleDepartmentDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err == nil && auth.ValidCSRF(r) {
		_ = s.store.DeleteDepartment(id)
	}
	http.Redirect(w, r, "/departments", http.StatusSeeOther)
}

func (s *Server) handlePositionCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err == nil && auth.ValidCSRF(r) {
		name := r.FormValue("name")
		if name != "" {
			_, _ = s.store.CreatePosition(name)
		}
	}
	http.Redirect(w, r, "/departments", http.StatusSeeOther)
}

func (s *Server) handlePositionDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err == nil && auth.ValidCSRF(r) {
		_ = s.store.DeletePosition(id)
	}
	http.Redirect(w, r, "/departments", http.StatusSeeOther)
}
