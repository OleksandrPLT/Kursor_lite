package server

import (
	"database/sql"
	"net/http"

	"kursor/internal/auth"
	"kursor/internal/dbmanager"
)

// DatabasesData backs the database manager page — real MySQL/PostgreSQL
// connections when reachable, honest "not detected" cards otherwise
// (same discipline as sites.go for Nginx).
type DatabasesData struct {
	PageData
	MySQLStatus    dbmanager.EngineStatus
	PostgresStatus dbmanager.EngineStatus
	Engine         string // "mysql" | "postgres" — which tab is active
	Databases      []string
	NewDBName      string
	NewUsername    string
	NewPassword    string
	FormErrorKey   string
	ErrorDetail    string
}

func activeEngine(r *http.Request) string {
	e := r.URL.Query().Get("engine")
	if e != "postgres" {
		return "mysql"
	}
	return e
}

// openActiveEngine opens a connection for the requested engine, or
// returns ok=false if that engine isn't reachable on this host.
func openActiveEngine(engine string) (db *sql.DB, ok bool, err error) {
	if engine == "postgres" {
		_, socket := dbmanager.DetectPostgres()
		if socket == "" {
			return nil, false, nil
		}
		db, err = dbmanager.OpenPostgres(socket)
		return db, true, err
	}
	_, socket := dbmanager.DetectMySQL()
	if socket == "" {
		return nil, false, nil
	}
	db, err = dbmanager.OpenMySQL(socket)
	return db, true, err
}

func (s *Server) handleDatabasesPage(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	engine := activeEngine(r)
	mysqlStatus, _ := dbmanager.DetectMySQL()
	pgStatus, _ := dbmanager.DetectPostgres()

	data := DatabasesData{
		PageData:       s.basePageData(w, r, "databases", sess),
		MySQLStatus:    mysqlStatus,
		PostgresStatus: pgStatus,
		Engine:         engine,
	}

	db, reachable, err := openActiveEngine(engine)
	if reachable && err == nil {
		defer db.Close()
		if engine == "postgres" {
			data.Databases, _ = dbmanager.ListPostgresDatabases(db)
		} else {
			data.Databases, _ = dbmanager.ListMySQLDatabases(db)
		}
	} else if reachable && err != nil {
		data.ErrorDetail = err.Error()
	}

	s.render(w, "databases", data)
}

func (s *Server) handleDatabaseCreate(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	engine := activeEngine(r)

	renderWithError := func(key, detail string) {
		data := DatabasesData{
			PageData:     s.basePageData(w, r, "databases", sess),
			Engine:       engine,
			FormErrorKey: key,
			ErrorDetail:  detail,
		}
		data.MySQLStatus, _ = dbmanager.DetectMySQL()
		data.PostgresStatus, _ = dbmanager.DetectPostgres()
		s.render(w, "databases", data)
	}

	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		renderWithError("login.error.csrf", "")
		return
	}

	dbName := r.FormValue("name")
	if err := dbmanager.ValidIdentifier(dbName); err != nil {
		renderWithError("databases.error.invalid_name", "")
		return
	}

	db, reachable, err := openActiveEngine(engine)
	if !reachable {
		renderWithError("databases.error.not_reachable", "")
		return
	}
	if err != nil {
		renderWithError("databases.error.connect", err.Error())
		return
	}
	defer db.Close()

	var createErr error
	if engine == "postgres" {
		createErr = dbmanager.CreatePostgresDatabase(db, dbName)
	} else {
		createErr = dbmanager.CreateMySQLDatabase(db, dbName)
	}
	if createErr != nil {
		renderWithError("databases.error.create", createErr.Error())
		return
	}

	// Optionally create a paired user scoped to this database.
	newUsername := ""
	newPassword := ""
	if r.FormValue("create_user") == "on" {
		username := dbName + "_user"
		password, genErr := auth.GenerateTempPassword()
		if genErr == nil {
			var grantErr error
			if engine == "postgres" {
				grantErr = dbmanager.CreatePostgresUserAndGrant(db, username, password, dbName)
			} else {
				grantErr = dbmanager.CreateMySQLUserAndGrant(db, username, password, dbName)
			}
			if grantErr == nil {
				newUsername, newPassword = username, password
			}
		}
	}

	data := DatabasesData{
		PageData:    s.basePageData(w, r, "databases", sess),
		Engine:      engine,
		NewDBName:   dbName,
		NewUsername: newUsername,
		NewPassword: newPassword,
	}
	data.MySQLStatus, _ = dbmanager.DetectMySQL()
	data.PostgresStatus, _ = dbmanager.DetectPostgres()
	if engine == "postgres" {
		data.Databases, _ = dbmanager.ListPostgresDatabases(db)
	} else {
		data.Databases, _ = dbmanager.ListMySQLDatabases(db)
	}
	s.render(w, "databases", data)
}

func (s *Server) handleDatabaseDrop(w http.ResponseWriter, r *http.Request) {
	engine := activeEngine(r)
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		http.Redirect(w, r, "/databases?engine="+engine, http.StatusSeeOther)
		return
	}
	name := r.FormValue("name")

	db, reachable, err := openActiveEngine(engine)
	if reachable && err == nil {
		defer db.Close()
		if engine == "postgres" {
			_ = dbmanager.DropPostgresDatabase(db, name)
		} else {
			_ = dbmanager.DropMySQLDatabase(db, name)
		}
	}
	http.Redirect(w, r, "/databases?engine="+engine, http.StatusSeeOther)
}
