package dbmanager

import (
	"os"
	"os/exec"
)

// EngineStatus is what the UI shows honestly instead of pretending a
// database engine is available when it isn't (same discipline as
// internal/sites.Status for Nginx).
type EngineStatus struct {
	Engine    string // "mysql" | "postgres"
	Installed bool   // client binary found on PATH
	Reachable bool   // local socket found
	Method    string // human-readable, for the UI ("unix socket", etc.)
}

// mysqlSocketPaths are the standard Debian/Ubuntu location first, then
// a couple of other common ones — macOS/Homebrew paths are a follow-up
// patch (see internal/sites for the same "general first" note).
var mysqlSocketPaths = []string{
	"/var/run/mysqld/mysqld.sock",
	"/var/lib/mysql/mysql.sock",
	"/tmp/mysql.sock",
}

var postgresSocketPaths = []string{
	"/var/run/postgresql/.s.PGSQL.5432",
	"/tmp/.s.PGSQL.5432",
}

func firstExisting(paths []string) string {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// DetectMySQL probes for the `mysql` client and a local socket.
func DetectMySQL() (EngineStatus, string) {
	_, err := exec.LookPath("mysql")
	socket := firstExisting(mysqlSocketPaths)
	st := EngineStatus{Engine: "mysql", Installed: err == nil, Reachable: socket != ""}
	if st.Reachable {
		st.Method = "unix socket"
	}
	return st, socket
}

// DetectPostgres probes for the `psql` client and a local socket.
func DetectPostgres() (EngineStatus, string) {
	_, err := exec.LookPath("psql")
	socket := firstExisting(postgresSocketPaths)
	st := EngineStatus{Engine: "postgres", Installed: err == nil, Reachable: socket != ""}
	if st.Reachable {
		st.Method = "unix socket"
	}
	return st, socket
}
