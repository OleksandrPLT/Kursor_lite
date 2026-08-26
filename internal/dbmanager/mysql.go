package dbmanager

import (
	"database/sql"
	"fmt"

	_ "github.com/go-sql-driver/mysql"
)

var mysqlSystemDBs = map[string]bool{
	"mysql":              true,
	"information_schema": true,
	"performance_schema": true,
	"sys":                true,
}

// OpenMySQL connects via the local unix socket as root — the
// `auth_socket`/`unix_socket` plugin common on Debian/Ubuntu installs
// authenticates this with no password when the OS process is root,
// which is how Kursor itself runs (see the project's SECURITY notes).
// A real MySQL install with a password-protected root account needs a
// credentials-based connection instead — not built yet, see the
// project plan's "stored-credentials fallback" note.
func OpenMySQL(socketPath string) (*sql.DB, error) {
	dsn := fmt.Sprintf("root@unix(%s)/", socketPath)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// ListMySQLDatabases excludes MySQL's own system schemas — this is a
// panel for the operator's own databases, not a MySQL internals browser.
func ListMySQLDatabases(db *sql.DB) ([]string, error) {
	rows, err := db.Query("SHOW DATABASES")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		if !mysqlSystemDBs[name] {
			out = append(out, name)
		}
	}
	return out, rows.Err()
}

// CreateMySQLDatabase validates name against the identifier whitelist
// BEFORE it's anywhere near a query string — CREATE DATABASE can't bind
// its name as a placeholder (that only works for values).
func CreateMySQLDatabase(db *sql.DB, name string) error {
	if err := ValidIdentifier(name); err != nil {
		return err
	}
	_, err := db.Exec("CREATE DATABASE " + QuoteMySQL(name) + " CHARACTER SET utf8mb4")
	return err
}

// DropMySQLDatabase drops a database — same whitelist discipline.
func DropMySQLDatabase(db *sql.DB, name string) error {
	if err := ValidIdentifier(name); err != nil {
		return err
	}
	_, err := db.Exec("DROP DATABASE " + QuoteMySQL(name))
	return err
}

// CreateMySQLUserAndGrant creates a user scoped to one database. The
// password IS a value position and goes through a real placeholder;
// username and dbname are identifiers and go through
// ValidIdentifier+quoting instead — the two are genuinely different
// SQL grammar positions, handled differently on purpose.
func CreateMySQLUserAndGrant(db *sql.DB, username, password, dbname string) error {
	if err := ValidIdentifier(username); err != nil {
		return err
	}
	if err := ValidIdentifier(dbname); err != nil {
		return err
	}
	userSpec := QuoteMySQLString(username) + "@'%'"

	if _, err := db.Exec("CREATE USER "+userSpec+" IDENTIFIED BY ?", password); err != nil {
		return fmt.Errorf("create user: %w", err)
	}
	if _, err := db.Exec("GRANT ALL PRIVILEGES ON " + QuoteMySQL(dbname) + ".* TO " + userSpec); err != nil {
		return fmt.Errorf("grant: %w", err)
	}
	if _, err := db.Exec("FLUSH PRIVILEGES"); err != nil {
		return fmt.Errorf("flush privileges: %w", err)
	}
	return nil
}

// DropMySQLUser removes a user account.
func DropMySQLUser(db *sql.DB, username string) error {
	if err := ValidIdentifier(username); err != nil {
		return err
	}
	_, err := db.Exec("DROP USER " + QuoteMySQLString(username) + "@'%'")
	return err
}
