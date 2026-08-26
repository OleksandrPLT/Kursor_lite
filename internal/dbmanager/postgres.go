package dbmanager

import (
	"database/sql"
	"fmt"
	"path/filepath"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// OpenPostgres connects via the local unix socket, directory-form (pgx
// accepts the socket's containing directory as the "host"). On
// Debian/Ubuntu, `peer` auth over that socket maps to the connecting OS
// user, not necessarily the `postgres` role — this genuinely may fail
// unless Kursor's OS user has a matching Postgres role, exactly the
// caveat the project plan flagged. A stored-credentials fallback isn't
// built yet.
func OpenPostgres(socketPath string) (*sql.DB, error) {
	dir := filepath.Dir(socketPath)
	dsn := fmt.Sprintf("host=%s user=postgres dbname=postgres sslmode=disable", dir)
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// ListPostgresDatabases excludes Postgres's own template/system databases.
func ListPostgresDatabases(db *sql.DB) ([]string, error) {
	rows, err := db.Query(`SELECT datname FROM pg_database WHERE datistemplate = false AND datname NOT IN ('postgres')`)
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
		out = append(out, name)
	}
	return out, rows.Err()
}

// CreatePostgresDatabase — Postgres DDL can't bind identifiers as
// placeholders either, so the same whitelist-then-quote discipline
// applies here as in mysql.go.
func CreatePostgresDatabase(db *sql.DB, name string) error {
	if err := ValidIdentifier(name); err != nil {
		return err
	}
	_, err := db.Exec("CREATE DATABASE " + QuotePostgres(name))
	return err
}

// DropPostgresDatabase drops a database.
func DropPostgresDatabase(db *sql.DB, name string) error {
	if err := ValidIdentifier(name); err != nil {
		return err
	}
	_, err := db.Exec("DROP DATABASE " + QuotePostgres(name))
	return err
}

// CreatePostgresUserAndGrant creates a login role and grants it every
// privilege on one database. The password is a genuine placeholder
// value; the role/database names go through ValidIdentifier+quoting.
func CreatePostgresUserAndGrant(db *sql.DB, username, password, dbname string) error {
	if err := ValidIdentifier(username); err != nil {
		return err
	}
	if err := ValidIdentifier(dbname); err != nil {
		return err
	}
	roleSpec := QuotePostgres(username)

	if _, err := db.Exec("CREATE ROLE "+roleSpec+" WITH LOGIN PASSWORD $1", password); err != nil {
		return fmt.Errorf("create role: %w", err)
	}
	if _, err := db.Exec("GRANT ALL PRIVILEGES ON DATABASE " + QuotePostgres(dbname) + " TO " + roleSpec); err != nil {
		return fmt.Errorf("grant: %w", err)
	}
	return nil
}

// DropPostgresUser removes a role.
func DropPostgresUser(db *sql.DB, username string) error {
	if err := ValidIdentifier(username); err != nil {
		return err
	}
	_, err := db.Exec("DROP ROLE " + QuotePostgres(username))
	return err
}
