// Package store wraps Kursor's own sqlite metadata database (users,
// sessions, sites, db_connections — see migrations/0001_init.sql). It is
// deliberately not a generic ORM: just the handful of queries the MVP
// modules need, using plain database/sql.
package store

import (
	"database/sql"
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

var migrationFilenameRe = regexp.MustCompile(`^(\d+)_.*\.sql$`)

// Store wraps the underlying sqlite connection.
type Store struct {
	db *sql.DB
}

// Open opens (creating if needed) the sqlite database under dataDir and
// applies any pending migrations.
func Open(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	dbPath := filepath.Join(dataDir, "kursor.db")

	db, err := sql.Open("sqlite", dbPath+"?_pragma=foreign_keys(1)")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// sqlite handles one writer at a time; keep this simple for the MVP.
	db.SetMaxOpenConns(1)

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) migrate() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version    INTEGER PRIMARY KEY,
		applied_at TEXT NOT NULL
	)`); err != nil {
		return err
	}

	var maxVersion int
	if err := s.db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&maxVersion); err != nil {
		return err
	}

	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	for _, e := range entries {
		m := migrationFilenameRe.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		version, _ := strconv.Atoi(m[1])
		if version <= maxVersion {
			continue
		}

		raw, err := migrationsFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			return err
		}

		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		for _, stmt := range splitStatements(string(raw)) {
			if _, err := tx.Exec(stmt); err != nil {
				tx.Rollback()
				return fmt.Errorf("migration %s: %w", e.Name(), err)
			}
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`,
			version, time.Now().UTC().Format(time.RFC3339)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// splitStatements is a small, deliberately naive splitter: our own
// migration files are plain DDL with no semicolons inside string
// literals, so splitting on ";" boundaries is enough and avoids
// depending on a full SQL parser for a handful of migrations. It does
// need to strip "--" line comments FIRST, though — a semicolon inside a
// comment (e.g. "-- ...unused; Go now composes...") would otherwise be
// mistaken for a statement boundary and split a comment sentence in
// half, leaving a fragment that starts mid-sentence and fails to parse
// as SQL.
func splitStatements(sqlText string) []string {
	lines := strings.Split(sqlText, "\n")
	for i, line := range lines {
		if idx := strings.Index(line, "--"); idx >= 0 {
			lines[i] = line[:idx]
		}
	}
	uncommented := strings.Join(lines, "\n")

	parts := strings.Split(uncommented, ";")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

// --- users ---

// User is a Kursor account. Role is "admin" or "member"; Status is
// "active" or "disabled" (a disabled account can't log in — see
// GetSession/GetUserByUsername).
type User struct {
	ID           int64
	Username     string
	PasswordHash string
	FullName     string // legacy (pre-0003) field, no longer written to
	Email        string
	Role         string
	Status       string
	CreatedAt    time.Time

	LastName     string
	FirstName    string
	Patronymic   string
	JobTitle     string
	Phone        string
	HiredAt      string // "YYYY-MM-DD", may be ""
	TerminatedAt string // "YYYY-MM-DD", may be ""
	AvatarMime   string
	HasAvatar    bool
	Permissions  string // comma-separated module keys, e.g. "sites,files" — see migration 0004

	DepartmentID   *int64
	PositionID     *int64
	DepartmentName string // "" if unset; "Parent / Child" if the department has a parent
	PositionName   string // "" if unset
}

// PermissionsList splits the stored comma-separated permissions into a
// slice, skipping empty entries.
func (u User) PermissionsList() []string {
	if u.Permissions == "" {
		return nil
	}
	parts := strings.Split(u.Permissions, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// HasModule reports whether this account can reach a given module.
// Admins always can; members need the module in their permissions list.
func (u User) HasModule(key string) bool {
	if u.Role == "admin" {
		return true
	}
	for _, p := range u.PermissionsList() {
		if p == key {
			return true
		}
	}
	return false
}

// DisplayName composes the Ukrainian ПІБ (Прізвище Ім'я По-батькові)
// order from the structured name fields, falling back to the username
// if none were entered.
func (u User) DisplayName() string {
	parts := make([]string, 0, 3)
	for _, p := range []string{u.LastName, u.FirstName, u.Patronymic} {
		if p != "" {
			parts = append(parts, p)
		}
	}
	if len(parts) == 0 {
		return u.Username
	}
	return strings.Join(parts, " ")
}

// CountUsers reports how many accounts exist (used for first-run
// bootstrap: an empty table means "generate the initial admin").
func (s *Store) CountUsers() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// CountAdmins reports how many active admin accounts exist — used to
// stop the last admin from being demoted, disabled or deleted, which
// would otherwise lock everyone out.
func (s *Store) CountAdmins() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE role = 'admin' AND status = 'active'`).Scan(&n)
	return n, err
}

// NewUser holds the fields needed to create an account (full employee
// profile — see migration 0003).
type NewUser struct {
	Username     string
	PasswordHash string
	Email        string
	Role         string // "admin" | "member"

	LastName     string
	FirstName    string
	Patronymic   string
	JobTitle     string
	Phone        string
	HiredAt      string // "YYYY-MM-DD", may be ""
	Permissions  string // comma-separated module keys
	DepartmentID *int64
	PositionID   *int64
}

// CreateUser inserts a new account.
func (s *Store) CreateUser(u NewUser) (int64, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	role := u.Role
	if role == "" {
		role = "member"
	}
	res, err := s.db.Exec(`INSERT INTO users
		(username, password_hash, email, role, status, created_at, updated_at,
		 last_name, first_name, patronymic, job_title, phone, hired_at, permissions, department_id, position_id)
		VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		u.Username, u.PasswordHash, u.Email, role, now, now,
		u.LastName, u.FirstName, u.Patronymic, u.JobTitle, u.Phone, u.HiredAt, u.Permissions,
		u.DepartmentID, u.PositionID)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// ProfileUpdate holds every editable field on an existing account
// (everything except username, which stays immutable, and password,
// which goes through ResetPassword instead).
type ProfileUpdate struct {
	LastName     string
	FirstName    string
	Patronymic   string
	JobTitle     string
	Phone        string
	Email        string
	HiredAt      string
	TerminatedAt string
	Role         string
	Permissions  string
	DepartmentID *int64
	PositionID   *int64
}

// UpdateProfile overwrites an account's editable fields.
func (s *Store) UpdateProfile(id int64, u ProfileUpdate) error {
	_, err := s.db.Exec(`UPDATE users SET
		last_name = ?, first_name = ?, patronymic = ?, job_title = ?, phone = ?, email = ?,
		hired_at = ?, terminated_at = ?, role = ?, permissions = ?, department_id = ?, position_id = ?, updated_at = ?
		WHERE id = ?`,
		u.LastName, u.FirstName, u.Patronymic, u.JobTitle, u.Phone, u.Email,
		u.HiredAt, u.TerminatedAt, u.Role, u.Permissions, u.DepartmentID, u.PositionID,
		time.Now().UTC().Format(time.RFC3339), id)
	return err
}

// SetUserPermissions overwrites only the permissions column — used by
// the Service Desk "grant access" ticket action, which should never
// touch a user's name/role/other profile fields, only add the module
// keys the approved request asked for.
func (s *Store) SetUserPermissions(id int64, permissions string) error {
	_, err := s.db.Exec(`UPDATE users SET permissions = ?, updated_at = ? WHERE id = ?`,
		permissions, time.Now().UTC().Format(time.RFC3339), id)
	return err
}

// ResetPassword overwrites an account's password hash (used to issue a
// fresh temp password from the edit page).
func (s *Store) ResetPassword(id int64, passwordHash string) error {
	_, err := s.db.Exec(`UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?`,
		passwordHash, time.Now().UTC().Format(time.RFC3339), id)
	return err
}

const userSelect = `u.id, u.username, u.password_hash, u.full_name, u.email, u.role, u.status, u.created_at,
	u.last_name, u.first_name, u.patronymic, u.job_title, u.phone, u.hired_at, u.terminated_at, u.avatar_mime,
	(u.avatar IS NOT NULL AND length(u.avatar) > 0), u.permissions, u.department_id, u.position_id,
	CASE WHEN d.id IS NULL THEN '' WHEN pd.id IS NULL THEN d.name ELSE pd.name || ' / ' || d.name END,
	COALESCE(p.name, '')`

const userFrom = `FROM users u
	LEFT JOIN departments d ON d.id = u.department_id
	LEFT JOIN departments pd ON pd.id = d.parent_id
	LEFT JOIN positions p ON p.id = u.position_id`

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	var departmentID, positionID sql.NullInt64
	var createdAt string
	var hasAvatar int
	if err := row.Scan(
		&u.ID, &u.Username, &u.PasswordHash, &u.FullName, &u.Email, &u.Role, &u.Status, &createdAt,
		&u.LastName, &u.FirstName, &u.Patronymic, &u.JobTitle, &u.Phone, &u.HiredAt, &u.TerminatedAt, &u.AvatarMime,
		&hasAvatar, &u.Permissions, &departmentID, &positionID, &u.DepartmentName, &u.PositionName,
	); err != nil {
		return nil, err
	}
	if t, err := time.Parse(time.RFC3339, createdAt); err == nil {
		u.CreatedAt = t
	}
	u.HasAvatar = hasAvatar != 0
	if departmentID.Valid {
		v := departmentID.Int64
		u.DepartmentID = &v
	}
	if positionID.Valid {
		v := positionID.Int64
		u.PositionID = &v
	}
	return &u, nil
}

// GetUserByUsername returns nil, nil if no such user exists.
func (s *Store) GetUserByUsername(username string) (*User, error) {
	row := s.db.QueryRow(`SELECT `+userSelect+` `+userFrom+` WHERE u.username = ?`, username)
	u, err := scanUser(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return u, err
}

// GetUserByID returns nil, nil if no such user exists.
func (s *Store) GetUserByID(id int64) (*User, error) {
	row := s.db.QueryRow(`SELECT `+userSelect+` `+userFrom+` WHERE u.id = ?`, id)
	u, err := scanUser(row)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return u, err
}

// ListUsers returns every account, oldest first.
func (s *Store) ListUsers() ([]User, error) {
	rows, err := s.db.Query(`SELECT ` + userSelect + ` ` + userFrom + ` ORDER BY u.created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

// UpdateUserStatus sets an account active/disabled.
func (s *Store) UpdateUserStatus(id int64, status string) error {
	_, err := s.db.Exec(`UPDATE users SET status = ?, updated_at = ? WHERE id = ?`,
		status, time.Now().UTC().Format(time.RFC3339), id)
	return err
}

// DeleteUser removes an account (its sessions cascade-delete).
func (s *Store) DeleteUser(id int64) error {
	_, err := s.db.Exec(`DELETE FROM users WHERE id = ?`, id)
	return err
}

// Terminate records an employee's last day and disables their login in
// one step (a distinct action from UpdateUserStatus's plain
// enable/disable, which doesn't touch terminated_at).
func (s *Store) Terminate(id int64, terminatedAt string) error {
	_, err := s.db.Exec(`UPDATE users SET terminated_at = ?, status = 'disabled', updated_at = ? WHERE id = ?`,
		terminatedAt, time.Now().UTC().Format(time.RFC3339), id)
	return err
}

// UpdateAvatar stores a profile photo's raw bytes and MIME type.
func (s *Store) UpdateAvatar(id int64, data []byte, mime string) error {
	_, err := s.db.Exec(`UPDATE users SET avatar = ?, avatar_mime = ?, updated_at = ? WHERE id = ?`,
		data, mime, time.Now().UTC().Format(time.RFC3339), id)
	return err
}

// GetAvatar returns nil, "", nil if the account has no photo set.
func (s *Store) GetAvatar(id int64) ([]byte, string, error) {
	var data []byte
	var mime string
	err := s.db.QueryRow(`SELECT avatar, avatar_mime FROM users WHERE id = ?`, id).Scan(&data, &mime)
	if err == sql.ErrNoRows {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	return data, mime, nil
}

// --- sessions ---

// Session is a server-side session backing the auth cookie.
type Session struct {
	Token       string
	UserID      int64
	Username    string
	Role        string
	Permissions string
	ExpiresAt   time.Time
}

// HasModule mirrors User.HasModule for the (lighter) session record —
// admins always pass, members need the module in their permissions.
func (sess Session) HasModule(key string) bool {
	if sess.Role == "admin" {
		return true
	}
	for _, p := range strings.Split(sess.Permissions, ",") {
		if p == key {
			return true
		}
	}
	return false
}

// CreateSession inserts a new session row.
func (s *Store) CreateSession(token string, userID int64, ttl time.Duration, userAgent, ip string) error {
	now := time.Now().UTC()
	_, err := s.db.Exec(`INSERT INTO sessions (token, user_id, created_at, expires_at, last_seen_at, user_agent, ip)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		token, userID, now.Format(time.RFC3339), now.Add(ttl).Format(time.RFC3339), now.Format(time.RFC3339), userAgent, ip)
	return err
}

// GetSession looks up a session by token, joined with the owning user.
// Returns nil, nil if the token is unknown, expired, or the account has
// since been disabled.
func (s *Store) GetSession(token string) (*Session, error) {
	var sess Session
	var expiresAt, status string
	err := s.db.QueryRow(`SELECT sessions.token, sessions.user_id, users.username, users.role, users.permissions, users.status, sessions.expires_at
		FROM sessions JOIN users ON users.id = sessions.user_id
		WHERE sessions.token = ?`, token).
		Scan(&sess.Token, &sess.UserID, &sess.Username, &sess.Role, &sess.Permissions, &status, &expiresAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if status != "active" {
		return nil, nil
	}
	exp, err := time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return nil, err
	}
	sess.ExpiresAt = exp
	if time.Now().UTC().After(exp) {
		return nil, nil
	}
	return &sess, nil
}

// DeleteSession removes a session (logout).
func (s *Store) DeleteSession(token string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE token = ?`, token)
	return err
}
