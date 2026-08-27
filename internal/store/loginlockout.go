package store

import (
	"database/sql"
	"time"
)

// Login brute-force protection, keyed by username (see the migration's
// comment on login_lockouts for why username rather than IP). 5 wrong
// passwords in a 15-minute window locks that account out for another
// 15 minutes — generous enough that a real user who mistypes their
// password a couple of times never notices, tight enough to make
// password-guessing impractical.
const (
	loginLockoutThreshold = 5
	loginLockoutWindow    = 15 * time.Minute
	loginLockoutDuration  = 15 * time.Minute
)

// nextLoginLockoutState is the pure decision behind RecordFailedLogin,
// split out so the actual threshold/window logic is unit-testable
// without a database: given the existing streak and "now", decide the
// new fail count and whether this failure just triggered a lockout
// (lockedUntil is the zero time if not).
func nextLoginLockoutState(failCount int, lastFailAt, now time.Time) (newFailCount int, lockedUntil time.Time) {
	if !lastFailAt.IsZero() && now.Sub(lastFailAt) > loginLockoutWindow {
		failCount = 0 // previous streak is stale — start counting fresh
	}
	failCount++
	if failCount >= loginLockoutThreshold {
		return failCount, now.Add(loginLockoutDuration)
	}
	return failCount, time.Time{}
}

// IsLoginLockedOut reports whether username is currently locked out,
// and until when. A lockout whose time has already passed reports
// false — the next successful login (ClearLoginLockout) or failure
// (RecordFailedLogin, which re-evaluates the stale window) is what
// actually clears the row; this just doesn't treat an expired lock as
// still active.
func (s *Store) IsLoginLockedOut(username string) (bool, time.Time, error) {
	var lockedUntilStr string
	err := s.db.QueryRow(`SELECT locked_until FROM login_lockouts WHERE username = ?`, username).Scan(&lockedUntilStr)
	if err == sql.ErrNoRows || lockedUntilStr == "" {
		return false, time.Time{}, nil
	}
	if err != nil {
		return false, time.Time{}, err
	}
	until, err := time.Parse(time.RFC3339, lockedUntilStr)
	if err != nil {
		return false, time.Time{}, nil
	}
	if time.Now().UTC().After(until) {
		return false, time.Time{}, nil
	}
	return true, until, nil
}

// RecordFailedLogin bumps username's failure streak, locking it out
// once the threshold is hit within the window.
func (s *Store) RecordFailedLogin(username string) error {
	now := time.Now().UTC()

	var failCount int
	var lastFailAtStr string
	_ = s.db.QueryRow(`SELECT fail_count, last_fail_at FROM login_lockouts WHERE username = ?`, username).Scan(&failCount, &lastFailAtStr)
	var lastFailAt time.Time
	if lastFailAtStr != "" {
		lastFailAt, _ = time.Parse(time.RFC3339, lastFailAtStr)
	}

	newCount, lockedUntil := nextLoginLockoutState(failCount, lastFailAt, now)
	lockedUntilStr := ""
	if !lockedUntil.IsZero() {
		lockedUntilStr = lockedUntil.Format(time.RFC3339)
	}

	if _, err := s.db.Exec(`DELETE FROM login_lockouts WHERE username = ?`, username); err != nil {
		return err
	}
	_, err := s.db.Exec(`INSERT INTO login_lockouts (username, fail_count, last_fail_at, locked_until) VALUES (?, ?, ?, ?)`,
		username, newCount, now.Format(time.RFC3339), lockedUntilStr)
	return err
}

// ClearLoginLockout resets username's streak — called on every
// successful login.
func (s *Store) ClearLoginLockout(username string) error {
	_, err := s.db.Exec(`DELETE FROM login_lockouts WHERE username = ?`, username)
	return err
}
