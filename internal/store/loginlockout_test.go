package store

import (
	"testing"
	"time"
)

func TestNextLoginLockoutStateBelowThreshold(t *testing.T) {
	now := time.Now()
	count, locked := nextLoginLockoutState(2, now.Add(-time.Minute), now)
	if count != 3 {
		t.Fatalf("expected count 3, got %d", count)
	}
	if !locked.IsZero() {
		t.Fatalf("expected no lockout below threshold, got %v", locked)
	}
}

func TestNextLoginLockoutStateHitsThreshold(t *testing.T) {
	now := time.Now()
	count, locked := nextLoginLockoutState(loginLockoutThreshold-1, now.Add(-time.Minute), now)
	if count != loginLockoutThreshold {
		t.Fatalf("expected count %d, got %d", loginLockoutThreshold, count)
	}
	if locked.IsZero() {
		t.Fatal("expected a lockout once the threshold is hit")
	}
	if !locked.After(now) {
		t.Fatalf("expected lockedUntil to be in the future, got %v (now=%v)", locked, now)
	}
}

func TestNextLoginLockoutStateStaleWindowResets(t *testing.T) {
	now := time.Now()
	// A failure right at the threshold, but the last attempt was long
	// ago (outside the window) — should reset to a fresh streak of 1,
	// not lock out on an old, stale count.
	count, locked := nextLoginLockoutState(loginLockoutThreshold-1, now.Add(-2*loginLockoutWindow), now)
	if count != 1 {
		t.Fatalf("expected the stale streak to reset to 1, got %d", count)
	}
	if !locked.IsZero() {
		t.Fatal("a reset streak of 1 must not trigger a lockout")
	}
}

func TestNextLoginLockoutStateFirstEverFailure(t *testing.T) {
	now := time.Now()
	count, locked := nextLoginLockoutState(0, time.Time{}, now)
	if count != 1 {
		t.Fatalf("expected count 1 for a first-ever failure, got %d", count)
	}
	if !locked.IsZero() {
		t.Fatal("a single failure must not trigger a lockout")
	}
}
