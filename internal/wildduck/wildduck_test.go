package wildduck

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAPITokenMissingFile(t *testing.T) {
	dir := t.TempDir()
	_, err := LoadAPIToken(dir)
	if err != ErrNotConfigured {
		t.Fatalf("expected ErrNotConfigured for a missing token file, got %v", err)
	}
}

func TestLoadAPITokenEmptyFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, tokenFileName), []byte("   \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadAPIToken(dir)
	if err != ErrNotConfigured {
		t.Fatalf("expected ErrNotConfigured for a blank token file, got %v", err)
	}
}

func TestLoadAPITokenTrimsWhitespace(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, tokenFileName), []byte("  abc123  \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	token, err := LoadAPIToken(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "abc123" {
		t.Fatalf("expected trimmed token %q, got %q", "abc123", token)
	}
}
