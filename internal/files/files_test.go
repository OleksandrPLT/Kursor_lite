package files

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSafeJoin_NormalPath(t *testing.T) {
	root := t.TempDir()
	got, err := SafeJoin(root, "sub/dir/file.txt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := filepath.Join(root, "sub", "dir", "file.txt")
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// Root-anchoring (Clean("/" + userPath)) neutralizes a "../" chain into
// a safe in-root path rather than erroring — same mechanism as the
// absolute-path case below. The property under test is that the result
// can NEVER land outside root, not that traversal syntax is rejected
// outright.
func TestSafeJoin_TraversalNeutralizedNotEscaped(t *testing.T) {
	root := t.TempDir()
	// SafeJoin returns paths built from the ORIGINAL root argument (not
	// its symlink-resolved form — e.g. macOS's /var -> /private/var), so
	// that's what a returned path's prefix should be checked against;
	// the resolved form is only used internally for the escape check.
	cleanRoot := filepath.Clean(root)
	cases := []string{
		"../../../etc/passwd",
		"../../etc/passwd",
		"a/../../b",
		"..",
		"a/b/../../../../etc/passwd",
	}
	for _, c := range cases {
		got, err := SafeJoin(root, c)
		if err != nil {
			t.Errorf("SafeJoin(%q): unexpected error: %v", c, err)
			continue
		}
		if got != cleanRoot && !strings.HasPrefix(got, cleanRoot+string(filepath.Separator)) {
			t.Errorf("SafeJoin(%q) = %q: escaped root %q", c, got, cleanRoot)
		}
	}
}

func TestSafeJoin_AbsolutePathIsRootAnchoredNotReal(t *testing.T) {
	root := t.TempDir()
	got, err := SafeJoin(root, "/etc/passwd")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := filepath.Join(root, "etc", "passwd")
	if got != want {
		t.Errorf("absolute-looking path should be treated as root-relative: got %q, want %q", got, want)
	}
	if got == "/etc/passwd" {
		t.Fatal("must never resolve to the real /etc/passwd")
	}
}

func TestSafeJoin_NullByteRejected(t *testing.T) {
	root := t.TempDir()
	if _, err := SafeJoin(root, "file\x00.txt"); err == nil {
		t.Error("expected error for null byte in path")
	}
}

func TestSafeJoin_SymlinkEscapeRejected(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}

	// A symlink planted INSIDE root pointing OUTSIDE it.
	link := filepath.Join(root, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}

	if _, err := SafeJoin(root, "escape/secret.txt"); err == nil {
		t.Error("expected SafeJoin to reject a path through a symlink that escapes root")
	}
}

func TestSafeJoin_NewFileNotYetExisting(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "existing"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := SafeJoin(root, "existing/new-file.txt")
	if err != nil {
		t.Fatalf("unexpected error for a not-yet-existing file: %v", err)
	}
	want := filepath.Join(root, "existing", "new-file.txt")
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestSafeJoin_NewFileViaTraversalNeutralized(t *testing.T) {
	root := t.TempDir()
	cleanRoot := filepath.Clean(root)
	got, err := SafeJoin(root, "../new-file-outside.txt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != cleanRoot && !strings.HasPrefix(got, cleanRoot+string(filepath.Separator)) {
		t.Errorf("escaped root: %q", got)
	}
}

func TestDelete_RefusesRootItself(t *testing.T) {
	root := t.TempDir()
	if err := Delete(root, "/"); err == nil {
		t.Error("expected Delete to refuse removing the managed root itself")
	}
	if _, err := os.Stat(root); err != nil {
		t.Errorf("root should still exist after refused delete: %v", err)
	}
}

func TestWriteReadRoundTrip(t *testing.T) {
	root := t.TempDir()
	if err := WriteFile(root, "notes/todo.txt", []byte("hello")); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := ReadFile(root, "notes/todo.txt")
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("got %q, want %q", got, "hello")
	}
}

func TestCopy_File(t *testing.T) {
	root := t.TempDir()
	if err := WriteFile(root, "a.txt", []byte("content")); err != nil {
		t.Fatal(err)
	}
	if err := Copy(root, "a.txt", "b.txt"); err != nil {
		t.Fatalf("Copy: %v", err)
	}
	got, err := ReadFile(root, "b.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "content" {
		t.Errorf("got %q, want %q", got, "content")
	}
	// original must be untouched
	if orig, _ := ReadFile(root, "a.txt"); string(orig) != "content" {
		t.Errorf("source file was modified by Copy")
	}
}

func TestCopy_DirectoryRecursive(t *testing.T) {
	root := t.TempDir()
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(WriteFile(root, "src/a.txt", []byte("A")))
	must(WriteFile(root, "src/nested/b.txt", []byte("B")))

	if err := Copy(root, "src", "dst"); err != nil {
		t.Fatalf("Copy: %v", err)
	}
	a, err := ReadFile(root, "dst/a.txt")
	if err != nil || string(a) != "A" {
		t.Errorf("dst/a.txt: got %q, err %v", a, err)
	}
	b, err := ReadFile(root, "dst/nested/b.txt")
	if err != nil || string(b) != "B" {
		t.Errorf("dst/nested/b.txt: got %q, err %v", b, err)
	}
}

func TestCopy_RefusesIntoSelf(t *testing.T) {
	root := t.TempDir()
	if err := WriteFile(root, "src/a.txt", []byte("A")); err != nil {
		t.Fatal(err)
	}
	if err := Copy(root, "src", "src/nested-into-self"); err == nil {
		t.Error("expected error copying a directory into its own descendant")
	}
	if err := Copy(root, "src", "src"); err == nil {
		t.Error("expected error copying a directory into itself")
	}
}

func TestChmod_ChangesPermissions(t *testing.T) {
	root := t.TempDir()
	if err := WriteFile(root, "a.txt", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := Chmod(root, "a.txt", 0o600); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	abs, info, err := Stat(root, "a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("%s: got mode %v, want 0600", abs, info.Mode().Perm())
	}
}

func TestList_DirsFirstThenAlpha(t *testing.T) {
	root := t.TempDir()
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.WriteFile(filepath.Join(root, "b.txt"), []byte("x"), 0o644))
	must(os.WriteFile(filepath.Join(root, "a.txt"), []byte("x"), 0o644))
	must(os.MkdirAll(filepath.Join(root, "zzz-dir"), 0o755))

	entries, err := List(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	if !entries[0].IsDir || entries[0].Name != "zzz-dir" {
		t.Errorf("expected directory first, got %+v", entries[0])
	}
	if entries[1].Name != "a.txt" || entries[2].Name != "b.txt" {
		t.Errorf("expected alphabetical files after dir, got %q, %q", entries[1].Name, entries[2].Name)
	}
}
