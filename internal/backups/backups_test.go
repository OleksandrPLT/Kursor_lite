package backups

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestCreate_ArchiveContainsRealFiles(t *testing.T) {
	src := t.TempDir()
	backupsDir := t.TempDir()

	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.WriteFile(filepath.Join(src, "index.html"), []byte("<h1>hi</h1>"), 0o644))
	must(os.MkdirAll(filepath.Join(src, "assets"), 0o755))
	must(os.WriteFile(filepath.Join(src, "assets", "style.css"), []byte("body{}"), 0o644))

	name, err := Create(backupsDir, src, "mysite")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Read the archive back with the standard library — proves it's a
	// real, valid tar.gz, not just an arbitrary blob.
	f, err := os.Open(filepath.Join(backupsDir, name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("not a valid gzip stream: %v", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	found := map[string]string{}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if hdr.Typeflag == tar.TypeReg {
			data, err := io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			found[hdr.Name] = string(data)
		}
	}

	if found["index.html"] != "<h1>hi</h1>" {
		t.Errorf("index.html: got %q", found["index.html"])
	}
	if found["assets/style.css"] != "body{}" {
		t.Errorf("assets/style.css: got %q", found["assets/style.css"])
	}
}

func TestList_NewestFirst(t *testing.T) {
	backupsDir := t.TempDir()
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}

	first, err := Create(backupsDir, src, "first")
	if err != nil {
		t.Fatal(err)
	}
	second, err := Create(backupsDir, src, "second")
	if err != nil {
		t.Fatal(err)
	}

	list, err := List(backupsDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 backups, got %d", len(list))
	}
	names := map[string]bool{list[0].Name: true, list[1].Name: true}
	if !names[first] || !names[second] {
		t.Errorf("expected both %q and %q in listing, got %v", first, second, list)
	}
}

// Delete goes through kfiles.SafeJoin, which NEUTRALIZES a "../" chain
// into a safe in-root path rather than erroring (see
// internal/files/files_test.go) — so this attempt harmlessly no-ops
// (removing a nonexistent path inside backupsDir) rather than touching
// the real /etc/passwd. That's the property under test.
func TestDelete_TraversalNeverTouchesRealFile(t *testing.T) {
	backupsDir := t.TempDir()
	before, err := os.ReadFile("/etc/passwd")
	if err != nil {
		t.Skip("can't read /etc/passwd on this system to compare")
	}
	_ = Delete(backupsDir, "../../etc/passwd")
	after, err := os.ReadFile("/etc/passwd")
	if err != nil || string(before) != string(after) {
		t.Error("the real /etc/passwd was touched — traversal escaped backupsDir")
	}
}
