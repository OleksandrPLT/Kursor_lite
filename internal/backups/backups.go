// Package backups creates and manages tar.gz archives of a site's
// docroot (or the whole wwwroot) — real archive/tar + compress/gzip
// from the standard library, no external `tar` binary required, so it
// works identically on Linux and macOS.
package backups

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	kfiles "kursor/internal/files"
)

var labelRe = regexp.MustCompile(`[^a-zA-Z0-9_-]+`)

func sanitizeLabel(label string) string {
	label = labelRe.ReplaceAllString(label, "-")
	label = strings.Trim(label, "-")
	if label == "" {
		return "backup"
	}
	if len(label) > 40 {
		label = label[:40]
	}
	return label
}

// Create archives sourceDir into backupsDir as a timestamped .tar.gz and
// returns its filename.
func Create(backupsDir, sourceDir, label string) (string, error) {
	if err := os.MkdirAll(backupsDir, 0o755); err != nil {
		return "", err
	}
	name := fmt.Sprintf("%s-%s.tar.gz", sanitizeLabel(label), time.Now().Format("20060102-150405"))
	destPath := filepath.Join(backupsDir, name)

	if err := archiveDir(sourceDir, destPath); err != nil {
		os.Remove(destPath) // don't leave a partial/corrupt archive behind
		return "", err
	}
	return name, nil
}

func archiveDir(sourceDir, destPath string) error {
	out, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer out.Close()

	gz := gzip.NewWriter(out)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	return filepath.Walk(sourceDir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(sourceDir, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if info.IsDir() {
			hdr.Name += "/"
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(tw, f)
		return err
	})
}

// Info is one row in the backups list.
type Info struct {
	Name      string
	SizeBytes int64
	ModTime   time.Time
}

// List returns every backup in backupsDir, newest first.
func List(backupsDir string) ([]Info, error) {
	entries, err := os.ReadDir(backupsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []Info
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".tar.gz") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, Info{Name: e.Name(), SizeBytes: info.Size(), ModTime: info.ModTime()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ModTime.After(out[j].ModTime) })
	return out, nil
}

// Path resolves a backup's filename to an absolute path, scoped to
// backupsDir via the same SafeJoin traversal protection the file
// manager uses — backupsDir is just another managed root.
func Path(backupsDir, name string) (string, error) {
	return kfiles.SafeJoin(backupsDir, name)
}

// Delete removes a backup archive.
func Delete(backupsDir, name string) error {
	return kfiles.Delete(backupsDir, name)
}
