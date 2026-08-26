// Package files is Kursor's real file manager backend: every operation
// is scoped under a configured root (config.WWWRoot) via SafeJoin, the
// single chokepoint every handler in internal/server/files.go must go
// through — see the project plan's "highest-leverage security
// primitive" note.
package files

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ErrPathEscape means the requested path resolved outside root — either
// a "../" traversal or a symlink planted inside root pointing out of it.
var ErrPathEscape = errors.New("path escapes the managed root")

// SafeJoin resolves userPath against root and guarantees the result
// stays inside root, following these rules:
//  1. Reject null bytes outright (they'd otherwise surface as a
//     confusing raw syscall error).
//  2. Root-anchor the path BEFORE joining ("/" + userPath, then Clean)
//     so a leading "../" chain can't walk above root — Clean alone
//     doesn't prevent that if the path isn't anchored first.
//  3. Resolve symlinks on both root and the result and require the
//     resolved result to still be under the resolved root — a symlink
//     planted inside the scoped tree could otherwise point anywhere.
func SafeJoin(root, userPath string) (string, error) {
	if strings.ContainsRune(userPath, 0) {
		return "", errors.New("invalid path")
	}

	cleaned := filepath.Clean(string(filepath.Separator) + userPath)
	full := filepath.Join(root, cleaned)

	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}

	resolvedFull, err := filepath.EvalSymlinks(full)
	if err != nil {
		// Doesn't exist yet (e.g. a new file about to be created) — walk
		// up to the nearest existing ancestor and resolve that instead,
		// so a symlink further up the chain still can't smuggle us out.
		dir := filepath.Dir(full)
		resolvedDir, dirErr := resolveNearestExisting(dir)
		if dirErr != nil {
			return "", dirErr
		}
		resolvedFull = filepath.Join(resolvedDir, filepath.Base(full))
	}

	if resolvedFull != resolvedRoot && !strings.HasPrefix(resolvedFull, resolvedRoot+string(filepath.Separator)) {
		return "", ErrPathEscape
	}
	return full, nil
}

// resolveNearestExisting walks up from dir until it finds a path that
// exists, resolves symlinks on it, then re-appends the part that didn't
// exist yet.
func resolveNearestExisting(dir string) (string, error) {
	if dir == string(filepath.Separator) || dir == "." {
		return filepath.EvalSymlinks(dir)
	}
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		return resolved, nil
	}
	parentResolved, err := resolveNearestExisting(filepath.Dir(dir))
	if err != nil {
		return "", err
	}
	return filepath.Join(parentResolved, filepath.Base(dir)), nil
}

// Entry is one row in a directory listing.
type Entry struct {
	Name    string
	IsDir   bool
	Size    int64
	ModTime time.Time
	Mode    string      // symbolic, e.g. "-rw-r--r--" — for display
	Perm    os.FileMode // permission bits only, e.g. 0644 — for chmod
}

// List returns the contents of relPath under root, directories first,
// then alphabetical.
func List(root, relPath string) ([]Entry, error) {
	dir, err := SafeJoin(root, relPath)
	if err != nil {
		return nil, err
	}
	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	out := make([]Entry, 0, len(dirEntries))
	for _, e := range dirEntries {
		info, err := e.Info()
		if err != nil {
			continue // vanished between ReadDir and Info — skip it
		}
		out = append(out, Entry{
			Name:    e.Name(),
			IsDir:   e.IsDir(),
			Size:    info.Size(),
			ModTime: info.ModTime(),
			Mode:    info.Mode().String(),
			Perm:    info.Mode().Perm(),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IsDir != out[j].IsDir {
			return out[i].IsDir
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out, nil
}

// ReadFile reads a file's full contents.
func ReadFile(root, relPath string) ([]byte, error) {
	p, err := SafeJoin(root, relPath)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(p)
}

// WriteFile writes (creating or overwriting) a file's contents, creating
// any missing parent directories — those are already confirmed to
// resolve inside root by SafeJoin, so MkdirAll-ing them is safe.
func WriteFile(root, relPath string, content []byte) error {
	p, err := SafeJoin(root, relPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, content, 0o644)
}

// Mkdir creates a directory (and any missing parents) under root.
func Mkdir(root, relPath string) error {
	p, err := SafeJoin(root, relPath)
	if err != nil {
		return err
	}
	return os.MkdirAll(p, 0o755)
}

// Rename moves/renames a file or directory, both endpoints scoped to root.
func Rename(root, oldRel, newRel string) error {
	oldP, err := SafeJoin(root, oldRel)
	if err != nil {
		return err
	}
	newP, err := SafeJoin(root, newRel)
	if err != nil {
		return err
	}
	return os.Rename(oldP, newP)
}

// Delete removes a file, or a directory and everything under it. Refuses
// to delete root itself.
func Delete(root, relPath string) error {
	p, err := SafeJoin(root, relPath)
	if err != nil {
		return err
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(p); err == nil && resolved == resolvedRoot {
		return errors.New("refusing to delete the managed root itself")
	}
	return os.RemoveAll(p)
}

// Chmod changes a file or directory's permission bits.
func Chmod(root, relPath string, mode os.FileMode) error {
	p, err := SafeJoin(root, relPath)
	if err != nil {
		return err
	}
	return os.Chmod(p, mode)
}

// Copy duplicates a file, or a directory and everything under it,
// scoped to root at both ends. Refuses to copy a directory into itself
// or one of its own descendants (which would otherwise recurse forever
// and fill the disk).
func Copy(root, srcRel, dstRel string) error {
	srcAbs, err := SafeJoin(root, srcRel)
	if err != nil {
		return err
	}
	dstAbs, err := SafeJoin(root, dstRel)
	if err != nil {
		return err
	}
	if dstAbs == srcAbs || strings.HasPrefix(dstAbs, srcAbs+string(filepath.Separator)) {
		return errors.New("cannot copy a folder into itself")
	}

	info, err := os.Stat(srcAbs)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return copyDir(srcAbs, dstAbs)
	}
	return copyFile(srcAbs, dstAbs, info.Mode())
}

func copyFile(src, dst string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

func copyDir(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dst, info.Mode()); err != nil {
		return err
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, e := range entries {
		s := filepath.Join(src, e.Name())
		d := filepath.Join(dst, e.Name())
		if e.IsDir() {
			if err := copyDir(s, d); err != nil {
				return err
			}
			continue
		}
		fi, err := e.Info()
		if err != nil {
			return err
		}
		if err := copyFile(s, d, fi.Mode()); err != nil {
			return err
		}
	}
	return nil
}

// SaveUploaded streams src into relPath under root without buffering the
// whole file in memory — the caller is expected to have already capped
// src's size (e.g. via http.MaxBytesReader).
func SaveUploaded(root, relPath string, src io.Reader) error {
	p, err := SafeJoin(root, relPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	dst, err := os.Create(p)
	if err != nil {
		return err
	}
	defer dst.Close()
	_, err = io.Copy(dst, src)
	return err
}

// LooksLikeText is a simple heuristic (no null byte in the first 8KB) —
// good enough to decide whether the file manager's plain textarea editor
// should offer to open something, without pulling in a MIME-sniffing
// dependency.
func LooksLikeText(sample []byte) bool {
	n := len(sample)
	if n > 8192 {
		n = 8192
	}
	for i := 0; i < n; i++ {
		if sample[i] == 0 {
			return false
		}
	}
	return true
}

// Stat returns the resolved absolute path and os.FileInfo for relPath.
func Stat(root, relPath string) (string, os.FileInfo, error) {
	p, err := SafeJoin(root, relPath)
	if err != nil {
		return "", nil, err
	}
	info, err := os.Stat(p)
	return p, info, err
}
