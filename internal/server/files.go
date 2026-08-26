package server

import (
	"fmt"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"

	"kursor/internal/auth"
	kfiles "kursor/internal/files"
)

const (
	maxUploadBytes = 50 << 20  // 50MB
	maxEditBytes   = 512 << 10 // 512KB — above this, edit in place is refused; download instead
)

// Breadcrumb is one clickable segment of the current path.
type Breadcrumb struct {
	Name string
	Path string
}

// FileRow is one directory-listing row, pre-formatted for the template.
type FileRow struct {
	Name      string
	IsDir     bool
	Path      string // relative path, for links
	SizeText  string
	Modified  string
	Mode      string
	OctalMode string
}

// FilesData backs the file manager page.
type FilesData struct {
	PageData
	CurrentPath string
	Breadcrumbs []Breadcrumb
	Rows        []FileRow
	ErrorKey    string

	// set only when viewing/editing one file
	Editing      bool
	EditPath     string
	EditContent  string
	EditTooLarge bool
	EditNotText  bool
}

func breadcrumbs(relPath string) []Breadcrumb {
	relPath = strings.Trim(path.Clean("/"+relPath), "/")
	if relPath == "" || relPath == "." {
		return nil
	}
	parts := strings.Split(relPath, "/")
	out := make([]Breadcrumb, 0, len(parts))
	acc := ""
	for _, p := range parts {
		if acc == "" {
			acc = p
		} else {
			acc = acc + "/" + p
		}
		out = append(out, Breadcrumb{Name: p, Path: acc})
	}
	return out
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return strconv.FormatInt(n, 10) + " B"
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	units := "KMGT"[exp]
	return strconv.FormatFloat(float64(n)/float64(div), 'f', 1, 64) + " " + string(units) + "B"
}

func (s *Server) handleFilesPage(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	relPath := r.URL.Query().Get("path")

	entries, err := kfiles.List(s.cfg.WWWRoot, relPath)
	data := FilesData{
		PageData:    s.basePageData(w, r, "files", sess),
		CurrentPath: strings.Trim(path.Clean("/"+relPath), "/"),
	}
	if data.CurrentPath == "." {
		data.CurrentPath = ""
	}
	data.Breadcrumbs = breadcrumbs(relPath)

	if err != nil {
		data.ErrorKey = "files.error.list"
		s.render(w, "files", data)
		return
	}
	if qErr := r.URL.Query().Get("error"); qErr != "" {
		data.ErrorKey = qErr
	}

	for _, e := range entries {
		rel := e.Name
		if data.CurrentPath != "" {
			rel = data.CurrentPath + "/" + e.Name
		}
		row := FileRow{
			Name:      e.Name,
			IsDir:     e.IsDir,
			Path:      rel,
			Modified:  e.ModTime.Format("Jan 2, 2006"),
			Mode:      e.Mode,
			OctalMode: fmt.Sprintf("%03o", e.Perm),
		}
		if !e.IsDir {
			row.SizeText = humanSize(e.Size)
		}
		data.Rows = append(data.Rows, row)
	}

	s.render(w, "files", data)
}

func (s *Server) handleFileDownload(w http.ResponseWriter, r *http.Request) {
	relPath := r.URL.Query().Get("path")
	abs, info, err := kfiles.Stat(s.cfg.WWWRoot, relPath)
	if err != nil || info == nil || info.IsDir() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="`+path.Base(abs)+`"`)
	http.ServeFile(w, r, abs)
}

func (s *Server) handleFileUpload(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)

	targetDir := r.URL.Query().Get("path")
	if err := r.ParseMultipartForm(maxUploadBytes); err != nil {
		s.redirectToFiles(w, r, targetDir, "files.error.too_large")
		return
	}
	if !auth.ValidCSRF(r) {
		s.redirectToFiles(w, r, targetDir, "login.error.csrf")
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		s.redirectToFiles(w, r, targetDir, "files.error.upload")
		return
	}
	defer file.Close()

	rel := header.Filename
	if targetDir != "" {
		rel = targetDir + "/" + header.Filename
	}
	if err := kfiles.SaveUploaded(s.cfg.WWWRoot, rel, file); err != nil {
		s.redirectToFiles(w, r, targetDir, "files.error.upload")
		return
	}
	s.redirectToFiles(w, r, targetDir, "")
}

func (s *Server) handleFileCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		s.redirectToFiles(w, r, r.FormValue("path"), "login.error.csrf")
		return
	}
	dir := r.FormValue("path")
	name := r.FormValue("name")
	kind := r.FormValue("kind")
	if name == "" || strings.ContainsAny(name, "/\\") {
		s.redirectToFiles(w, r, dir, "files.error.bad_name")
		return
	}
	rel := name
	if dir != "" {
		rel = dir + "/" + name
	}

	var err error
	if kind == "dir" {
		err = kfiles.Mkdir(s.cfg.WWWRoot, rel)
	} else {
		err = kfiles.WriteFile(s.cfg.WWWRoot, rel, []byte{})
	}
	if err != nil {
		s.redirectToFiles(w, r, dir, "files.error.create")
		return
	}
	s.redirectToFiles(w, r, dir, "")
}

func (s *Server) handleFileRename(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		s.redirectToFiles(w, r, "", "login.error.csrf")
		return
	}
	oldRel := r.FormValue("path")
	newName := r.FormValue("new_name")
	dir := path.Dir(oldRel)
	if dir == "." {
		dir = ""
	}
	if newName == "" || strings.ContainsAny(newName, "/\\") {
		s.redirectToFiles(w, r, dir, "files.error.bad_name")
		return
	}
	newRel := newName
	if dir != "" {
		newRel = dir + "/" + newName
	}
	if err := kfiles.Rename(s.cfg.WWWRoot, oldRel, newRel); err != nil {
		s.redirectToFiles(w, r, dir, "files.error.rename")
		return
	}
	s.redirectToFiles(w, r, dir, "")
}

func (s *Server) handleFileMove(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		s.redirectToFiles(w, r, "", "login.error.csrf")
		return
	}
	srcRel := r.FormValue("path")
	destDir := strings.Trim(r.FormValue("dest_dir"), "/")
	srcDir := path.Dir(srcRel)
	if srcDir == "." {
		srcDir = ""
	}

	name := path.Base(srcRel)
	newRel := name
	if destDir != "" {
		newRel = destDir + "/" + name
	}
	if err := kfiles.Rename(s.cfg.WWWRoot, srcRel, newRel); err != nil {
		s.redirectToFiles(w, r, srcDir, "files.error.move")
		return
	}
	s.redirectToFiles(w, r, destDir, "")
}

func (s *Server) handleFileCopy(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		s.redirectToFiles(w, r, "", "login.error.csrf")
		return
	}
	srcRel := r.FormValue("path")
	dest := strings.Trim(r.FormValue("dest"), "/")
	dir := path.Dir(srcRel)
	if dir == "." {
		dir = ""
	}
	if dest == "" {
		s.redirectToFiles(w, r, dir, "files.error.bad_name")
		return
	}
	if err := kfiles.Copy(s.cfg.WWWRoot, srcRel, dest); err != nil {
		s.redirectToFiles(w, r, dir, "files.error.copy")
		return
	}
	s.redirectToFiles(w, r, dir, "")
}

func (s *Server) handleFileChmod(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		s.redirectToFiles(w, r, "", "login.error.csrf")
		return
	}
	rel := r.FormValue("path")
	dir := path.Dir(rel)
	if dir == "." {
		dir = ""
	}
	modeStr := r.FormValue("mode")
	modeVal, err := strconv.ParseUint(modeStr, 8, 32)
	if err != nil || modeStr == "" || len(modeStr) > 4 {
		s.redirectToFiles(w, r, dir, "files.error.bad_mode")
		return
	}
	if err := kfiles.Chmod(s.cfg.WWWRoot, rel, os.FileMode(modeVal)); err != nil {
		s.redirectToFiles(w, r, dir, "files.error.chmod")
		return
	}
	s.redirectToFiles(w, r, dir, "")
}

func (s *Server) handleFileDelete(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || !auth.ValidCSRF(r) {
		s.redirectToFiles(w, r, "", "login.error.csrf")
		return
	}
	rel := r.FormValue("path")
	dir := path.Dir(rel)
	if dir == "." {
		dir = ""
	}
	if err := kfiles.Delete(s.cfg.WWWRoot, rel); err != nil {
		s.redirectToFiles(w, r, dir, "files.error.delete")
		return
	}
	s.redirectToFiles(w, r, dir, "")
}

func (s *Server) handleFileEditPage(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	relPath := r.URL.Query().Get("path")
	dir := path.Dir(relPath)
	if dir == "." {
		dir = ""
	}

	data := FilesData{
		PageData:    s.basePageData(w, r, "files", sess),
		CurrentPath: dir,
		Breadcrumbs: breadcrumbs(dir),
		Editing:     true,
		EditPath:    relPath,
	}

	abs, info, err := kfiles.Stat(s.cfg.WWWRoot, relPath)
	if err != nil || info == nil || info.IsDir() {
		http.NotFound(w, r)
		return
	}
	if info.Size() > maxEditBytes {
		data.EditTooLarge = true
		s.render(w, "files", data)
		return
	}
	content, err := os.ReadFile(abs)
	if err != nil {
		data.ErrorKey = "files.error.list"
		s.render(w, "files", data)
		return
	}
	if !kfiles.LooksLikeText(content) {
		data.EditNotText = true
		s.render(w, "files", data)
		return
	}
	data.EditContent = string(content)
	s.render(w, "files", data)
}

func (s *Server) handleFileEditSave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(maxEditBytes + (1 << 20)); err != nil {
		http.Error(w, "content too large", http.StatusRequestEntityTooLarge)
		return
	}
	if !auth.ValidCSRF(r) {
		http.Redirect(w, r, "/files", http.StatusSeeOther)
		return
	}
	relPath := r.FormValue("path")
	content := r.FormValue("content")

	if err := kfiles.WriteFile(s.cfg.WWWRoot, relPath, []byte(content)); err != nil {
		http.Redirect(w, r, "/files/edit?path="+relPath, http.StatusSeeOther)
		return
	}
	dir := path.Dir(relPath)
	if dir == "." {
		dir = ""
	}
	http.Redirect(w, r, "/files?path="+dir, http.StatusSeeOther)
}

// redirectToFiles redirects back to the directory listing (a plain
// redirect after every POST, so a page refresh never resubmits a form),
// carrying an error key as a query param when errKey is non-empty so the
// listing page can show it translated.
func (s *Server) redirectToFiles(w http.ResponseWriter, r *http.Request, dir, errKey string) {
	target := "/files"
	if dir != "" {
		target += "?path=" + dir
	}
	if errKey != "" {
		sep := "?"
		if strings.Contains(target, "?") {
			sep = "&"
		}
		target += sep + "error=" + errKey
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}
