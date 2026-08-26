package server

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"kursor/internal/store"
)

// maxAttachmentSize caps a single upload — generous enough for a
// screenshot or a short document, small enough that a ticket thread
// can't quietly fill the disk.
const maxAttachmentSize = 10 << 20 // 10 MiB

func ticketAttachmentsDir(dataDir string, ticketID int64) string {
	return filepath.Join(dataDir, "ticket_attachments", strconv.FormatInt(ticketID, 10))
}

// randomStoredName never trusts the uploader's filename for the
// on-disk name (path traversal, collisions, weird characters) — only
// the extension is kept, purely cosmetic, from a fixed safe set.
func randomStoredName(originalName string) (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	ext := filepath.Ext(originalName)
	if len(ext) > 10 || strings.ContainsAny(ext, "/\\") {
		ext = "" // implausible/hostile extension — drop it rather than trust it
	}
	return hex.EncodeToString(buf) + ext, nil
}

// saveTicketAttachment streams an uploaded file to disk under this
// ticket's own directory and records it — reused by both ticket
// creation (commentID nil) and commenting (commentID set).
func saveTicketAttachment(st *store.Store, dataDir string, ticketID int64, commentID *int64, uploaderID int64, file multipart.File, header *multipart.FileHeader) error {
	if header.Size > maxAttachmentSize {
		return fmt.Errorf("file too large (max %d MB)", maxAttachmentSize/(1<<20))
	}
	dir := ticketAttachmentsDir(dataDir, ticketID)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	storedName, err := randomStoredName(header.Filename)
	if err != nil {
		return err
	}
	dest, err := os.OpenFile(filepath.Join(dir, storedName), os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o640)
	if err != nil {
		return err
	}
	defer dest.Close()

	written, err := io.CopyN(dest, file, maxAttachmentSize+1)
	if err != nil && err != io.EOF {
		return err
	}
	if written > maxAttachmentSize {
		_ = os.Remove(filepath.Join(dir, storedName))
		return fmt.Errorf("file too large (max %d MB)", maxAttachmentSize/(1<<20))
	}

	_, err = st.CreateTicketAttachment(ticketID, commentID, header.Filename, storedName, written, uploaderID)
	return err
}

// handleTicketAttachmentDownload serves one attachment — gated by the
// exact same access rule as the ticket itself (loadTicket): a
// requester only ever reaches their own tickets' files, an agent
// reaches any.
func (s *Server) handleTicketAttachmentDownload(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	ticket, err := s.loadTicket(r, sess)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if ticket == nil {
		http.NotFound(w, r)
		return
	}
	attID, err := strconv.ParseInt(chi.URLParam(r, "attachment_id"), 10, 64)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	att, err := s.store.GetTicketAttachment(attID)
	if err != nil || att == nil || att.TicketID != ticket.ID {
		http.NotFound(w, r)
		return
	}
	path := filepath.Join(ticketAttachmentsDir(s.cfg.DataDir, ticket.ID), att.StoredName)
	w.Header().Set("Content-Disposition", `attachment; filename="`+strings.ReplaceAll(att.OriginalName, `"`, "")+`"`)
	http.ServeFile(w, r, path)
}
