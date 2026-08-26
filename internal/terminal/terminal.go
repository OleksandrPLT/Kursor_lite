// Package terminal spawns a real PTY-backed shell — the browser
// terminal is a genuine shell session (same privileges as whatever OS
// user runs kursord), not a sandboxed command runner. See the project's
// SECURITY notes: this is the single most sensitive module in Kursor.
package terminal

import (
	"os"
	"os/exec"

	"github.com/creack/pty"
)

// Shell returns the login shell to spawn — $SHELL if set, else a
// reasonable default.
func Shell() string {
	if s := os.Getenv("SHELL"); s != "" {
		return s
	}
	return "/bin/bash"
}

// Session wraps a live PTY-backed shell process.
type Session struct {
	PTY *os.File
	Cmd *exec.Cmd
}

// Spawn starts a new login shell attached to a PTY.
func Spawn() (*Session, error) {
	cmd := exec.Command(Shell(), "-l")
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")
	ptmx, err := pty.Start(cmd)
	if err != nil {
		return nil, err
	}
	return &Session{PTY: ptmx, Cmd: cmd}, nil
}

// Resize updates the PTY's terminal size (so full-screen programs like
// vim/htop draw correctly).
func (s *Session) Resize(cols, rows uint16) error {
	return pty.Setsize(s.PTY, &pty.Winsize{Cols: cols, Rows: rows})
}

// Close terminates the shell process and closes the PTY.
func (s *Session) Close() {
	_ = s.Cmd.Process.Kill()
	_ = s.PTY.Close()
	_, _ = s.Cmd.Process.Wait()
}
