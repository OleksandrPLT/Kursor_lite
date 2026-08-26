package server

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/websocket"

	kterm "kursor/internal/terminal"
)

var terminalUpgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	// The WS handshake rides on the same authenticated, CSRF-adjacent
	// session as the rest of the app (this route sits behind
	// requireAuth + requireModule("server") in server.go) — same-origin
	// only, matching how the browser actually loads this page.
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		return origin == "" || origin == "http://"+r.Host || origin == "https://"+r.Host
	},
}

type terminalControlMsg struct {
	Resize *struct {
		Cols uint16 `json:"cols"`
		Rows uint16 `json:"rows"`
	} `json:"resize"`
}

// handleTerminalWS bridges a browser WebSocket to a real PTY shell
// session — see internal/terminal. Every byte typed in the browser
// reaches a real shell running with kursord's own OS privileges.
func (s *Server) handleTerminalWS(w http.ResponseWriter, r *http.Request) {
	conn, err := terminalUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	sess, err := kterm.Spawn()
	if err != nil {
		_ = conn.WriteMessage(websocket.TextMessage, []byte("failed to start shell: "+err.Error()))
		return
	}
	// Closing the PTY (below) makes the reader goroutine's Read return an
	// error on its own, so it cleans itself up — no need to wait on it
	// here (waiting would deadlock: Close only runs after this handler
	// returns, and Close is exactly what unblocks the reader).
	defer sess.Close()

	// Kursor's own brand banner, first — before the shell has written a
	// single byte of its own prompt.
	_ = conn.WriteMessage(websocket.BinaryMessage, kterm.Banner())

	// PTY output -> browser
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := sess.PTY.Read(buf)
			if n > 0 {
				if werr := conn.WriteMessage(websocket.BinaryMessage, buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	// browser input -> PTY (keystrokes, and JSON control frames for resize)
	for {
		mt, data, err := conn.ReadMessage()
		if err != nil {
			break
		}
		if mt == websocket.TextMessage && len(data) > 0 && data[0] == '{' {
			var msg terminalControlMsg
			if json.Unmarshal(data, &msg) == nil && msg.Resize != nil {
				_ = sess.Resize(msg.Resize.Cols, msg.Resize.Rows)
				continue
			}
		}
		if _, err := sess.PTY.Write(data); err != nil {
			break
		}
	}
}

func (s *Server) handleTerminalPage(w http.ResponseWriter, r *http.Request) {
	sess := sessionFromContext(r)
	s.render(w, "terminal", s.basePageData(w, r, "server-terminal", sess))
}
