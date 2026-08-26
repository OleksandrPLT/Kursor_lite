package terminal

// ANSI 24-bit color codes for the exact Intech brand palette (see the
// project's brand notes) — kept here rather than imported from
// anywhere, since this package has no UI-layer dependency otherwise.
const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiDim    = "\x1b[2m"
	ansiYellow = "\x1b[38;2;255;213;0m" // Flag Yellow
	ansiBlue   = "\x1b[38;2;0;87;183m"  // Flag Blue
)

// Banner is written straight over the WebSocket, before any byte of the
// real shell's own output, the instant a Kursor terminal session opens
// — so wherever someone lands in this web terminal, the first thing
// they see is the same Kursor by Intech mark as the rest of the panel,
// not a bare shell prompt. Real \r\n line endings: this bypasses the
// PTY entirely (see server/terminal.go), so nothing else translates
// them for the terminal emulator.
func Banner() []byte {
	return []byte(
		ansiYellow + ansiBold + "▌ KURSOR" + ansiReset + "\r\n" +
			ansiBlue + ansiBold + "▌ by Intech" + ansiReset + ansiDim + "  ·  intech.org.ua" + ansiReset + "\r\n" +
			ansiDim + "  real shell session — every keystroke runs as this host's own OS user" + ansiReset + "\r\n\r\n",
	)
}
