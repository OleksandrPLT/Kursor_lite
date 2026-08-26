// Package config loads Kursor's runtime configuration from flags and
// environment variables. Kept intentionally small for the MVP: no YAML
// file yet (see the build plan, M8, for the installer-driven config file).
package config

import (
	"flag"
	"os"
)

// Config holds everything the daemon needs to start.
type Config struct {
	// Addr is the listen address, e.g. ":8888".
	Addr string
	// DataDir holds the sqlite database and other local state.
	DataDir string
	// WWWRoot is the default root for site docroots (file manager scope
	// in a later milestone). Not used yet, but wired through now so the
	// config shape doesn't need to change later.
	WWWRoot string
}

// Load parses flags (falling back to environment variables, falling back
// to sane local-dev defaults) into a Config.
func Load() Config {
	addr := flag.String("addr", getenv("KURSOR_ADDR", ":8888"), "listen address")
	dataDir := flag.String("data-dir", getenv("KURSOR_DATA_DIR", "./data"), "directory for the sqlite database and local state")
	wwwRoot := flag.String("www-root", getenv("KURSOR_WWW_ROOT", "./data/wwwroot"), "default root directory for managed site docroots")
	flag.Parse()

	return Config{
		Addr:    *addr,
		DataDir: *dataDir,
		WWWRoot: *wwwRoot,
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
