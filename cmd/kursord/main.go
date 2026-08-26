// Command kursord is the Kursor by Intech panel daemon.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"kursor/internal/auth"
	"kursor/internal/config"
	"kursor/internal/monitor"
	"kursor/internal/oidc"
	"kursor/internal/server"
	"kursor/internal/store"
)

func main() {
	cfg := config.Load()
	if err := os.MkdirAll(cfg.WWWRoot, 0o755); err != nil {
		log.Fatalf("create www root: %v", err)
	}

	st, err := store.Open(cfg.DataDir)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer st.Close()

	username, password, created, err := auth.EnsureAdmin(st)
	if err != nil {
		log.Fatalf("bootstrap admin: %v", err)
	}
	if created {
		log.Printf(`
==========================================
 Kursor by Intech — first run
 Username: %s
 Password: %s
==========================================
 Save this password now — it will not be shown again.
`, username, password)
	}

	collector := monitor.NewCollector(2*time.Second, "/")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go collector.Run(ctx)

	signingKey, err := oidc.LoadOrGenerateKey(cfg.DataDir)
	if err != nil {
		log.Fatalf("load/generate OIDC signing key: %v", err)
	}
	issuer := oidc.NewIssuer(signingKey)

	handler, err := server.New(cfg, st, collector, issuer)
	if err != nil {
		log.Fatalf("build server: %v", err)
	}

	log.Printf("Kursor by Intech listening on http://localhost%s", cfg.Addr)
	if err := http.ListenAndServe(cfg.Addr, handler); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
