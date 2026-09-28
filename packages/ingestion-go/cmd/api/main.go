// Command audittrail-api serves the ingestion API.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"audittrail.dev/packages/ingestion-go/internal/api"
	"audittrail.dev/packages/ingestion-go/internal/config"
	"audittrail.dev/packages/ingestion-go/internal/db"
	"audittrail.dev/packages/ingestion-go/internal/keys"
)

func main() {
	config.LoadDotEnv()
	level := slog.LevelInfo
	if config.Bool("DEBUG", false) {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	master, err := keys.ParseMasterKey(os.Getenv("AUDITTRAIL_MASTER_KEY"))
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	maxConns := min(max(config.Int("DB_MAX_CONNS", 20), 1), 1000)
	pool, err := db.Connect(ctx, config.AppDBURL(), int32(maxConns)) // #nosec G115 -- clamped to 1..1000
	if err != nil {
		log.Error("database", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	control, err := db.Connect(ctx, config.ControlDBURL(), 5)
	if err != nil {
		log.Error("control database", "err", err)
		os.Exit(1)
	}
	defer control.Close()
	pepper, err := keys.ParsePepper(os.Getenv("AUDITTRAIL_KEY_PEPPER"))
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}

	var cors []string
	for _, o := range strings.Split(config.Str("CORS_ORIGINS", "http://localhost:3000"), ",") {
		if o = strings.TrimSpace(o); o != "" {
			cors = append(cors, o)
		}
	}
	srv := api.New(pool, control, master, pepper, os.Getenv("AUDITTRAIL_ADMIN_TOKEN"), cors, log)
	if n := config.Int("SEQUENCER_MAX_BATCH", 256); n > 0 {
		srv.Seq.MaxBatch = n
	}
	api.RegisterExtensions(srv)
	srv.StartNonceJanitor(ctx)
	srv.StartMonitor(ctx, config.Dur("MONITOR_INTERVAL", 30*time.Second))

	addr := config.Str("LISTEN_ADDR", ":8080")
	// Timeouts bound slow clients (slowloris-style bodies, stalled readers).
	hs := &http.Server{Addr: addr, Handler: srv, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 120 * time.Second, IdleTimeout: 120 * time.Second, MaxHeaderBytes: 64 << 10}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = hs.Shutdown(sctx)
	}()
	log.Info("audittrail-api listening", "addr", addr)
	if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("listen", "err", err)
		os.Exit(1)
	}
}
