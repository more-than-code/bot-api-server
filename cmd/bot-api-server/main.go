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

	"github.com/more-than-code/bot-api-server/internal/agentws"
	"github.com/more-than-code/bot-api-server/internal/api"
	"github.com/more-than-code/bot-api-server/internal/audit"
	"github.com/more-than-code/bot-api-server/internal/auth"
	"github.com/more-than-code/bot-api-server/internal/config"
	"github.com/more-than-code/bot-api-server/internal/db"
	"github.com/more-than-code/bot-api-server/internal/registry"
	"github.com/more-than-code/bot-api-server/internal/seal"
)

type deps struct {
	open    func(context.Context, string) (*db.DB, error)
	migrate func(context.Context, string) error
	serve   func(addr string, h http.Handler, stop func()) error
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(log)
	err := run(os.Args[1:], os.Getenv, deps{
		open:    db.Open,
		migrate: db.Migrate,
		serve:   serve,
	})
	if err != nil {
		log.Error("startup failed", "err", safeErr(err))
		os.Exit(1)
	}
}

func run(args []string, getenv func(string) string, d deps) error {
	migrateOnly := false
	for _, arg := range args {
		if arg != "--migrate" {
			return errors.New("unknown argument")
		}
		migrateOnly = true
	}
	cfg, err := config.FromEnv(getenv, migrateOnly)
	if err != nil {
		return err
	}
	ctx := context.Background()
	if migrateOnly {
		return d.migrate(ctx, cfg.MigrateDatabaseURL)
	}
	var mcpSecret string
	if cfg.MCPResource != "" {
		mcpSecret, err = config.ReadMCPClientSecret(cfg.MCPClientSecretFile)
		if err != nil {
			return err
		}
	}
	key, err := config.ReadSecretsKey(cfg.SecretsKeyFile)
	if err != nil {
		return err
	}
	var secrets *seal.Box
	if key != nil {
		secrets, err = seal.New(key)
		if err != nil {
			return err
		}
	}
	pool, err := d.open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	now := func() time.Time { return time.Now().UTC() }
	log := slog.Default()
	aud := audit.Writer{Store: pool, Log: log, Now: now}
	hub := agentws.New(pool, aud, log, now)
	authn := auth.New(pool, cfg, now)
	if mcpSecret != "" {
		if err := authn.SetMCPClientSecret(ctx, mcpSecret); err != nil {
			return err
		}
		log.Info("mcp oauth client ready")
	}
	srv := &api.Server{
		Store:         pool,
		Auth:          authn,
		Hub:           hub,
		Audit:         aud,
		AgentWSURL:    cfg.AgentWSURL,
		ConsoleOrigin: cfg.ConsoleOrigin,
		TrustedProxy:  cfg.TrustedProxy,
		Log:           log,
		Now:           now,
		Secrets:       secrets,
		Registry:      registry.NewService(registry.Options{AllowPrivate: cfg.RegistryAllowPrivate}),
	}
	if cfg.RegistryAllowPrivate {
		log.Warn("registry lookups may reach private addresses and other ports (BOT_API_REGISTRY_ALLOW_PRIVATE=1, dev only)")
	}
	root := http.NewServeMux()
	root.Handle("GET /agent/v1/ws", hub)
	root.Handle("/", srv.Handler())
	log.Info("listening", "addr", cfg.Listen, "public_origin", cfg.PublicOrigin)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go housekeep(ctx, pool, srv.Auth, now)
	return d.serve(cfg.Listen, root, hub.CloseAll)
}

func housekeep(ctx context.Context, pool *db.DB, authn *auth.Service, now func() time.Time) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	var minutes int
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			authn.Sweep(now())
			minutes++
			if minutes%60 != 0 {
				continue
			}
			if err := authn.PurgeDevices(ctx); err != nil {
				slog.Error("device purge failed")
			}
			if err := authn.PurgeOAuthClients(ctx); err != nil {
				slog.Error("oauth client purge failed")
			}
			if err := pool.DeleteOldBatches(ctx, now().Add(-48*time.Hour)); err != nil {
				slog.Error("batch purge failed")
			}
		}
	}
}

func serve(addr string, h http.Handler, stop func()) error {
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- httpSrv.ListenAndServe() }()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-sig:
		if stop != nil {
			stop()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return httpSrv.Shutdown(ctx)
	}
}

func safeErr(err error) string {
	msg := err.Error()
	if strings.Contains(msg, "://") {
		return "redacted"
	}
	return msg
}
