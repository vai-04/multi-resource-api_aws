// Command api runs the Pokémon League HTTP API.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"pokeleague/internal/auth"
	"pokeleague/internal/config"
	"pokeleague/internal/db"
	"pokeleague/internal/httpapi"
	"pokeleague/internal/logging"
	"pokeleague/internal/service"
	"pokeleague/internal/store"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	log := logging.New(os.Stdout, cfg.LogLevel)
	slog.SetDefault(log)

	// SIGTERM is what ECS / Kubernetes send before stopping a container.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if cfg.JWTKeyEphemeral {
		log.Warn("JWT_ED25519_SEED not set: using an ephemeral signing key (development only)")
	}

	pool, err := db.Connect(ctx, cfg.DatabaseURL, cfg.DBMaxConns, log)
	if err != nil {
		return err
	}
	defer pool.Close()

	if cfg.AutoMigrate {
		if err := db.Migrate(ctx, pool, log); err != nil {
			return err
		}
	}

	st := store.New(pool)
	hasher := auth.NewPasswordHasher(auth.DefaultArgon2Params, cfg.HashConcurrency)
	tokens := auth.NewTokenManager(cfg.JWTPrivateKey, cfg.JWTIssuer, cfg.JWTAudience, cfg.AccessTokenTTL, nil)
	authSvc, err := service.NewAuth(ctx, st, hasher, tokens,
		service.AuthConfig{RefreshTTL: cfg.RefreshTokenTTL, SessionTTL: cfg.SessionTTL}, nil, log)
	if err != nil {
		return err
	}
	league := service.NewLeague(st, cfg.LockTimeout, nil)

	if cfg.BootstrapAdminUsername != "" {
		if err := authSvc.BootstrapAdmin(ctx, cfg.BootstrapAdminUsername, cfg.BootstrapAdminEmail, cfg.BootstrapAdminPassword); err != nil {
			return fmt.Errorf("bootstrap admin: %w", err)
		}
	}

	api := httpapi.New(authSvc, league, tokens, st, log, httpapi.Options{
		RequestTimeout:    cfg.RequestTimeout,
		AuthRatePerMinute: cfg.AuthRatePerMinute,
		TrustProxy:        cfg.TrustProxy,
	})
	api.StartBackground(ctx)
	go cleanupRefreshTokens(ctx, st, log)

	srv := &http.Server{
		Addr:    cfg.HTTPAddr,
		Handler: api.Handler(),
		// Without these, a slow client can hold a connection (and goroutine)
		// open indefinitely - the classic Slowloris attack.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      cfg.RequestTimeout + 5*time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}

	serveErr := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", cfg.HTTPAddr, "env", cfg.Env)
		serveErr <- srv.ListenAndServe()
	}()

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
	}

	// Graceful shutdown: fail readiness so the load balancer drains us, stop
	// accepting connections, and let in-flight requests finish.
	log.Info("shutting down")
	api.SetDraining()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	if err := <-serveErr; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	log.Info("stopped cleanly")
	return nil
}

// cleanupRefreshTokens periodically deletes sessions past their absolute
// lifetime. Running it on every replica is harmless (DELETE is idempotent).
func cleanupRefreshTokens(ctx context.Context, st *store.Store, log *slog.Logger) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n, err := st.DeleteExpiredRefreshTokens(ctx)
			if err != nil {
				log.Warn("refresh token cleanup failed", "err", err)
				continue
			}
			if n > 0 {
				log.Info("deleted expired refresh tokens", "count", n)
			}
		}
	}
}
