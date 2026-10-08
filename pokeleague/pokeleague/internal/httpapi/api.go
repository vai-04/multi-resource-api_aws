// Package httpapi is the HTTP transport: routing, middleware, request
// decoding, response encoding and error mapping. Business decisions are
// delegated to package service.
package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"pokeleague/internal/auth"
	"pokeleague/internal/rbac"
	"pokeleague/internal/service"
)

// Options configures the transport layer.
type Options struct {
	RequestTimeout    time.Duration
	AuthRatePerMinute int // per client IP on /v1/auth/*
	AuthRateBurst     int
	TrustProxy        bool // trust X-Forwarded-For from a load balancer
}

// Pinger is the readiness dependency (the database).
type Pinger interface {
	Ping(ctx context.Context) error
}

// API holds the handlers' dependencies.
type API struct {
	auth     *service.Auth
	league   *service.League
	tokens   *auth.TokenManager
	db       Pinger
	log      *slog.Logger
	opts     Options
	limiter  *limiter
	draining atomic.Bool
}

func New(authSvc *service.Auth, league *service.League, tokens *auth.TokenManager, db Pinger, log *slog.Logger, opts Options) *API {
	if opts.RequestTimeout == 0 {
		opts.RequestTimeout = 10 * time.Second
	}
	if opts.AuthRatePerMinute == 0 {
		opts.AuthRatePerMinute = 20
	}
	if opts.AuthRateBurst == 0 {
		opts.AuthRateBurst = 10
	}
	return &API{
		auth: authSvc, league: league, tokens: tokens, db: db, log: log, opts: opts,
		limiter: newLimiter(opts.AuthRatePerMinute, opts.AuthRateBurst),
	}
}

// StartBackground runs housekeeping until ctx is cancelled.
func (a *API) StartBackground(ctx context.Context) {
	go a.limiter.janitor(ctx, time.Minute)
}

// SetDraining makes /readyz fail so the load balancer stops routing new
// requests here while in-flight ones finish during graceful shutdown.
func (a *API) SetDraining() { a.draining.Store(true) }

// Handler builds the routing table.
//
// Access control is visible at the route: `authed` = any logged-in trainer,
// `can(p)` = logged in AND role has permission p. Ownership rules ("only the
// host may edit") need the resource, so they live in the service layer.
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()

	base := []middleware{timeout(a.opts.RequestTimeout)}
	public := func(h http.HandlerFunc) http.Handler { return chain(h, base...) }
	throttled := func(h http.HandlerFunc) http.Handler {
		return chain(h, append(base, a.rateLimit(a.limiter))...)
	}
	authed := func(h http.HandlerFunc) http.Handler { return chain(h, append(base, a.authenticate)...) }
	can := func(p rbac.Permission, h http.HandlerFunc) http.Handler {
		return chain(h, append(base, a.authenticate, a.require(p))...)
	}

	// Service index. The {$} anchor matches only the exact root path, so
	// unknown paths still get a 404 problem document instead of this page.
	mux.HandleFunc("GET /{$}", a.index)

	// Probes
	mux.HandleFunc("GET /healthz", a.healthz)
	mux.HandleFunc("GET /readyz", a.readyz)

	// Auth
	mux.Handle("POST /v1/auth/signup", throttled(a.signup))
	mux.Handle("POST /v1/auth/login", throttled(a.login))
	mux.Handle("POST /v1/auth/refresh", throttled(a.refresh))
	mux.Handle("POST /v1/auth/logout", public(a.logout))

	// Me
	mux.Handle("GET /v1/me", authed(a.me))
	mux.Handle("GET /v1/me/registrations", authed(a.myRegistrations))

	// Tournaments
	mux.Handle("GET /v1/tournaments", authed(a.listTournaments))
	mux.Handle("POST /v1/tournaments", can(rbac.PermTournamentCreate, a.createTournament))
	mux.Handle("GET /v1/tournaments/{id}", authed(a.getTournament))
	mux.Handle("PATCH /v1/tournaments/{id}", authed(a.updateTournament)) // owner or admin: checked in service

	// Registrations (the trainer <-> tournament relationship)
	mux.Handle("POST /v1/tournaments/{id}/registrations", can(rbac.PermTournamentRegister, a.register))
	mux.Handle("DELETE /v1/tournaments/{id}/registrations/me", authed(a.withdraw))
	mux.Handle("GET /v1/tournaments/{id}/registrations", authed(a.roster)) // host or admin: checked in service

	// Admin
	mux.Handle("PUT /v1/admin/trainers/{id}/role", can(rbac.PermTrainerManageRoles, a.setRole))

	return chain(mux, requestID, a.accessLog, a.recoverPanics, securityHeaders)
}

// index is an unauthenticated entry point for the base URL: it lists the
// routes so that opening the service in a browser is useful rather than a 404.
// It advertises paths only - never configuration, versions or build details.
func (a *API) index(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"service": "pokeleague-api",
		"api":     "/v1",
		"endpoints": map[string]string{
			"signup":            "POST /v1/auth/signup",
			"login":             "POST /v1/auth/login",
			"refresh":           "POST /v1/auth/refresh",
			"logout":            "POST /v1/auth/logout",
			"me":                "GET /v1/me",
			"my_registrations":  "GET /v1/me/registrations",
			"list_tournaments":  "GET /v1/tournaments",
			"create_tournament": "POST /v1/tournaments",
			"get_tournament":    "GET /v1/tournaments/{id}",
			"update_tournament": "PATCH /v1/tournaments/{id}",
			"register":          "POST /v1/tournaments/{id}/registrations",
			"withdraw":          "DELETE /v1/tournaments/{id}/registrations/me",
			"roster":            "GET /v1/tournaments/{id}/registrations",
			"set_role":          "PUT /v1/admin/trainers/{id}/role",
		},
		"health": map[string]string{"live": "GET /healthz", "ready": "GET /readyz"},
	})
}

func (a *API) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// readyz reports whether this instance should receive traffic: it is not
// shutting down and can reach the database. Liveness (/healthz) deliberately
// does NOT check the database - a DB outage should stop traffic, not trigger
// a restart loop of every container.
func (a *API) readyz(w http.ResponseWriter, r *http.Request) {
	if a.draining.Load() {
		writeProblem(w, r, http.StatusServiceUnavailable, "draining", "instance is shutting down", nil)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := a.db.Ping(ctx); err != nil {
		a.log.WarnContext(r.Context(), "readiness check failed", "err", err)
		writeProblem(w, r, http.StatusServiceUnavailable, "db_unavailable", "database is unreachable", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}
