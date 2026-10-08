package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"net/http"
	"regexp"
	"runtime/debug"
	"strings"
	"time"

	"pokeleague/internal/domain"
	"pokeleague/internal/logging"
	"pokeleague/internal/rbac"
)

type middleware func(http.Handler) http.Handler

// chain applies middleware so the first listed runs outermost.
func chain(h http.Handler, mws ...middleware) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

var validRequestID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// requestID propagates an incoming X-Request-ID (e.g. from a load balancer)
// or generates one, and echoes it back so clients can quote it in bug
// reports. Incoming ids are validated so they can't inject junk into logs.
func requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if !validRequestID.MatchString(id) {
			var b [12]byte
			_, _ = rand.Read(b[:])
			id = hex.EncodeToString(b[:])
		}
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(logging.WithRequestID(r.Context(), id)))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	n, err := s.ResponseWriter.Write(b)
	s.bytes += n
	return n, err
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// accessLog writes one structured line per request.
func (a *API) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			return // probes every few seconds would drown real traffic
		}
		a.log.InfoContext(r.Context(), "http request",
			"method", r.Method,
			"path", r.URL.Path,
			"route", r.Pattern,
			"status", rec.status,
			"bytes", rec.bytes,
			"duration_ms", float64(time.Since(start).Microseconds())/1000,
			"remote_ip", a.clientIP(r),
		)
	})
}

// recoverPanics turns a panic into a 500 instead of a dropped connection,
// and logs the stack.
func (a *API) recoverPanics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v) // deliberate abort: let net/http handle it
				}
				a.log.ErrorContext(r.Context(), "panic", "panic", v, "stack", string(debug.Stack()))
				writeProblem(w, r, http.StatusInternalServerError, "internal_error", "an unexpected error occurred", nil)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// securityHeaders sets conservative defaults for a JSON API.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// timeout bounds the time a handler (and every DB call it makes, since they
// share the context) may spend on a request.
func timeout(d time.Duration) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), d)
			defer cancel()
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

type actorKey struct{}

func actorFrom(ctx context.Context) (domain.Actor, bool) {
	a, ok := ctx.Value(actorKey{}).(domain.Actor)
	return a, ok
}

// authenticate requires a valid Bearer access token (RFC 6750) and puts the
// actor in the request context. Verification is purely cryptographic - no
// database round trip per request - which is the point of short-lived JWTs.
func (a *API) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scheme, tok, ok := strings.Cut(r.Header.Get("Authorization"), " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") || tok == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="pokeleague"`)
			writeProblem(w, r, http.StatusUnauthorized, "missing_token", "an access token is required", nil)
			return
		}
		actor, err := a.tokens.Verify(strings.TrimSpace(tok))
		if err != nil {
			a.writeError(w, r, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), actorKey{}, actor)))
	})
}

// require enforces a role permission. It must run after authenticate.
// 401 means "we don't know who you are"; 403 means "we know, and you can't".
func (a *API) require(p rbac.Permission) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			actor, ok := actorFrom(r.Context())
			if !ok {
				writeProblem(w, r, http.StatusUnauthorized, "missing_token", "an access token is required", nil)
				return
			}
			if !actor.Role.Can(p) {
				a.writeError(w, r, domain.ErrForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// rateLimit throttles by client IP.
func (a *API) rateLimit(l *limiter) middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if ok, retry := l.allow(a.clientIP(r)); !ok {
				w.Header().Set("Retry-After", retryAfterSeconds(retry))
				writeProblem(w, r, http.StatusTooManyRequests, domain.ErrRateLimited.Code, domain.ErrRateLimited.Detail, nil)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// clientIP returns the caller's IP. Behind an AWS ALB the connection comes
// from the load balancer, which appends the real client address as the LAST
// X-Forwarded-For entry. Earlier entries are client-supplied and spoofable,
// so only the last one is trusted, and only when configured to trust a proxy.
func (a *API) clientIP(r *http.Request) string {
	if a.opts.TrustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if ip := net.ParseIP(strings.TrimSpace(parts[len(parts)-1])); ip != nil {
				return ip.String()
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
