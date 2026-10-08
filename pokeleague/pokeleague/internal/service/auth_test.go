package service_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"

	"pokeleague/internal/auth"
	"pokeleague/internal/domain"
	"pokeleague/internal/service"
	"pokeleague/internal/store"
	"pokeleague/internal/testdb"
)

// clock is a controllable time source shared by the token manager and the
// auth service, so expiry can be tested without sleeping.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Advance(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

// TestRefresh_RotationReuseDetectionAndExpiry covers the refresh-token
// lifecycle: every refresh rotates the token, replaying an old token revokes
// the whole session family (theft response), and sessions end at their
// absolute lifetime no matter how often they're refreshed.
func TestRefresh_RotationReuseDetectionAndExpiry(t *testing.T) {
	t.Parallel()
	pool := testdb.New(t)
	st := store.New(pool)
	ctx := context.Background()

	clk := &clock{t: time.Now()}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	tokens := auth.NewTokenManager(priv, "test", "test", 15*time.Minute, clk.Now)
	fastHasher := auth.NewPasswordHasher(auth.Argon2Params{Memory: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}, 4)
	svc, err := service.NewAuth(ctx, st, fastHasher, tokens,
		service.AuthConfig{RefreshTTL: 24 * time.Hour, SessionTTL: 72 * time.Hour}, clk.Now, testdb.Discard)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := svc.Signup(ctx, "misty", "misty@cerulean.gym", "starmie-is-best-girl"); err != nil {
		t.Fatal(err)
	}
	login := func(t *testing.T) service.TokenPair {
		t.Helper()
		p, err := svc.Login(ctx, "misty", "starmie-is-best-girl", "test")
		if err != nil {
			t.Fatal(err)
		}
		return p
	}

	t.Run("refresh rotates and the access token verifies", func(t *testing.T) {
		p1 := login(t)
		p2, err := svc.Refresh(ctx, p1.RefreshToken, "test")
		if err != nil {
			t.Fatal(err)
		}
		if p2.RefreshToken == p1.RefreshToken {
			t.Fatal("refresh token was not rotated")
		}
		if _, err := tokens.Verify(p2.AccessToken); err != nil {
			t.Fatalf("new access token invalid: %v", err)
		}
	})

	t.Run("replaying a rotated token revokes the whole family", func(t *testing.T) {
		p1 := login(t)
		p2, err := svc.Refresh(ctx, p1.RefreshToken, "legit client")
		if err != nil {
			t.Fatal(err)
		}
		// An attacker replays the stolen, already-used p1.
		if _, err := svc.Refresh(ctx, p1.RefreshToken, "attacker"); !errors.Is(err, domain.ErrRefreshTokenReused) {
			t.Fatalf("replay: got %v, want ErrRefreshTokenReused", err)
		}
		// The legitimate client's current token is dead too: the family is
		// revoked because we can't tell which holder is the real one.
		if _, err := svc.Refresh(ctx, p2.RefreshToken, "legit client"); !errors.Is(err, domain.ErrRefreshTokenReused) {
			t.Fatalf("descendant after reuse: got %v, want ErrRefreshTokenReused", err)
		}
		// Other sessions (another device's login) are unaffected.
		other := login(t)
		if _, err := svc.Refresh(ctx, other.RefreshToken, "phone"); err != nil {
			t.Fatalf("unrelated session was revoked: %v", err)
		}
	})

	t.Run("concurrent refreshes with one token: exactly one wins", func(t *testing.T) {
		p := login(t)
		const n = 8
		var (
			wg    sync.WaitGroup
			start = make(chan struct{})
			errs  = make([]error, n)
		)
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, errs[i] = svc.Refresh(ctx, p.RefreshToken, "racer")
			}()
		}
		close(start)
		wg.Wait()
		wins := 0
		for _, err := range errs {
			if err == nil {
				wins++
			} else if !errors.Is(err, domain.ErrRefreshTokenReused) {
				t.Errorf("unexpected error: %v", err)
			}
		}
		if wins != 1 {
			t.Fatalf("%d concurrent refreshes succeeded, want exactly 1", wins)
		}
	})

	t.Run("access tokens expire; sessions end at their absolute lifetime", func(t *testing.T) {
		p := login(t)
		clk.Advance(16 * time.Minute)
		if _, err := tokens.Verify(p.AccessToken); !errors.Is(err, domain.ErrInvalidToken) {
			t.Fatalf("expired access token: got %v, want ErrInvalidToken", err)
		}
		// Keep refreshing every 20h: each refresh slides expiry forward, but
		// never past 72h after login.
		cur := p.RefreshToken
		for range 3 {
			clk.Advance(20 * time.Hour)
			next, err := svc.Refresh(ctx, cur, "test")
			if err != nil {
				t.Fatalf("refresh within session lifetime: %v", err)
			}
			cur = next.RefreshToken
		}
		clk.Advance(13 * time.Hour) // ~73h after login: past the 72h session cap
		if _, err := svc.Refresh(ctx, cur, "test"); !errors.Is(err, domain.ErrInvalidToken) {
			t.Fatalf("refresh past session lifetime: got %v, want ErrInvalidToken", err)
		}
	})

	t.Run("logout revokes the session", func(t *testing.T) {
		p := login(t)
		if err := svc.Logout(ctx, p.RefreshToken); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.Refresh(ctx, p.RefreshToken, "test"); err == nil {
			t.Fatal("refresh succeeded after logout")
		}
	})
}
