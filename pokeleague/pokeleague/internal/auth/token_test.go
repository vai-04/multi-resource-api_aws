package auth_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"pokeleague/internal/auth"
	"pokeleague/internal/domain"
	"pokeleague/internal/rbac"
)

// TestTokenManager_RejectsForgedExpiredAndMisdirectedTokens is a unit test
// (no database) for access-token verification. Each case is a real attack
// or misconfiguration that a hand-rolled or loosely configured JWT check
// would let through.
func TestTokenManager_RejectsForgedExpiredAndMisdirectedTokens(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	tm := auth.NewTokenManager(priv, "pokeleague-api", "pokeleague-clients", 15*time.Minute, clock)
	subject := uuid.New()

	valid, _, err := tm.Issue(subject, rbac.RoleGymLeader)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("valid token round-trips subject and role", func(t *testing.T) {
		a, err := tm.Verify(valid)
		if err != nil {
			t.Fatal(err)
		}
		if a.ID != subject || a.Role != rbac.RoleGymLeader {
			t.Fatalf("got %+v", a)
		}
	})

	reject := func(t *testing.T, tok string) {
		t.Helper()
		if _, err := tm.Verify(tok); !errors.Is(err, domain.ErrInvalidToken) {
			t.Fatalf("got %v, want ErrInvalidToken", err)
		}
	}

	t.Run("expired token (past the leeway)", func(t *testing.T) {
		later := auth.NewTokenManager(priv, "pokeleague-api", "pokeleague-clients", 15*time.Minute,
			func() time.Time { return now.Add(16 * time.Minute) })
		if _, err := later.Verify(valid); !errors.Is(err, domain.ErrInvalidToken) {
			t.Fatalf("got %v, want ErrInvalidToken", err)
		}
	})

	t.Run("signed by a different key", func(t *testing.T) {
		_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
		other := auth.NewTokenManager(otherPriv, "pokeleague-api", "pokeleague-clients", 15*time.Minute, clock)
		tok, _, _ := other.Issue(subject, rbac.RoleAdmin)
		reject(t, tok)
	})

	t.Run("privilege escalation by editing the payload", func(t *testing.T) {
		parts := strings.Split(valid, ".")
		payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
		forged := strings.Replace(string(payload), `"gym_leader"`, `"admin"`, 1)
		parts[1] = base64.RawURLEncoding.EncodeToString([]byte(forged))
		reject(t, strings.Join(parts, "."))
	})

	claims := func(aud string) jwt.MapClaims {
		return jwt.MapClaims{
			"sub": subject.String(), "role": "admin", "iss": "pokeleague-api", "aud": aud,
			"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
		}
	}

	t.Run(`alg "none"`, func(t *testing.T) {
		tok := jwt.NewWithClaims(jwt.SigningMethodNone, claims("pokeleague-clients"))
		s, _ := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
		reject(t, s)
	})

	t.Run("alg confusion: HS256 keyed with the public key", func(t *testing.T) {
		// Classic attack on verifiers that pick the algorithm from the token
		// header: the public key is public, so anyone can make this HMAC.
		pub := priv.Public().(ed25519.PublicKey)
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims("pokeleague-clients"))
		s, _ := tok.SignedString([]byte(pub))
		reject(t, s)
	})

	t.Run("token minted for another audience", func(t *testing.T) {
		other := auth.NewTokenManager(priv, "pokeleague-api", "some-other-service", 15*time.Minute, clock)
		tok, _, _ := other.Issue(subject, rbac.RoleTrainer)
		reject(t, tok)
	})

	t.Run("unknown role claim", func(t *testing.T) {
		tok, _, _ := tm.Issue(subject, rbac.Role("champion"))
		reject(t, tok)
	})
}
