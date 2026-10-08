package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"pokeleague/internal/domain"
	"pokeleague/internal/rbac"
)

// AccessClaims is the JWT payload of an access token.
type AccessClaims struct {
	Role rbac.Role `json:"role"`
	jwt.RegisteredClaims
}

// TokenManager issues and verifies short-lived access tokens signed with
// Ed25519 (JWS alg "EdDSA").
//
// Asymmetric signing means only this service holds the private key, while
// any other service (or an API gateway authorizer) can verify tokens with
// the public key. With HS256, every verifier would also be able to mint
// tokens.
type TokenManager struct {
	priv     ed25519.PrivateKey
	pub      ed25519.PublicKey
	kid      string
	issuer   string
	audience string
	ttl      time.Duration
	leeway   time.Duration
	now      func() time.Time
}

func NewTokenManager(priv ed25519.PrivateKey, issuer, audience string, ttl time.Duration, now func() time.Time) *TokenManager {
	pub := priv.Public().(ed25519.PublicKey)
	sum := sha256.Sum256(pub)
	if now == nil {
		now = time.Now
	}
	return &TokenManager{
		priv: priv, pub: pub,
		kid:    hex.EncodeToString(sum[:8]), // stable key id; enables key rotation via a key set later
		issuer: issuer, audience: audience,
		ttl: ttl, leeway: 30 * time.Second, now: now,
	}
}

// TTL is the access-token lifetime.
func (m *TokenManager) TTL() time.Duration { return m.ttl }

// Issue mints an access token for the trainer.
func (m *TokenManager) Issue(sub uuid.UUID, role rbac.Role) (string, time.Time, error) {
	now := m.now()
	exp := now.Add(m.ttl)
	claims := AccessClaims{
		Role: role,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   sub.String(),
			Audience:  jwt.ClaimStrings{m.audience},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
			ID:        uuid.NewString(),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["kid"] = m.kid
	s, err := tok.SignedString(m.priv)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("auth: signing token: %w", err)
	}
	return s, exp, nil
}

// Verify validates signature, algorithm, issuer, audience and time claims and
// returns the authenticated actor. Every failure maps to ErrInvalidToken so
// callers can't distinguish "expired" from "forged".
func (m *TokenManager) Verify(raw string) (domain.Actor, error) {
	var claims AccessClaims
	_, err := jwt.ParseWithClaims(raw, &claims,
		func(t *jwt.Token) (any, error) {
			if kid, _ := t.Header["kid"].(string); kid != m.kid {
				return nil, errors.New("unknown key id")
			}
			return m.pub, nil
		},
		// Pinning the algorithm defeats "alg: none" and alg-confusion attacks
		// (e.g. an HS256 token "signed" with our public key as the secret).
		jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
		jwt.WithIssuer(m.issuer),
		jwt.WithAudience(m.audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(m.leeway),
		jwt.WithTimeFunc(m.now),
	)
	if err != nil {
		return domain.Actor{}, domain.ErrInvalidToken
	}
	id, err := uuid.Parse(claims.Subject)
	if err != nil || !claims.Role.Valid() {
		return domain.Actor{}, domain.ErrInvalidToken
	}
	return domain.Actor{ID: id, Role: claims.Role}, nil
}

// NewOpaqueToken returns a random 256-bit refresh token and its SHA-256 hash.
// Only the hash is persisted, so a database leak doesn't leak usable tokens.
func NewOpaqueToken() (raw string, hash []byte, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, fmt.Errorf("auth: reading random bytes: %w", err)
	}
	raw = base64.RawURLEncoding.EncodeToString(b)
	return raw, HashOpaqueToken(raw), nil
}

// HashOpaqueToken hashes a refresh token for lookup. A fast hash is correct
// here (unlike for passwords) because the input already has 256 bits of
// entropy, so brute force is infeasible regardless of hash speed.
func HashOpaqueToken(raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}
