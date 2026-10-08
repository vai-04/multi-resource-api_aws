// Package auth contains the credential primitives: password hashing,
// signed access tokens and opaque refresh tokens. It knows nothing about
// HTTP or the database.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2Params configures Argon2id. Memory is in KiB.
type Argon2Params struct {
	Memory  uint32
	Time    uint32
	Threads uint8
	SaltLen uint32
	KeyLen  uint32
}

// DefaultArgon2Params follows the OWASP Password Storage Cheat Sheet's
// baseline for Argon2id: 19 MiB of memory, 2 iterations, 1 degree of
// parallelism.
var DefaultArgon2Params = Argon2Params{Memory: 19 * 1024, Time: 2, Threads: 1, SaltLen: 16, KeyLen: 32}

var errMalformedHash = errors.New("auth: malformed password hash")

// PasswordHasher hashes and verifies passwords with Argon2id.
//
// Argon2id is deliberately memory-hard, which also makes it a denial-of-
// service lever: 100 concurrent logins at 19 MiB each is ~2 GiB. A semaphore
// bounds how many hashes run at once so a login flood degrades into queueing
// instead of an OOM kill.
type PasswordHasher struct {
	p   Argon2Params
	sem chan struct{}
}

func NewPasswordHasher(p Argon2Params, maxConcurrent int) *PasswordHasher {
	if maxConcurrent < 1 {
		maxConcurrent = 1
	}
	return &PasswordHasher{p: p, sem: make(chan struct{}, maxConcurrent)}
}

func (h *PasswordHasher) acquire(ctx context.Context) error {
	select {
	case h.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (h *PasswordHasher) release() { <-h.sem }

// Hash returns a self-describing PHC-format string:
//
//	$argon2id$v=19$m=19456,t=2,p=1$<salt>$<key>
//
// Storing the parameters with the hash lets us raise the cost later and
// transparently upgrade old hashes on the next successful login.
func (h *PasswordHasher) Hash(ctx context.Context, password string) (string, error) {
	salt := make([]byte, h.p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: reading salt: %w", err)
	}
	if err := h.acquire(ctx); err != nil {
		return "", err
	}
	defer h.release()
	key := argon2.IDKey([]byte(password), salt, h.p.Time, h.p.Memory, h.p.Threads, h.p.KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, h.p.Memory, h.p.Time, h.p.Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// Verify checks password against an encoded hash in constant time.
// needsRehash is true when the hash was made with different parameters than
// the hasher's current ones.
func (h *PasswordHasher) Verify(ctx context.Context, password, encoded string) (ok, needsRehash bool, err error) {
	p, salt, want, err := decodeHash(encoded)
	if err != nil {
		return false, false, err
	}
	if err := h.acquire(ctx); err != nil {
		return false, false, err
	}
	defer h.release()
	got := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, uint32(len(want)))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return false, false, nil
	}
	needsRehash = p.Memory != h.p.Memory || p.Time != h.p.Time || p.Threads != h.p.Threads || uint32(len(want)) != h.p.KeyLen
	return true, needsRehash, nil
}

func decodeHash(encoded string) (p Argon2Params, salt, key []byte, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return p, nil, nil, errMalformedHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return p, nil, nil, errMalformedHash
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Time, &p.Threads); err != nil {
		return p, nil, nil, errMalformedHash
	}
	if salt, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil {
		return p, nil, nil, errMalformedHash
	}
	if key, err = base64.RawStdEncoding.DecodeString(parts[5]); err != nil || len(key) == 0 {
		return p, nil, nil, errMalformedHash
	}
	return p, salt, key, nil
}
