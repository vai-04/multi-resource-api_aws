package service

import (
	"context"
	"errors"
	"log/slog"
	"net/mail"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"pokeleague/internal/auth"
	"pokeleague/internal/domain"
	"pokeleague/internal/rbac"
	"pokeleague/internal/store"
)

// TokenPair is what a successful login or refresh returns.
type TokenPair struct {
	AccessToken      string
	AccessExpiresAt  time.Time
	RefreshToken     string
	RefreshExpiresAt time.Time
}

// AuthConfig tunes session lifetimes.
type AuthConfig struct {
	RefreshTTL time.Duration // sliding: each rotation extends by this much...
	SessionTTL time.Duration // ...but never past this absolute limit from login
}

// Auth handles sign-up, login and the refresh-token lifecycle.
type Auth struct {
	st        *store.Store
	hasher    *auth.PasswordHasher
	tokens    *auth.TokenManager
	cfg       AuthConfig
	now       func() time.Time
	log       *slog.Logger
	dummyHash string
}

func NewAuth(ctx context.Context, st *store.Store, h *auth.PasswordHasher, tm *auth.TokenManager,
	cfg AuthConfig, now func() time.Time, log *slog.Logger) (*Auth, error) {
	if now == nil {
		now = time.Now
	}
	// A real hash to verify against when the username doesn't exist, so a
	// failed login takes the same time whether or not the account exists.
	// Otherwise response timing reveals which usernames are registered.
	dummy, err := h.Hash(ctx, "pikachu-uses-thunderbolt-on-a-timing-attack")
	if err != nil {
		return nil, err
	}
	return &Auth{st: st, hasher: h, tokens: tm, cfg: cfg, now: now, log: log, dummyHash: dummy}, nil
}

var usernameRE = regexp.MustCompile(`^[A-Za-z0-9_]{3,32}$`)

// Password policy follows NIST SP 800-63B: favour length, no composition
// rules ("must contain a symbol"), and a generous maximum.
const (
	minPasswordLen = 12
	maxPasswordLen = 128
)

// Signup creates a trainer account. New accounts always get the least
// privileged role; elevation is an admin action.
func (s *Auth) Signup(ctx context.Context, username, email, password string) (domain.Trainer, error) {
	username = strings.TrimSpace(username)
	email = strings.TrimSpace(email)

	f := fieldErrors{}
	if !usernameRE.MatchString(username) {
		f["username"] = "must be 3-32 characters of letters, digits or underscores"
	}
	if addr, err := mail.ParseAddress(email); err != nil || addr.Address != email || len(email) > 254 {
		f["email"] = "must be a valid email address"
	}
	if n := utf8.RuneCountInString(password); n < minPasswordLen || n > maxPasswordLen {
		f["password"] = "must be between 12 and 128 characters"
	}
	if err := f.err(); err != nil {
		return domain.Trainer{}, err
	}

	hash, err := s.hasher.Hash(ctx, password)
	if err != nil {
		return domain.Trainer{}, err
	}
	return s.st.CreateTrainer(ctx, username, email, hash, rbac.RoleTrainer)
}

// Login verifies credentials and starts a new session (refresh-token family).
func (s *Auth) Login(ctx context.Context, username, password, userAgent string) (TokenPair, error) {
	tr, err := s.st.TrainerByUsername(ctx, username)
	if errors.Is(err, domain.ErrTrainerNotFound) {
		_, _, _ = s.hasher.Verify(ctx, password, s.dummyHash) // equalise timing
		return TokenPair{}, domain.ErrInvalidCredentials
	}
	if err != nil {
		return TokenPair{}, err
	}

	ok, needsRehash, err := s.hasher.Verify(ctx, password, tr.PasswordHash)
	if err != nil {
		return TokenPair{}, err
	}
	if !ok {
		return TokenPair{}, domain.ErrInvalidCredentials
	}
	if needsRehash {
		// Hash parameters were raised since this password was stored. We
		// have the plaintext right now, so upgrade it. Best effort only.
		if h, err := s.hasher.Hash(ctx, password); err == nil {
			if err := s.st.UpdatePasswordHash(ctx, tr.ID, h); err != nil {
				s.log.WarnContext(ctx, "password rehash failed", "trainer_id", tr.ID, "err", err)
			}
		}
	}

	now := s.now()
	family, err := uuid.NewV7()
	if err != nil {
		return TokenPair{}, err
	}
	return s.issue(ctx, s.st, tr, family, now.Add(s.cfg.SessionTTL), userAgent)
}

// Refresh exchanges a refresh token for a new pair (rotation).
//
// Every refresh token is single-use. Presenting one that was already rotated
// means two parties hold it - the legitimate client and, probably, an
// attacker - and we can't tell which is which, so the whole family (every
// token descended from that login) is revoked and both must log in again.
// This is the reuse-detection scheme from the OAuth 2.0 Security BCP.
func (s *Auth) Refresh(ctx context.Context, rawRefresh, userAgent string) (TokenPair, error) {
	hash := auth.HashOpaqueToken(rawRefresh)
	var (
		pair   TokenPair
		reused bool
	)
	err := s.st.WithTx(ctx, func(tx *store.Store) error {
		// Row lock: two concurrent refreshes with the same token are
		// serialised, so exactly one can rotate it.
		rt, err := tx.LockRefreshTokenByHash(ctx, hash)
		if err != nil {
			return err
		}
		if rt.RevokedAt != nil {
			// Return nil so the transaction COMMITS the family revocation;
			// returning an error here would roll it back.
			reused = true
			return tx.RevokeFamily(ctx, rt.FamilyID)
		}
		if !s.now().Before(rt.ExpiresAt) {
			return domain.ErrInvalidToken
		}

		// Re-read the trainer so the new access token carries their current
		// role, not the one from when they logged in.
		tr, err := tx.TrainerByID(ctx, rt.TrainerID)
		if err != nil {
			return err
		}
		var newID uuid.UUID
		pair, newID, err = s.issueWithID(ctx, tx, tr, rt.FamilyID, rt.SessionExpiresAt, userAgent)
		if err != nil {
			return err
		}
		return tx.MarkRotated(ctx, rt.ID, newID)
	})
	if err != nil {
		return TokenPair{}, err
	}
	if reused {
		s.log.WarnContext(ctx, "refresh token reuse detected; session family revoked")
		return TokenPair{}, domain.ErrRefreshTokenReused
	}
	return pair, nil
}

// Logout revokes the session family of the given refresh token. It is
// idempotent: logging out with an unknown or already-revoked token succeeds.
func (s *Auth) Logout(ctx context.Context, rawRefresh string) error {
	fam, err := s.st.FamilyByHash(ctx, auth.HashOpaqueToken(rawRefresh))
	if errors.Is(err, domain.ErrInvalidToken) {
		return nil
	}
	if err != nil {
		return err
	}
	return s.st.RevokeFamily(ctx, fam)
}

// Me returns the authenticated trainer.
func (s *Auth) Me(ctx context.Context, a domain.Actor) (domain.Trainer, error) {
	return s.st.TrainerByID(ctx, a.ID)
}

// BootstrapAdmin creates the first admin account from configuration if it
// doesn't exist yet. It is safe to run on every start-up.
func (s *Auth) BootstrapAdmin(ctx context.Context, username, email, password string) error {
	if _, err := s.st.TrainerByUsername(ctx, username); err == nil {
		return nil
	} else if !errors.Is(err, domain.ErrTrainerNotFound) {
		return err
	}
	tr, err := s.Signup(ctx, username, email, password)
	if errors.Is(err, domain.ErrUsernameTaken) {
		return nil // another replica won the race
	}
	if err != nil {
		return err
	}
	_, err = s.st.UpdateTrainerRole(ctx, tr.ID, rbac.RoleAdmin)
	if err == nil {
		s.log.InfoContext(ctx, "bootstrap admin created", "username", username)
	}
	return err
}

func (s *Auth) issue(ctx context.Context, st *store.Store, tr domain.Trainer, family uuid.UUID,
	sessionExp time.Time, userAgent string) (TokenPair, error) {
	p, _, err := s.issueWithID(ctx, st, tr, family, sessionExp, userAgent)
	return p, err
}

func (s *Auth) issueWithID(ctx context.Context, st *store.Store, tr domain.Trainer, family uuid.UUID,
	sessionExp time.Time, userAgent string) (TokenPair, uuid.UUID, error) {
	access, accessExp, err := s.tokens.Issue(tr.ID, tr.Role)
	if err != nil {
		return TokenPair{}, uuid.Nil, err
	}
	raw, hash, err := auth.NewOpaqueToken()
	if err != nil {
		return TokenPair{}, uuid.Nil, err
	}
	id, err := uuid.NewV7()
	if err != nil {
		return TokenPair{}, uuid.Nil, err
	}
	exp := s.now().Add(s.cfg.RefreshTTL)
	if exp.After(sessionExp) {
		exp = sessionExp
	}
	rt := domain.RefreshToken{ID: id, TrainerID: tr.ID, FamilyID: family, ExpiresAt: exp, SessionExpiresAt: sessionExp}
	if err := st.InsertRefreshToken(ctx, rt, hash, userAgent); err != nil {
		return TokenPair{}, uuid.Nil, err
	}
	return TokenPair{AccessToken: access, AccessExpiresAt: accessExp, RefreshToken: raw, RefreshExpiresAt: exp}, id, nil
}
