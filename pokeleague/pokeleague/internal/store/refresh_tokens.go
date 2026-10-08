package store

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pokeleague/internal/domain"
)

func (s *Store) InsertRefreshToken(ctx context.Context, rt domain.RefreshToken, hash []byte, userAgent string) error {
	_, err := s.db.Exec(ctx, `
		INSERT INTO refresh_tokens (id, trainer_id, family_id, token_hash, expires_at, session_expires_at, user_agent)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		rt.ID, rt.TrainerID, rt.FamilyID, hash, rt.ExpiresAt, rt.SessionExpiresAt, truncate(userAgent, 256))
	return mapErr(err)
}

// LockRefreshTokenByHash fetches a refresh token and locks its row. Two
// concurrent refreshes with the same token are serialised: the second one
// sees the token already rotated (revoked) and is treated as reuse.
func (s *Store) LockRefreshTokenByHash(ctx context.Context, hash []byte) (domain.RefreshToken, error) {
	if s.pool != nil {
		return domain.RefreshToken{}, errors.New("store: LockRefreshTokenByHash must be called inside a transaction")
	}
	var rt domain.RefreshToken
	err := s.db.QueryRow(ctx, `
		SELECT id, trainer_id, family_id, expires_at, session_expires_at, revoked_at, replaced_by
		FROM refresh_tokens WHERE token_hash = $1
		FOR UPDATE`, hash,
	).Scan(&rt.ID, &rt.TrainerID, &rt.FamilyID, &rt.ExpiresAt, &rt.SessionExpiresAt, &rt.RevokedAt, &rt.ReplacedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return rt, domain.ErrInvalidToken
	}
	return rt, mapErr(err)
}

// FamilyByHash returns the family of a token without locking (used by logout).
func (s *Store) FamilyByHash(ctx context.Context, hash []byte) (uuid.UUID, error) {
	var fam uuid.UUID
	err := s.db.QueryRow(ctx, `SELECT family_id FROM refresh_tokens WHERE token_hash = $1`, hash).Scan(&fam)
	if errors.Is(err, pgx.ErrNoRows) {
		return fam, domain.ErrInvalidToken
	}
	return fam, mapErr(err)
}

// MarkRotated revokes a token and links it to its successor.
func (s *Store) MarkRotated(ctx context.Context, id, replacedBy uuid.UUID) error {
	_, err := s.db.Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at = now(), replaced_by = $2 WHERE id = $1`, id, replacedBy)
	return mapErr(err)
}

// RevokeFamily revokes every still-active token descended from one login.
func (s *Store) RevokeFamily(ctx context.Context, familyID uuid.UUID) error {
	_, err := s.db.Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at = now() WHERE family_id = $1 AND revoked_at IS NULL`, familyID)
	return mapErr(err)
}

// RevokeAllForTrainer ends every session of a trainer (e.g. after a role
// change or a password reset).
func (s *Store) RevokeAllForTrainer(ctx context.Context, trainerID uuid.UUID) error {
	_, err := s.db.Exec(ctx,
		`UPDATE refresh_tokens SET revoked_at = now() WHERE trainer_id = $1 AND revoked_at IS NULL`, trainerID)
	return mapErr(err)
}

// DeleteExpiredRefreshTokens garbage-collects whole families whose absolute
// session lifetime ended. Revoked-but-unexpired rows are kept on purpose:
// they are what lets us detect reuse of a stolen token.
func (s *Store) DeleteExpiredRefreshTokens(ctx context.Context) (int64, error) {
	tag, err := s.db.Exec(ctx, `DELETE FROM refresh_tokens WHERE session_expires_at < now()`)
	if err != nil {
		return 0, mapErr(err)
	}
	return tag.RowsAffected(), nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// Don't cut a multi-byte rune in half.
	for n > 0 && (s[n]&0xC0) == 0x80 {
		n--
	}
	return s[:n]
}
