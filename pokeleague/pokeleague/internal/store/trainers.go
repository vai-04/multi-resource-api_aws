package store

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pokeleague/internal/domain"
	"pokeleague/internal/rbac"
)

const trainerCols = `id, username, email, password_hash, role, created_at, updated_at`

func scanTrainer(row pgx.Row) (domain.Trainer, error) {
	var t domain.Trainer
	var role string
	err := row.Scan(&t.ID, &t.Username, &t.Email, &t.PasswordHash, &role, &t.CreatedAt, &t.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return t, domain.ErrTrainerNotFound
	}
	t.Role = rbac.Role(role)
	return t, mapErr(err)
}

// CreateTrainer inserts a trainer. Uniqueness is enforced by the database,
// not by a prior "does this username exist?" query, which would race.
func (s *Store) CreateTrainer(ctx context.Context, username, email, passwordHash string, role rbac.Role) (domain.Trainer, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return domain.Trainer{}, err
	}
	t, err := scanTrainer(s.db.QueryRow(ctx,
		`INSERT INTO trainers (id, username, email, password_hash, role)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING `+trainerCols,
		id, username, email, passwordHash, string(role)))
	if pe := pgError(err); pe != nil && pe.Code == pgUniqueViolation {
		switch pe.ConstraintName {
		case "trainers_username_lower_key":
			return t, domain.ErrUsernameTaken
		case "trainers_email_lower_key":
			return t, domain.ErrEmailTaken
		}
	}
	return t, err
}

func (s *Store) TrainerByID(ctx context.Context, id uuid.UUID) (domain.Trainer, error) {
	return scanTrainer(s.db.QueryRow(ctx, `SELECT `+trainerCols+` FROM trainers WHERE id = $1`, id))
}

// TrainerByUsername looks a trainer up case-insensitively; the predicate
// matches the lower(username) unique index.
func (s *Store) TrainerByUsername(ctx context.Context, username string) (domain.Trainer, error) {
	return scanTrainer(s.db.QueryRow(ctx,
		`SELECT `+trainerCols+` FROM trainers WHERE lower(username) = lower($1)`, username))
}

func (s *Store) UpdateTrainerRole(ctx context.Context, id uuid.UUID, role rbac.Role) (domain.Trainer, error) {
	return scanTrainer(s.db.QueryRow(ctx,
		`UPDATE trainers SET role = $2, updated_at = now() WHERE id = $1 RETURNING `+trainerCols,
		id, string(role)))
}

func (s *Store) UpdatePasswordHash(ctx context.Context, id uuid.UUID, hash string) error {
	_, err := s.db.Exec(ctx, `UPDATE trainers SET password_hash = $2, updated_at = now() WHERE id = $1`, id, hash)
	return mapErr(err)
}
