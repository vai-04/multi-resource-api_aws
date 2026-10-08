package store

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pokeleague/internal/domain"
)

// InsertRegistration creates the join row. The UNIQUE (tournament_id,
// trainer_id) constraint turns a duplicate into ErrAlreadyRegistered even
// if two requests from the same trainer race.
func (s *Store) InsertRegistration(ctx context.Context, tournamentID, trainerID uuid.UUID, leadPokemon string) (domain.Registration, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return domain.Registration{}, err
	}
	var r domain.Registration
	err = s.db.QueryRow(ctx, `
		WITH r AS (
			INSERT INTO registrations (id, tournament_id, trainer_id, lead_pokemon)
			VALUES ($1, $2, $3, $4)
			RETURNING *
		)
		SELECT r.id, r.tournament_id, t.name, r.trainer_id, tr.username, r.lead_pokemon, r.created_at
		FROM r
		JOIN tournaments t ON t.id = r.tournament_id
		JOIN trainers tr   ON tr.id = r.trainer_id`,
		id, tournamentID, trainerID, leadPokemon,
	).Scan(&r.ID, &r.TournamentID, &r.TournamentName, &r.TrainerID, &r.TrainerUsername, &r.LeadPokemon, &r.CreatedAt)
	if pe := pgError(err); pe != nil && pe.Code == pgUniqueViolation {
		return r, domain.ErrAlreadyRegistered
	}
	return r, mapErr(err)
}

// DeleteRegistration removes the trainer's registration and reports whether
// one existed.
func (s *Store) DeleteRegistration(ctx context.Context, tournamentID, trainerID uuid.UUID) (bool, error) {
	tag, err := s.db.Exec(ctx,
		`DELETE FROM registrations WHERE tournament_id = $1 AND trainer_id = $2`, tournamentID, trainerID)
	if err != nil {
		return false, mapErr(err)
	}
	return tag.RowsAffected() == 1, nil
}

const registrationSelect = `
	SELECT r.id, r.tournament_id, t.name, r.trainer_id, tr.username, r.lead_pokemon, r.created_at
	FROM registrations r
	JOIN tournaments t ON t.id = r.tournament_id
	JOIN trainers tr   ON tr.id = r.trainer_id`

func collectRegistrations(rows pgx.Rows, err error) ([]domain.Registration, error) {
	if err != nil {
		return nil, mapErr(err)
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (domain.Registration, error) {
		var r domain.Registration
		err := row.Scan(&r.ID, &r.TournamentID, &r.TournamentName, &r.TrainerID, &r.TrainerUsername, &r.LeadPokemon, &r.CreatedAt)
		return r, err
	})
	return out, mapErr(err)
}

// RegistrationsForTournament returns the roster in sign-up order. It is
// bounded by the tournament's capacity (max 1024), so it isn't paginated.
func (s *Store) RegistrationsForTournament(ctx context.Context, tournamentID uuid.UUID) ([]domain.Registration, error) {
	return collectRegistrations(s.db.Query(ctx,
		registrationSelect+` WHERE r.tournament_id = $1 ORDER BY r.created_at, r.id`, tournamentID))
}

// RegistrationsForTrainer returns the trainer's registrations, newest first.
func (s *Store) RegistrationsForTrainer(ctx context.Context, trainerID uuid.UUID) ([]domain.Registration, error) {
	return collectRegistrations(s.db.Query(ctx,
		registrationSelect+` WHERE r.trainer_id = $1 ORDER BY r.created_at DESC, r.id DESC LIMIT 200`, trainerID))
}

// CountRegistrations counts join rows directly (used by tests to verify the
// denormalised counter).
func (s *Store) CountRegistrations(ctx context.Context, tournamentID uuid.UUID) (int, error) {
	var n int
	err := s.db.QueryRow(ctx, `SELECT count(*) FROM registrations WHERE tournament_id = $1`, tournamentID).Scan(&n)
	return n, mapErr(err)
}
