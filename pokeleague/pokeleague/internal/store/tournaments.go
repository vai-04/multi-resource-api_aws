package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pokeleague/internal/domain"
)

const tournamentCols = `t.id, t.host_id, h.username, t.name, t.description, t.region, t.pokemon_type,
	t.capacity, t.registered_count, t.status, t.starts_at, t.created_at, t.updated_at`

func scanTournament(row pgx.Row) (domain.Tournament, error) {
	var t domain.Tournament
	var status string
	err := row.Scan(&t.ID, &t.HostID, &t.HostUsername, &t.Name, &t.Description, &t.Region, &t.Type,
		&t.Capacity, &t.RegisteredCount, &status, &t.StartsAt, &t.CreatedAt, &t.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return t, domain.ErrTournamentNotFound
	}
	t.Status = domain.TournamentStatus(status)
	return t, mapErr(err)
}

func (s *Store) CreateTournament(ctx context.Context, in domain.NewTournament) (domain.Tournament, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return domain.Tournament{}, err
	}
	// The CTE returns the inserted row joined with its host in one round trip.
	return scanTournament(s.db.QueryRow(ctx, `
		WITH t AS (
			INSERT INTO tournaments (id, host_id, name, description, region, pokemon_type, capacity, starts_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			RETURNING *
		)
		SELECT `+tournamentCols+` FROM t JOIN trainers h ON h.id = t.host_id`,
		id, in.HostID, in.Name, in.Description, in.Region, in.Type, in.Capacity, in.StartsAt))
}

func (s *Store) TournamentByID(ctx context.Context, id uuid.UUID) (domain.Tournament, error) {
	return scanTournament(s.db.QueryRow(ctx,
		`SELECT `+tournamentCols+` FROM tournaments t JOIN trainers h ON h.id = t.host_id WHERE t.id = $1`, id))
}

// LockTournament reads a tournament and takes a row-level exclusive lock on
// it until the surrounding transaction ends. Any other transaction calling
// LockTournament (or UPDATE-ing the row) for the same id blocks here, which
// serialises every write that depends on capacity/registered_count.
//
// "FOR UPDATE OF t" locks only the tournament row, not the joined host row,
// so registrations don't contend with, say, the host changing their password.
func (s *Store) LockTournament(ctx context.Context, id uuid.UUID) (domain.Tournament, error) {
	if s.pool != nil {
		return domain.Tournament{}, errors.New("store: LockTournament must be called inside a transaction")
	}
	return scanTournament(s.db.QueryRow(ctx,
		`SELECT `+tournamentCols+` FROM tournaments t JOIN trainers h ON h.id = t.host_id
		 WHERE t.id = $1
		 FOR UPDATE OF t`, id))
}

// UpdateTournament applies a partial update; NULL parameters keep the
// current value.
func (s *Store) UpdateTournament(ctx context.Context, id uuid.UUID, p domain.TournamentPatch) (domain.Tournament, error) {
	var status *string
	if p.Status != nil {
		v := string(*p.Status)
		status = &v
	}
	t, err := scanTournament(s.db.QueryRow(ctx, `
		WITH t AS (
			UPDATE tournaments SET
				name        = COALESCE($2::text, name),
				description = COALESCE($3::text, description),
				capacity    = COALESCE($4::int, capacity),
				status      = COALESCE($5::text, status),
				starts_at   = COALESCE($6::timestamptz, starts_at),
				updated_at  = now()
			WHERE id = $1
			RETURNING *
		)
		SELECT `+tournamentCols+` FROM t JOIN trainers h ON h.id = t.host_id`,
		id, p.Name, p.Description, p.Capacity, status, p.StartsAt))
	if pe := pgError(err); pe != nil && pe.Code == pgCheckViolation &&
		pe.ConstraintName == "tournaments_registered_count_within_capacity" {
		return t, domain.ErrCapacityBelowRegistered
	}
	return t, err
}

// AdjustRegisteredCount changes registered_count by delta. If the CHECK
// constraint rejects the result, the tournament is full: this is the
// database-level backstop behind the application's own capacity check.
func (s *Store) AdjustRegisteredCount(ctx context.Context, id uuid.UUID, delta int) error {
	tag, err := s.db.Exec(ctx,
		`UPDATE tournaments SET registered_count = registered_count + $2, updated_at = now() WHERE id = $1`,
		id, delta)
	if pe := pgError(err); pe != nil && pe.Code == pgCheckViolation {
		return domain.ErrTournamentFull
	}
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return domain.ErrTournamentNotFound
	}
	return nil
}

// sortColumns is the whitelist mapping API sort fields to SQL expressions.
var sortColumns = map[domain.SortField]string{
	domain.SortStartsAt:  "t.starts_at",
	domain.SortCreatedAt: "t.created_at",
	domain.SortName:      "t.name",
}

// ListTournaments returns up to q.Limit+1 rows (the extra row tells the
// caller whether another page exists) using keyset pagination.
//
// Keyset ("seek") pagination filters on the last row seen instead of using
// OFFSET. OFFSET n makes Postgres read and discard n rows, so page 1,000 is
// slow; and if rows are inserted while a client pages, OFFSET shifts and the
// client sees duplicates or misses rows. A keyset cursor has neither problem.
func (s *Store) ListTournaments(ctx context.Context, q domain.TournamentQuery) ([]domain.Tournament, error) {
	col, ok := sortColumns[q.Sort]
	if !ok {
		return nil, fmt.Errorf("store: unsupported sort %q", q.Sort)
	}

	var (
		where []string
		args  []any
	)
	arg := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}

	if q.Region != "" {
		where = append(where, "t.region = "+arg(q.Region))
	}
	if q.Type != "" {
		where = append(where, "t.pokemon_type = "+arg(q.Type))
	}
	if q.Status != "" {
		where = append(where, "t.status = "+arg(string(q.Status)))
	}
	if q.HostID != nil {
		where = append(where, "t.host_id = "+arg(*q.HostID))
	}
	if q.StartsAfter != nil {
		where = append(where, "t.starts_at >= "+arg(*q.StartsAfter))
	}
	if q.StartsBefore != nil {
		where = append(where, "t.starts_at < "+arg(*q.StartsBefore))
	}
	if q.HasSpots {
		where = append(where, "t.registered_count < t.capacity")
	}

	dir, cmp := "ASC", ">"
	if q.Desc {
		dir, cmp = "DESC", "<"
	}

	if c := q.Cursor; c != nil {
		var v any = c.Value
		if q.Sort != domain.SortName {
			ts, err := time.Parse(time.RFC3339Nano, c.Value)
			if err != nil {
				return nil, domain.ErrValidation
			}
			v = ts
		}
		// Row-value comparison: (a, b) > (x, y) means a > x OR (a = x AND b > y).
		where = append(where, fmt.Sprintf("(%s, t.id) %s (%s, %s)", col, cmp, arg(v), arg(c.ID)))
	}

	var sb strings.Builder
	sb.WriteString(`SELECT ` + tournamentCols + ` FROM tournaments t JOIN trainers h ON h.id = t.host_id`)
	if len(where) > 0 {
		sb.WriteString(" WHERE " + strings.Join(where, " AND "))
	}
	fmt.Fprintf(&sb, " ORDER BY %s %s, t.id %s LIMIT %s", col, dir, dir, arg(q.Limit+1))

	rows, err := s.db.Query(ctx, sb.String(), args...)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()

	var out []domain.Tournament
	for rows.Next() {
		t, err := scanTournament(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, mapErr(rows.Err())
}
