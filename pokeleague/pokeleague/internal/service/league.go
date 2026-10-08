// Package service implements the league's use cases: who may do what, and
// the business rules around tournaments and registrations. It coordinates
// the store inside transactions but contains no SQL.
package service

import (
	"context"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"pokeleague/internal/domain"
	"pokeleague/internal/rbac"
	"pokeleague/internal/store"
)

// League manages tournaments, registrations and roles.
type League struct {
	st          *store.Store
	now         func() time.Time
	lockTimeout time.Duration
}

func NewLeague(st *store.Store, lockTimeout time.Duration, now func() time.Time) *League {
	if now == nil {
		now = time.Now
	}
	return &League{st: st, now: now, lockTimeout: lockTimeout}
}

// canManage is the ownership-aware policy: admins manage any tournament,
// gym leaders only the ones they host.
func canManage(a domain.Actor, t domain.Tournament) bool {
	return a.Role.Can(rbac.PermTournamentManageAny) ||
		(a.Role.Can(rbac.PermTournamentManageOwn) && t.HostID == a.ID)
}

// CreateTournament creates a tournament hosted by the actor.
func (l *League) CreateTournament(ctx context.Context, a domain.Actor, in domain.NewTournament) (domain.Tournament, error) {
	// The router already checks this permission; checking again here keeps the
	// rule true for every caller (a CLI, a queue consumer, a test), not just HTTP.
	if !a.Role.Can(rbac.PermTournamentCreate) {
		return domain.Tournament{}, domain.ErrForbidden
	}
	in.HostID = a.ID
	in.Name = strings.TrimSpace(in.Name)
	in.Description = strings.TrimSpace(in.Description)
	in.Region = strings.ToLower(strings.TrimSpace(in.Region))
	in.Type = strings.ToLower(strings.TrimSpace(in.Type))

	f := fieldErrors{}
	f.checkLen("name", in.Name, 3, 100)
	f.checkLen("description", in.Description, 0, 2000)
	if !domain.IsRegion(in.Region) {
		f["region"] = "must be one of: " + strings.Join(domain.Regions, ", ")
	}
	if !domain.IsType(in.Type) {
		f["type"] = "must be a Pokémon type, e.g. fire, water, grass"
	}
	f.checkCapacity(in.Capacity)
	if in.StartsAt.IsZero() || !in.StartsAt.After(l.now()) {
		f["starts_at"] = "must be in the future"
	}
	if err := f.err(); err != nil {
		return domain.Tournament{}, err
	}
	return l.st.CreateTournament(ctx, in)
}

func (l *League) GetTournament(ctx context.Context, id uuid.UUID) (domain.Tournament, error) {
	return l.st.TournamentByID(ctx, id)
}

// UpdateTournament applies a partial update. The row is locked first so the
// "capacity >= registered_count" check can't race with a registration.
func (l *League) UpdateTournament(ctx context.Context, a domain.Actor, id uuid.UUID, p domain.TournamentPatch) (domain.Tournament, error) {
	f := fieldErrors{}
	if p.Name != nil {
		*p.Name = strings.TrimSpace(*p.Name)
		f.checkLen("name", *p.Name, 3, 100)
	}
	if p.Description != nil {
		*p.Description = strings.TrimSpace(*p.Description)
		f.checkLen("description", *p.Description, 0, 2000)
	}
	if p.Capacity != nil {
		f.checkCapacity(*p.Capacity)
	}
	if p.Status != nil && !p.Status.Valid() {
		f["status"] = "must be one of: open, closed, cancelled"
	}
	if p.StartsAt != nil && !p.StartsAt.After(l.now()) {
		f["starts_at"] = "must be in the future"
	}
	if err := f.err(); err != nil {
		return domain.Tournament{}, err
	}

	var out domain.Tournament
	err := l.st.WithTx(ctx, func(tx *store.Store) error {
		if err := tx.SetLockTimeout(ctx, l.lockTimeout); err != nil {
			return err
		}
		t, err := tx.LockTournament(ctx, id)
		if err != nil {
			return err
		}
		if !canManage(a, t) {
			return domain.ErrForbidden
		}
		if t.Status == domain.StatusCancelled {
			return domain.ErrTournamentCancelled
		}
		if p.Capacity != nil && *p.Capacity < t.RegisteredCount {
			return domain.ErrCapacityBelowRegistered
		}
		out, err = tx.UpdateTournament(ctx, id, p)
		return err
	})
	return out, err
}

// ListTournaments returns one page of tournaments.
func (l *League) ListTournaments(ctx context.Context, q domain.TournamentQuery) (domain.Page[domain.Tournament], error) {
	if q.Sort == "" {
		q.Sort = domain.SortStartsAt
	}
	if q.Limit <= 0 {
		q.Limit = domain.DefaultPageSize
	}
	q.Limit = min(q.Limit, domain.MaxPageSize)
	if q.Cursor != nil && (q.Cursor.Sort != q.Sort || q.Cursor.Desc != q.Desc) {
		return domain.Page[domain.Tournament]{}, domain.Validation(map[string]string{
			"cursor": "cursor was issued for a different sort order",
		})
	}

	rows, err := l.st.ListTournaments(ctx, q)
	if err != nil {
		return domain.Page[domain.Tournament]{}, err
	}
	page := domain.Page[domain.Tournament]{Items: rows}
	if len(rows) > q.Limit {
		page.Items = rows[:q.Limit]
		page.NextCursor = domain.CursorFor(page.Items[q.Limit-1], q.Sort, q.Desc).Encode()
	}
	return page, nil
}

// Register signs the actor up for a tournament.
//
// This is the concurrency-critical path. The naive version
//
//	t := get(id); if t.count < t.capacity { insert(); t.count++ }
//
// races: two requests both read count=capacity-1, both pass the check, and
// both insert. Here the check and the write happen inside one transaction
// that first takes a row lock on the tournament (SELECT ... FOR UPDATE).
// Concurrent registrations for the same tournament queue on that lock and
// each sees the count committed by the one before it, so at most `capacity`
// of them can succeed. Registrations for different tournaments lock
// different rows and don't block each other.
func (l *League) Register(ctx context.Context, a domain.Actor, tournamentID uuid.UUID, leadPokemon string) (domain.Registration, error) {
	if !a.Role.Can(rbac.PermTournamentRegister) {
		return domain.Registration{}, domain.ErrForbidden
	}
	leadPokemon = strings.TrimSpace(leadPokemon)
	f := fieldErrors{}
	f.checkLen("lead_pokemon", leadPokemon, 1, 40)
	if err := f.err(); err != nil {
		return domain.Registration{}, err
	}

	var reg domain.Registration
	err := l.st.WithTx(ctx, func(tx *store.Store) error {
		if err := tx.SetLockTimeout(ctx, l.lockTimeout); err != nil {
			return err
		}
		t, err := tx.LockTournament(ctx, tournamentID) // <- the serialisation point
		if err != nil {
			return err
		}
		switch {
		case t.HostID == a.ID:
			return domain.ErrHostCannotRegister
		case !t.AcceptsRegistrations(l.now()):
			return domain.ErrRegistrationClosed
		case t.RegisteredCount >= t.Capacity:
			return domain.ErrTournamentFull
		}
		if reg, err = tx.InsertRegistration(ctx, tournamentID, a.ID, leadPokemon); err != nil {
			return err
		}
		return tx.AdjustRegisteredCount(ctx, tournamentID, +1)
	})
	return reg, err
}

// Withdraw removes the actor's registration and frees the spot. It takes the
// same lock as Register, in the same order (tournament row first), so the
// two can't deadlock and the counter stays exact.
func (l *League) Withdraw(ctx context.Context, a domain.Actor, tournamentID uuid.UUID) error {
	return l.st.WithTx(ctx, func(tx *store.Store) error {
		if err := tx.SetLockTimeout(ctx, l.lockTimeout); err != nil {
			return err
		}
		t, err := tx.LockTournament(ctx, tournamentID)
		if err != nil {
			return err
		}
		if !l.now().Before(t.StartsAt) {
			return domain.ErrRegistrationClosed // the tournament has started
		}
		deleted, err := tx.DeleteRegistration(ctx, tournamentID, a.ID)
		if err != nil {
			return err
		}
		if !deleted {
			return domain.ErrRegistrationNotFound
		}
		return tx.AdjustRegisteredCount(ctx, tournamentID, -1)
	})
}

// Roster lists the registered trainers. Only the host or an admin may see it.
func (l *League) Roster(ctx context.Context, a domain.Actor, tournamentID uuid.UUID) ([]domain.Registration, error) {
	t, err := l.st.TournamentByID(ctx, tournamentID)
	if err != nil {
		return nil, err
	}
	if !canManage(a, t) {
		return nil, domain.ErrForbidden
	}
	return l.st.RegistrationsForTournament(ctx, tournamentID)
}

func (l *League) MyRegistrations(ctx context.Context, a domain.Actor) ([]domain.Registration, error) {
	return l.st.RegistrationsForTrainer(ctx, a.ID)
}

// SetRole changes a trainer's role (admin only). Their existing refresh
// tokens are revoked so the change can't be outlived by an old session; the
// access token they hold stays valid until it expires (at most the access
// TTL), which is the accepted trade-off of stateless access tokens.
func (l *League) SetRole(ctx context.Context, a domain.Actor, trainerID uuid.UUID, role rbac.Role) (domain.Trainer, error) {
	if !a.Role.Can(rbac.PermTrainerManageRoles) {
		return domain.Trainer{}, domain.ErrForbidden
	}
	if !role.Valid() {
		return domain.Trainer{}, domain.Validation(map[string]string{"role": "must be one of: trainer, gym_leader, admin"})
	}
	if trainerID == a.ID {
		return domain.Trainer{}, domain.ErrCannotChangeOwnRole // prevents the last admin locking everyone out
	}
	var out domain.Trainer
	err := l.st.WithTx(ctx, func(tx *store.Store) error {
		var err error
		if out, err = tx.UpdateTrainerRole(ctx, trainerID, role); err != nil {
			return err
		}
		return tx.RevokeAllForTrainer(ctx, trainerID)
	})
	return out, err
}

// fieldErrors accumulates validation failures so clients get every problem
// in one response instead of fixing them one round trip at a time.
type fieldErrors map[string]string

func (f fieldErrors) checkLen(field, v string, minLen, maxLen int) {
	n := utf8.RuneCountInString(v)
	switch {
	case n < minLen && minLen == 1:
		f[field] = "is required"
	case n < minLen || n > maxLen:
		f[field] = "must be between " + strconv.Itoa(minLen) + " and " + strconv.Itoa(maxLen) + " characters"
	}
}

func (f fieldErrors) checkCapacity(c int) {
	if c < domain.MinCapacity || c > domain.MaxCapacity {
		f["capacity"] = "must be between " + strconv.Itoa(domain.MinCapacity) + " and " + strconv.Itoa(domain.MaxCapacity)
	}
}

func (f fieldErrors) err() error {
	if len(f) == 0 {
		return nil
	}
	return domain.Validation(f)
}
