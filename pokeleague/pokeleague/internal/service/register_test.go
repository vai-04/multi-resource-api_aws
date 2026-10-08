package service_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"pokeleague/internal/domain"
	"pokeleague/internal/rbac"
	"pokeleague/internal/service"
	"pokeleague/internal/store"
	"pokeleague/internal/testdb"
)

// TestRegister_ConcurrentRequestsNeverExceedCapacity fires many registrations
// at a small tournament at the same instant and checks the invariant that
// matters: exactly `capacity` succeed, everyone else is told it's full, and
// the denormalised counter agrees with the real number of join rows.
//
// With a check-then-write implementation (no lock) this test fails
// intermittently with more than `capacity` winners.
func TestRegister_ConcurrentRequestsNeverExceedCapacity(t *testing.T) {
	t.Parallel()
	pool := testdb.New(t)
	st := store.New(pool)
	league := service.NewLeague(st, 5*time.Second, nil)
	ctx := context.Background()

	t.Run("many trainers race for the last spots", func(t *testing.T) {
		const capacity, contenders = 5, 40

		host := mkTrainer(t, st, rbac.RoleGymLeader)
		tm := mkTournament(t, st, host, capacity, time.Now().Add(24*time.Hour))
		trainers := make([]domain.Actor, contenders)
		for i := range trainers {
			trainers[i] = mkTrainer(t, st, rbac.RoleTrainer)
		}

		var (
			start = make(chan struct{})
			wg    sync.WaitGroup
			errs  = make([]error, contenders)
		)
		for i, tr := range trainers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start // release every goroutine at once to maximise contention
				_, errs[i] = league.Register(ctx, tr, tm.ID, "Charizard")
			}()
		}
		close(start)
		wg.Wait()

		var ok, full int
		for _, err := range errs {
			switch {
			case err == nil:
				ok++
			case errors.Is(err, domain.ErrTournamentFull):
				full++
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}
		if ok != capacity || full != contenders-capacity {
			t.Fatalf("got %d registered / %d full, want %d / %d", ok, full, capacity, contenders-capacity)
		}

		got, err := st.TournamentByID(ctx, tm.ID)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := st.CountRegistrations(ctx, tm.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.RegisteredCount != capacity || rows != capacity {
			t.Fatalf("registered_count=%d, join rows=%d, want both %d", got.RegisteredCount, rows, capacity)
		}
	})

	t.Run("one trainer double-submitting gets exactly one registration", func(t *testing.T) {
		const attempts = 10

		host := mkTrainer(t, st, rbac.RoleGymLeader)
		tm := mkTournament(t, st, host, 8, time.Now().Add(24*time.Hour))
		me := mkTrainer(t, st, rbac.RoleTrainer)

		var (
			start = make(chan struct{})
			wg    sync.WaitGroup
			errs  = make([]error, attempts)
		)
		for i := range attempts {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, errs[i] = league.Register(ctx, me, tm.ID, "Pikachu")
			}()
		}
		close(start)
		wg.Wait()

		var ok, dup int
		for _, err := range errs {
			switch {
			case err == nil:
				ok++
			case errors.Is(err, domain.ErrAlreadyRegistered):
				dup++
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}
		if ok != 1 || dup != attempts-1 {
			t.Fatalf("got %d ok / %d duplicate, want 1 / %d", ok, dup, attempts-1)
		}
		// A failed duplicate must not have bumped the counter (its
		// transaction rolled back as a whole).
		got, _ := st.TournamentByID(ctx, tm.ID)
		if got.RegisteredCount != 1 {
			t.Fatalf("registered_count = %d, want 1", got.RegisteredCount)
		}
	})

	t.Run("withdrawing frees a spot for the next trainer", func(t *testing.T) {
		host := mkTrainer(t, st, rbac.RoleGymLeader)
		tm := mkTournament(t, st, host, 2, time.Now().Add(24*time.Hour))
		a, b, c := mkTrainer(t, st, rbac.RoleTrainer), mkTrainer(t, st, rbac.RoleTrainer), mkTrainer(t, st, rbac.RoleTrainer)

		for _, tr := range []domain.Actor{a, b} {
			if _, err := league.Register(ctx, tr, tm.ID, "Squirtle"); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := league.Register(ctx, c, tm.ID, "Bulbasaur"); !errors.Is(err, domain.ErrTournamentFull) {
			t.Fatalf("third registration: got %v, want ErrTournamentFull", err)
		}
		if err := league.Withdraw(ctx, a, tm.ID); err != nil {
			t.Fatal(err)
		}
		if _, err := league.Register(ctx, c, tm.ID, "Bulbasaur"); err != nil {
			t.Fatalf("registration after withdrawal: %v", err)
		}
		if _, err := league.Register(ctx, host, tm.ID, "Arcanine"); !errors.Is(err, domain.ErrHostCannotRegister) {
			t.Fatalf("host registering: got %v, want ErrHostCannotRegister", err)
		}
	})
}
