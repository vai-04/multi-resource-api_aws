package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"pokeleague/internal/domain"
	"pokeleague/internal/rbac"
	"pokeleague/internal/service"
	"pokeleague/internal/store"
	"pokeleague/internal/testdb"
)

// TestListTournaments_KeysetPaginationFiltersAndSorting walks the list
// page by page and checks that every row appears exactly once, in order,
// including rows that share a sort value (the id tiebreaker) and rows
// inserted mid-walk (where OFFSET pagination would repeat a row).
func TestListTournaments_KeysetPaginationFiltersAndSorting(t *testing.T) {
	t.Parallel()
	pool := testdb.New(t)
	st := store.New(pool)
	league := service.NewLeague(st, 5*time.Second, nil)
	ctx := context.Background()

	host := mkTrainer(t, st, rbac.RoleGymLeader)
	base := time.Now().Add(48 * time.Hour).Truncate(time.Second)

	// 25 Kanto tournaments, in pairs that share starts_at to exercise the tiebreak,
	// plus 5 Johto ones that the region filter must exclude.
	var kanto []uuid.UUID
	for i := range 25 {
		tm, err := st.CreateTournament(ctx, domain.NewTournament{
			HostID: host.ID, Name: "Kanto Open", Region: "kanto", Type: "electric",
			Capacity: 8, StartsAt: base.Add(time.Duration(i/2) * time.Hour),
		})
		if err != nil {
			t.Fatal(err)
		}
		kanto = append(kanto, tm.ID)
	}
	for i := range 5 {
		mkTournamentIn(t, st, host, "johto", base.Add(time.Duration(i)*time.Minute))
	}

	walk := func(t *testing.T, q domain.TournamentQuery, onPage func(page int)) []domain.Tournament {
		t.Helper()
		var all []domain.Tournament
		for page := 1; ; page++ {
			p, err := league.ListTournaments(ctx, q)
			if err != nil {
				t.Fatal(err)
			}
			all = append(all, p.Items...)
			if onPage != nil {
				onPage(page)
			}
			if p.NextCursor == "" {
				return all
			}
			c, err := domain.DecodeCursor(p.NextCursor)
			if err != nil {
				t.Fatal(err)
			}
			q.Cursor = &c
		}
	}

	t.Run("ascending walk visits each row once, in order", func(t *testing.T) {
		got := walk(t, domain.TournamentQuery{Region: "kanto", Sort: domain.SortStartsAt, Limit: 4}, nil)
		if len(got) != len(kanto) {
			t.Fatalf("got %d rows, want %d", len(got), len(kanto))
		}
		seen := map[uuid.UUID]bool{}
		for i, tm := range got {
			if seen[tm.ID] {
				t.Fatalf("duplicate row %s", tm.ID)
			}
			seen[tm.ID] = true
			if tm.Region != "kanto" {
				t.Fatalf("filter leaked region %q", tm.Region)
			}
			if i > 0 {
				prev := got[i-1]
				if tm.StartsAt.Before(prev.StartsAt) ||
					(tm.StartsAt.Equal(prev.StartsAt) && tm.ID.String() < prev.ID.String()) {
					t.Fatalf("row %d out of order", i)
				}
			}
		}
	})

	t.Run("descending order is the exact reverse", func(t *testing.T) {
		asc := walk(t, domain.TournamentQuery{Region: "kanto", Sort: domain.SortStartsAt, Limit: 7}, nil)
		desc := walk(t, domain.TournamentQuery{Region: "kanto", Sort: domain.SortStartsAt, Desc: true, Limit: 7}, nil)
		for i := range asc {
			if asc[i].ID != desc[len(desc)-1-i].ID {
				t.Fatalf("position %d: descending is not the reverse of ascending", i)
			}
		}
	})

	t.Run("rows inserted mid-walk don't cause duplicates", func(t *testing.T) {
		got := walk(t, domain.TournamentQuery{Region: "kanto", Sort: domain.SortStartsAt, Limit: 5}, func(page int) {
			if page == 2 {
				// Lands on an already-visited page. With OFFSET this shifts every
				// later row by one and the next page repeats a row.
				mkTournamentIn(t, st, host, "kanto", base.Add(-time.Hour))
			}
		})
		seen := map[uuid.UUID]bool{}
		for _, tm := range got {
			if seen[tm.ID] {
				t.Fatalf("row %s returned twice", tm.ID)
			}
			seen[tm.ID] = true
		}
		if len(got) != len(kanto) {
			t.Fatalf("got %d rows, want %d", len(got), len(kanto))
		}
	})

	t.Run("has_spots filter and cursor/sort mismatch", func(t *testing.T) {
		if _, err := pool.Exec(ctx, `UPDATE tournaments SET registered_count = capacity WHERE id = $1`, kanto[0]); err != nil {
			t.Fatal(err)
		}
		got := walk(t, domain.TournamentQuery{Region: "kanto", HasSpots: true, Sort: domain.SortStartsAt, Limit: 50}, nil)
		for _, tm := range got {
			if tm.ID == kanto[0] {
				t.Fatal("full tournament returned with has_spots=true")
			}
		}

		p, err := league.ListTournaments(ctx, domain.TournamentQuery{Sort: domain.SortStartsAt, Limit: 2})
		if err != nil {
			t.Fatal(err)
		}
		c, _ := domain.DecodeCursor(p.NextCursor)
		_, err = league.ListTournaments(ctx, domain.TournamentQuery{Sort: domain.SortName, Cursor: &c})
		if !errors.Is(err, domain.ErrValidation) {
			t.Fatalf("cursor reused with a different sort: got %v, want validation error", err)
		}
	})
}

func mkTournamentIn(t *testing.T, st *store.Store, host domain.Actor, region string, startsAt time.Time) {
	t.Helper()
	if _, err := st.CreateTournament(context.Background(), domain.NewTournament{
		HostID: host.ID, Name: "Late Entry", Region: region, Type: "water", Capacity: 4, StartsAt: startsAt,
	}); err != nil {
		t.Fatal(err)
	}
}
