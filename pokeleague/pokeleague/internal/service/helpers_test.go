package service_test

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"pokeleague/internal/domain"
	"pokeleague/internal/rbac"
	"pokeleague/internal/store"
)

var seq atomic.Int64

// mkTrainer inserts a trainer directly (no password hashing - these tests
// aren't about login) and returns it as an Actor.
func mkTrainer(t *testing.T, st *store.Store, role rbac.Role) domain.Actor {
	t.Helper()
	n := seq.Add(1)
	tr, err := st.CreateTrainer(context.Background(),
		fmt.Sprintf("trainer_%d", n), fmt.Sprintf("trainer%d@league.test", n), "not-a-real-hash", role)
	if err != nil {
		t.Fatalf("creating trainer: %v", err)
	}
	return domain.Actor{ID: tr.ID, Role: tr.Role}
}

func mkTournament(t *testing.T, st *store.Store, host domain.Actor, capacity int, startsAt time.Time) domain.Tournament {
	t.Helper()
	tm, err := st.CreateTournament(context.Background(), domain.NewTournament{
		HostID: host.ID, Name: "Indigo Plateau Cup", Region: "kanto", Type: "fire",
		Capacity: capacity, StartsAt: startsAt,
	})
	if err != nil {
		t.Fatalf("creating tournament: %v", err)
	}
	return tm
}
