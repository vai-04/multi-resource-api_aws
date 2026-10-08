// Package domain holds the core types of the Pokémon League and the rules
// that do not depend on storage or transport.
package domain

import (
	"time"

	"github.com/google/uuid"

	"pokeleague/internal/rbac"
)

// Actor is the authenticated caller of an operation.
type Actor struct {
	ID   uuid.UUID
	Role rbac.Role
}

// Trainer is a league account. Every account is a trainer; the role decides
// what else it may do.
type Trainer struct {
	ID           uuid.UUID
	Username     string
	Email        string
	PasswordHash string
	Role         rbac.Role
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// TournamentStatus is the lifecycle state of a tournament.
type TournamentStatus string

const (
	StatusOpen      TournamentStatus = "open"
	StatusClosed    TournamentStatus = "closed"
	StatusCancelled TournamentStatus = "cancelled"
)

func (s TournamentStatus) Valid() bool {
	return s == StatusOpen || s == StatusClosed || s == StatusCancelled
}

// Tournament is a capacity-limited event hosted by a gym leader.
type Tournament struct {
	ID              uuid.UUID
	HostID          uuid.UUID
	HostUsername    string
	Name            string
	Description     string
	Region          string
	Type            string // the gym's Pokémon type, e.g. "water"
	Capacity        int
	RegisteredCount int
	Status          TournamentStatus
	StartsAt        time.Time
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

// SpotsLeft is the number of registrations the tournament can still accept.
func (t Tournament) SpotsLeft() int { return max(0, t.Capacity-t.RegisteredCount) }

// AcceptsRegistrations reports whether a trainer could register at time now,
// ignoring capacity.
func (t Tournament) AcceptsRegistrations(now time.Time) bool {
	return t.Status == StatusOpen && now.Before(t.StartsAt)
}

// NewTournament is the input for creating a tournament.
type NewTournament struct {
	HostID      uuid.UUID
	Name        string
	Description string
	Region      string
	Type        string
	Capacity    int
	StartsAt    time.Time
}

// TournamentPatch is a partial update; nil fields are left unchanged.
type TournamentPatch struct {
	Name        *string
	Description *string
	Capacity    *int
	Status      *TournamentStatus
	StartsAt    *time.Time
}

// Registration links a trainer to a tournament (the join table).
type Registration struct {
	ID              uuid.UUID
	TournamentID    uuid.UUID
	TournamentName  string
	TrainerID       uuid.UUID
	TrainerUsername string
	LeadPokemon     string
	CreatedAt       time.Time
}

// RefreshToken is the server-side record of an issued refresh token. The raw
// token is never stored, only its SHA-256 hash.
type RefreshToken struct {
	ID               uuid.UUID
	TrainerID        uuid.UUID
	FamilyID         uuid.UUID // all tokens descended from one login share a family
	ExpiresAt        time.Time
	SessionExpiresAt time.Time // absolute cap for the whole family
	RevokedAt        *time.Time
	ReplacedBy       *uuid.UUID
}

// Limits shared by validation and the database CHECK constraints.
const (
	MinCapacity = 2
	MaxCapacity = 1024
)

// Regions and Types are closed sets; the schema enforces the same lists.
var (
	Regions = []string{"kanto", "johto", "hoenn", "sinnoh", "unova", "kalos", "alola", "galar", "paldea"}
	Types   = []string{
		"normal", "fire", "water", "grass", "electric", "ice", "fighting", "poison", "ground",
		"flying", "psychic", "bug", "rock", "ghost", "dragon", "dark", "steel", "fairy",
	}
)

func IsRegion(s string) bool { return contains(Regions, s) }
func IsType(s string) bool   { return contains(Types, s) }

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
