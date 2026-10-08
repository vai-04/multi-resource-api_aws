package httpapi

import (
	"time"

	"pokeleague/internal/domain"
	"pokeleague/internal/service"
)

// Response DTOs are separate from domain types so the wire format is an
// explicit contract: a new domain field (say, PasswordHash) can never leak
// into a response by accident. All timestamps are emitted in UTC.

type trainerDTO struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email,omitempty"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

func toTrainer(t domain.Trainer) trainerDTO {
	return trainerDTO{ID: t.ID.String(), Username: t.Username, Email: t.Email, Role: string(t.Role), CreatedAt: t.CreatedAt.UTC()}
}

type hostDTO struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}

type tournamentDTO struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Description     string    `json:"description"`
	Region          string    `json:"region"`
	Type            string    `json:"type"`
	Host            hostDTO   `json:"host"`
	Capacity        int       `json:"capacity"`
	RegisteredCount int       `json:"registered_count"`
	SpotsLeft       int       `json:"spots_left"`
	Status          string    `json:"status"`
	StartsAt        time.Time `json:"starts_at"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

func toTournament(t domain.Tournament) tournamentDTO {
	return tournamentDTO{
		ID: t.ID.String(), Name: t.Name, Description: t.Description, Region: t.Region, Type: t.Type,
		Host:     hostDTO{ID: t.HostID.String(), Username: t.HostUsername},
		Capacity: t.Capacity, RegisteredCount: t.RegisteredCount, SpotsLeft: t.SpotsLeft(),
		Status: string(t.Status), StartsAt: t.StartsAt.UTC(), CreatedAt: t.CreatedAt.UTC(), UpdatedAt: t.UpdatedAt.UTC(),
	}
}

type registrationDTO struct {
	ID             string    `json:"id"`
	TournamentID   string    `json:"tournament_id"`
	TournamentName string    `json:"tournament_name"`
	Trainer        hostDTO   `json:"trainer"`
	LeadPokemon    string    `json:"lead_pokemon"`
	CreatedAt      time.Time `json:"created_at"`
}

func toRegistration(r domain.Registration) registrationDTO {
	return registrationDTO{
		ID: r.ID.String(), TournamentID: r.TournamentID.String(), TournamentName: r.TournamentName,
		Trainer:     hostDTO{ID: r.TrainerID.String(), Username: r.TrainerUsername},
		LeadPokemon: r.LeadPokemon, CreatedAt: r.CreatedAt.UTC(),
	}
}

type tokenDTO struct {
	AccessToken      string    `json:"access_token"`
	TokenType        string    `json:"token_type"`
	ExpiresIn        int       `json:"expires_in"` // seconds, as in OAuth 2.0 (RFC 6749 §5.1)
	RefreshToken     string    `json:"refresh_token"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at"`
}

func toToken(p service.TokenPair, now time.Time) tokenDTO {
	return tokenDTO{
		AccessToken: p.AccessToken, TokenType: "Bearer",
		ExpiresIn:        int(p.AccessExpiresAt.Sub(now).Round(time.Second).Seconds()),
		RefreshToken:     p.RefreshToken,
		RefreshExpiresAt: p.RefreshExpiresAt.UTC(),
	}
}

type listDTO[T any] struct {
	Data []T     `json:"data"`
	Page pageDTO `json:"page"`
}

type pageDTO struct {
	NextCursor *string `json:"next_cursor"` // null on the last page
	Limit      int     `json:"limit"`
}

type dataDTO[T any] struct {
	Data []T `json:"data"`
}

func mapSlice[A, B any](in []A, f func(A) B) []B {
	out := make([]B, len(in)) // non-nil: encodes as [] not null
	for i, v := range in {
		out[i] = f(v)
	}
	return out
}
