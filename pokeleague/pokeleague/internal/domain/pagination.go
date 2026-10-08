package domain

import (
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// SortField is a column the tournament list can be ordered by. Only values
// in this whitelist ever reach SQL, so sorting can't be used for injection.
type SortField string

const (
	SortStartsAt  SortField = "starts_at"
	SortCreatedAt SortField = "created_at"
	SortName      SortField = "name"
)

func (f SortField) Valid() bool {
	return f == SortStartsAt || f == SortCreatedAt || f == SortName
}

const (
	DefaultPageSize = 20
	MaxPageSize     = 100
)

// TournamentQuery describes one page of the tournament list.
type TournamentQuery struct {
	// Filters (zero value = no filter).
	Region       string
	Type         string
	Status       TournamentStatus
	HostID       *uuid.UUID
	StartsAfter  *time.Time
	StartsBefore *time.Time
	HasSpots     bool

	// Ordering. ID is always the tiebreaker so the order is total.
	Sort SortField
	Desc bool

	// Keyset pagination.
	Limit  int
	Cursor *Cursor
}

// Cursor marks the last row of the previous page. The next page starts
// strictly after (Value, ID) in the requested order.
//
// It records the sort it was minted for so a cursor from one ordering can't
// be replayed against another (which would silently skip or repeat rows).
type Cursor struct {
	Sort  SortField `json:"s"`
	Desc  bool      `json:"d"`
	Value string    `json:"v"` // RFC 3339 (nanoseconds) for times, raw string for names
	ID    uuid.UUID `json:"id"`
}

// Encode returns an opaque, URL-safe token. Clients must treat it as opaque.
func (c Cursor) Encode() string {
	b, _ := json.Marshal(c) // cannot fail: plain struct of strings/bools/uuid
	return base64.RawURLEncoding.EncodeToString(b)
}

// DecodeCursor parses a token produced by Encode.
func DecodeCursor(s string) (Cursor, error) {
	var c Cursor
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, err
	}
	if !c.Sort.Valid() || c.ID == uuid.Nil {
		return c, ErrValidation
	}
	if c.Sort != SortName {
		if _, err := time.Parse(time.RFC3339Nano, c.Value); err != nil {
			return c, err
		}
	}
	return c, nil
}

// CursorFor builds the cursor pointing at t under the given ordering.
func CursorFor(t Tournament, sort SortField, desc bool) Cursor {
	c := Cursor{Sort: sort, Desc: desc, ID: t.ID}
	switch sort {
	case SortName:
		c.Value = t.Name
	case SortCreatedAt:
		c.Value = t.CreatedAt.UTC().Format(time.RFC3339Nano)
	default:
		c.Value = t.StartsAt.UTC().Format(time.RFC3339Nano)
	}
	return c
}

// Page is one page of results.
type Page[T any] struct {
	Items      []T
	NextCursor string // empty when there are no more results
}
