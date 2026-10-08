package httpapi

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"pokeleague/internal/domain"
	"pokeleague/internal/rbac"
)

// ---- auth -------------------------------------------------------------

func (a *API) signup(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		a.writeError(w, r, err)
		return
	}
	t, err := a.auth.Signup(r.Context(), in.Username, in.Email, in.Password)
	if err != nil {
		a.writeError(w, r, err)
		return
	}
	w.Header().Set("Location", "/v1/me")
	writeJSON(w, http.StatusCreated, toTrainer(t))
}

func (a *API) login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		a.writeError(w, r, err)
		return
	}
	pair, err := a.auth.Login(r.Context(), in.Username, in.Password, r.UserAgent())
	if err != nil {
		a.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toToken(pair, time.Now()))
}

type refreshBody struct {
	RefreshToken string `json:"refresh_token"`
}

func (a *API) refresh(w http.ResponseWriter, r *http.Request) {
	var in refreshBody
	if err := decodeJSON(w, r, &in); err != nil {
		a.writeError(w, r, err)
		return
	}
	if in.RefreshToken == "" {
		a.writeError(w, r, domain.Validation(map[string]string{"refresh_token": "is required"}))
		return
	}
	pair, err := a.auth.Refresh(r.Context(), in.RefreshToken, r.UserAgent())
	if err != nil {
		a.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toToken(pair, time.Now()))
}

func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	var in refreshBody
	if err := decodeJSON(w, r, &in); err != nil {
		a.writeError(w, r, err)
		return
	}
	if err := a.auth.Logout(r.Context(), in.RefreshToken); err != nil {
		a.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- me ---------------------------------------------------------------

func (a *API) me(w http.ResponseWriter, r *http.Request) {
	actor, _ := actorFrom(r.Context())
	t, err := a.auth.Me(r.Context(), actor)
	if err != nil {
		a.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toTrainer(t))
}

func (a *API) myRegistrations(w http.ResponseWriter, r *http.Request) {
	actor, _ := actorFrom(r.Context())
	regs, err := a.league.MyRegistrations(r.Context(), actor)
	if err != nil {
		a.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, dataDTO[registrationDTO]{Data: mapSlice(regs, toRegistration)})
}

// ---- tournaments ------------------------------------------------------

func (a *API) createTournament(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name        string    `json:"name"`
		Description string    `json:"description"`
		Region      string    `json:"region"`
		Type        string    `json:"type"`
		Capacity    int       `json:"capacity"`
		StartsAt    time.Time `json:"starts_at"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		a.writeError(w, r, err)
		return
	}
	actor, _ := actorFrom(r.Context())
	t, err := a.league.CreateTournament(r.Context(), actor, domain.NewTournament{
		Name: in.Name, Description: in.Description, Region: in.Region, Type: in.Type,
		Capacity: in.Capacity, StartsAt: in.StartsAt,
	})
	if err != nil {
		a.writeError(w, r, err)
		return
	}
	w.Header().Set("Location", "/v1/tournaments/"+t.ID.String())
	writeJSON(w, http.StatusCreated, toTournament(t))
}

func (a *API) getTournament(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		a.writeError(w, r, domain.ErrTournamentNotFound)
		return
	}
	t, err := a.league.GetTournament(r.Context(), id)
	if err != nil {
		a.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toTournament(t))
}

func (a *API) updateTournament(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		a.writeError(w, r, domain.ErrTournamentNotFound)
		return
	}
	// Pointers distinguish "field absent" (leave unchanged) from a zero value.
	var in struct {
		Name        *string    `json:"name"`
		Description *string    `json:"description"`
		Capacity    *int       `json:"capacity"`
		Status      *string    `json:"status"`
		StartsAt    *time.Time `json:"starts_at"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		a.writeError(w, r, err)
		return
	}
	patch := domain.TournamentPatch{Name: in.Name, Description: in.Description, Capacity: in.Capacity, StartsAt: in.StartsAt}
	if in.Status != nil {
		s := domain.TournamentStatus(*in.Status)
		patch.Status = &s
	}
	actor, _ := actorFrom(r.Context())
	t, err := a.league.UpdateTournament(r.Context(), actor, id, patch)
	if err != nil {
		a.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toTournament(t))
}

// listTournaments: GET /v1/tournaments
//
//	?region=kanto&type=fire&status=open&host_id=<uuid>&has_spots=true
//	&starts_after=<RFC3339>&starts_before=<RFC3339>
//	&sort=starts_at|-starts_at|name|-name|created_at|-created_at
//	&limit=1..100&cursor=<opaque>
func (a *API) listTournaments(w http.ResponseWriter, r *http.Request) {
	q, err := parseTournamentQuery(r)
	if err != nil {
		a.writeError(w, r, err)
		return
	}
	page, err := a.league.ListTournaments(r.Context(), q)
	if err != nil {
		a.writeError(w, r, err)
		return
	}
	out := listDTO[tournamentDTO]{Data: mapSlice(page.Items, toTournament), Page: pageDTO{Limit: q.Limit}}
	if out.Page.Limit == 0 {
		out.Page.Limit = domain.DefaultPageSize
	}
	if page.NextCursor != "" {
		out.Page.NextCursor = &page.NextCursor
	}
	writeJSON(w, http.StatusOK, out)
}

func parseTournamentQuery(r *http.Request) (domain.TournamentQuery, error) {
	v := r.URL.Query()
	q := domain.TournamentQuery{}
	f := map[string]string{}

	if s := v.Get("region"); s != "" {
		if q.Region = strings.ToLower(s); !domain.IsRegion(q.Region) {
			f["region"] = "unknown region"
		}
	}
	if s := v.Get("type"); s != "" {
		if q.Type = strings.ToLower(s); !domain.IsType(q.Type) {
			f["type"] = "unknown Pokémon type"
		}
	}
	if s := v.Get("status"); s != "" {
		if q.Status = domain.TournamentStatus(s); !q.Status.Valid() {
			f["status"] = "must be one of: open, closed, cancelled"
		}
	}
	if s := v.Get("host_id"); s != "" {
		id, err := uuid.Parse(s)
		if err != nil {
			f["host_id"] = "must be a UUID"
		}
		q.HostID = &id
	}
	parseTime := func(key string) *time.Time {
		s := v.Get(key)
		if s == "" {
			return nil
		}
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			f[key] = "must be an RFC 3339 timestamp, e.g. 2026-11-01T18:00:00Z"
			return nil
		}
		return &t
	}
	q.StartsAfter = parseTime("starts_after")
	q.StartsBefore = parseTime("starts_before")
	if s := v.Get("has_spots"); s != "" {
		b, err := strconv.ParseBool(s)
		if err != nil {
			f["has_spots"] = "must be true or false"
		}
		q.HasSpots = b
	}

	if s := v.Get("sort"); s != "" {
		q.Desc = strings.HasPrefix(s, "-")
		if q.Sort = domain.SortField(strings.TrimPrefix(s, "-")); !q.Sort.Valid() {
			f["sort"] = "must be one of: starts_at, created_at, name (prefix with - for descending)"
		}
	} else {
		q.Sort = domain.SortStartsAt
	}
	if s := v.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 || n > domain.MaxPageSize {
			f["limit"] = "must be an integer between 1 and " + strconv.Itoa(domain.MaxPageSize)
		}
		q.Limit = n
	}
	if s := v.Get("cursor"); s != "" {
		c, err := domain.DecodeCursor(s)
		if err != nil {
			f["cursor"] = "is malformed"
		}
		q.Cursor = &c
	}

	if len(f) > 0 {
		return q, domain.Validation(f)
	}
	return q, nil
}

// ---- registrations ----------------------------------------------------

func (a *API) register(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		a.writeError(w, r, domain.ErrTournamentNotFound)
		return
	}
	var in struct {
		LeadPokemon string `json:"lead_pokemon"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		a.writeError(w, r, err)
		return
	}
	actor, _ := actorFrom(r.Context())
	reg, err := a.league.Register(r.Context(), actor, id, in.LeadPokemon)
	if err != nil {
		a.writeError(w, r, err)
		return
	}
	w.Header().Set("Location", "/v1/tournaments/"+id.String()+"/registrations/me")
	writeJSON(w, http.StatusCreated, toRegistration(reg))
}

func (a *API) withdraw(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		a.writeError(w, r, domain.ErrTournamentNotFound)
		return
	}
	actor, _ := actorFrom(r.Context())
	if err := a.league.Withdraw(r.Context(), actor, id); err != nil {
		a.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) roster(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		a.writeError(w, r, domain.ErrTournamentNotFound)
		return
	}
	actor, _ := actorFrom(r.Context())
	regs, err := a.league.Roster(r.Context(), actor, id)
	if err != nil {
		a.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, dataDTO[registrationDTO]{Data: mapSlice(regs, toRegistration)})
}

// ---- admin ------------------------------------------------------------

func (a *API) setRole(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(r)
	if !ok {
		a.writeError(w, r, domain.ErrTrainerNotFound)
		return
	}
	var in struct {
		Role string `json:"role"`
	}
	if err := decodeJSON(w, r, &in); err != nil {
		a.writeError(w, r, err)
		return
	}
	actor, _ := actorFrom(r.Context())
	t, err := a.league.SetRole(r.Context(), actor, id, rbac.Role(in.Role))
	if err != nil {
		a.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toTrainer(t))
}

// pathID parses the {id} path segment. A malformed id can't match any row,
// so it is reported as "not found" rather than as a validation error.
func pathID(r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	return id, err == nil
}
