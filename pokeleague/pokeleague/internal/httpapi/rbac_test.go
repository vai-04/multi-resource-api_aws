package httpapi_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"pokeleague/internal/auth"
	"pokeleague/internal/httpapi"
	"pokeleague/internal/rbac"
	"pokeleague/internal/service"
	"pokeleague/internal/store"
	"pokeleague/internal/testdb"
)

// TestRBAC_RolesAndOwnershipAreEnforcedEndToEnd drives the real HTTP stack
// (router, middleware, services, Postgres) and checks who may call what.
// It covers both kinds of authorization:
//   - role-based, decided at the route: only gym leaders/admins create
//     tournaments, only admins assign roles;
//   - ownership-based, decided with the resource loaded: a gym leader may
//     edit or view the roster of their own tournament, not a rival's.
func TestRBAC_RolesAndOwnershipAreEnforcedEndToEnd(t *testing.T) {
	t.Parallel()
	pool := testdb.New(t)
	st := store.New(pool)
	ctx := context.Background()

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	tokens := auth.NewTokenManager(priv, "test", "test", 15*time.Minute, nil)
	hasher := auth.NewPasswordHasher(auth.Argon2Params{Memory: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}, 4)
	authSvc, err := service.NewAuth(ctx, st, hasher, tokens,
		service.AuthConfig{RefreshTTL: time.Hour, SessionTTL: 2 * time.Hour}, nil, testdb.Discard)
	if err != nil {
		t.Fatal(err)
	}
	league := service.NewLeague(st, 3*time.Second, nil)
	api := httpapi.New(authSvc, league, tokens, st, testdb.Discard, httpapi.Options{AuthRatePerMinute: 1000, AuthRateBurst: 1000})
	srv := httptest.NewServer(api.Handler())
	t.Cleanup(srv.Close)

	call := func(t *testing.T, method, path, token string, body any) (int, map[string]any) {
		t.Helper()
		var buf bytes.Buffer
		if body != nil {
			_ = json.NewEncoder(&buf).Encode(body)
		}
		req, _ := http.NewRequest(method, srv.URL+path, &buf)
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		res, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(res.Body).Decode(&out)
		return res.StatusCode, out
	}

	// account signs up over HTTP, optionally gets promoted, then logs in.
	account := func(t *testing.T, name string, role rbac.Role) (token string, id uuid.UUID) {
		t.Helper()
		pw := name + "-has-a-long-password"
		code, body := call(t, "POST", "/v1/auth/signup", "", map[string]string{
			"username": name, "email": name + "@league.test", "password": pw,
		})
		if code != http.StatusCreated {
			t.Fatalf("signup %s: %d %v", name, code, body)
		}
		id = uuid.MustParse(body["id"].(string))
		if role != rbac.RoleTrainer {
			if _, err := st.UpdateTrainerRole(ctx, id, role); err != nil {
				t.Fatal(err)
			}
		}
		code, body = call(t, "POST", "/v1/auth/login", "", map[string]string{"username": name, "password": pw})
		if code != http.StatusOK {
			t.Fatalf("login %s: %d %v", name, code, body)
		}
		return body["access_token"].(string), id
	}

	ash, ashID := account(t, "ash", rbac.RoleTrainer)
	brock, _ := account(t, "brock", rbac.RoleGymLeader)
	misty, _ := account(t, "misty", rbac.RoleGymLeader)
	oak, _ := account(t, "oak", rbac.RoleAdmin)

	newTournament := map[string]any{
		"name": "Pewter City Rock Cup", "region": "kanto", "type": "rock",
		"capacity": 16, "starts_at": time.Now().Add(72 * time.Hour).Format(time.RFC3339),
	}

	// Brock's tournament, used by the ownership checks below.
	code, body := call(t, "POST", "/v1/tournaments", brock, newTournament)
	if code != http.StatusCreated {
		t.Fatalf("gym leader creating tournament: %d %v", code, body)
	}
	tid := body["id"].(string)

	cases := []struct {
		name   string
		method string
		path   string
		token  string
		body   any
		want   int
	}{
		{"no token is 401", "GET", "/v1/tournaments", "", nil, http.StatusUnauthorized},
		{"garbage token is 401", "GET", "/v1/tournaments", "not.a.jwt", nil, http.StatusUnauthorized},
		{"any role can list", "GET", "/v1/tournaments", ash, nil, http.StatusOK},

		{"trainer cannot create a tournament", "POST", "/v1/tournaments", ash, newTournament, http.StatusForbidden},
		{"admin can create a tournament", "POST", "/v1/tournaments", oak, newTournament, http.StatusCreated},

		{"rival gym leader cannot edit it", "PATCH", "/v1/tournaments/" + tid, misty, map[string]any{"capacity": 32}, http.StatusForbidden},
		{"trainer cannot edit it", "PATCH", "/v1/tournaments/" + tid, ash, map[string]any{"capacity": 32}, http.StatusForbidden},
		{"host can edit it", "PATCH", "/v1/tournaments/" + tid, brock, map[string]any{"capacity": 32}, http.StatusOK},
		{"admin can edit any", "PATCH", "/v1/tournaments/" + tid, oak, map[string]any{"name": "Pewter Rock Cup"}, http.StatusOK},

		{"trainer can register", "POST", "/v1/tournaments/" + tid + "/registrations", ash, map[string]any{"lead_pokemon": "Pikachu"}, http.StatusCreated},
		{"admin cannot compete", "POST", "/v1/tournaments/" + tid + "/registrations", oak, map[string]any{"lead_pokemon": "Mew"}, http.StatusForbidden},
		{"host cannot enter own tournament", "POST", "/v1/tournaments/" + tid + "/registrations", brock, map[string]any{"lead_pokemon": "Onix"}, http.StatusConflict},

		{"trainer cannot see the roster", "GET", "/v1/tournaments/" + tid + "/registrations", ash, nil, http.StatusForbidden},
		{"rival gym leader cannot see the roster", "GET", "/v1/tournaments/" + tid + "/registrations", misty, nil, http.StatusForbidden},
		{"host can see the roster", "GET", "/v1/tournaments/" + tid + "/registrations", brock, nil, http.StatusOK},

		{"gym leader cannot assign roles", "PUT", "/v1/admin/trainers/" + ashID.String() + "/role", brock, map[string]any{"role": "admin"}, http.StatusForbidden},
		{"admin can assign roles", "PUT", "/v1/admin/trainers/" + ashID.String() + "/role", oak, map[string]any{"role": "gym_leader"}, http.StatusOK},
	}
	// Sequential on purpose: later cases depend on earlier state (Ash registers).
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, body := call(t, tc.method, tc.path, tc.token, tc.body)
			if code != tc.want {
				t.Fatalf("%s %s: got %d, want %d (%v)", tc.method, tc.path, code, tc.want, body)
			}
			if code >= 400 && body["code"] == nil {
				t.Fatalf("error response is not problem+json: %v", body)
			}
		})
	}
}
