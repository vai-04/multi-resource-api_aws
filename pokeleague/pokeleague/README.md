# Pokémon League API

A Go REST API where **trainers** register for capacity-limited **tournaments** hosted by **gym leaders**, with **admins** running the league.

It is a small codebase built to production standards: a relational schema with real foreign keys, role-based access control, short-lived access tokens with rotating refresh tokens, and a registration path that stays correct when hundreds of requests race for the last spot.

> **Every design decision and its trade-offs are explained in [`docs/DESIGN.md`](docs/DESIGN.md).** This README is the quick start.

| Requirement | Where | Proven by |
|---|---|---|
| 2+ related resources, real relationship | `trainers` ↔ `tournaments` via the `registrations` join table, FKs + unique constraint ([schema](internal/db/migrations/0001_init.sql)) | all integration tests |
| RBAC with 2+ roles | `trainer`, `gym_leader`, `admin` → permissions ([rbac.go](internal/rbac/rbac.go)), route-level + ownership checks | `TestRBAC_RolesAndOwnershipAreEnforcedEndToEnd` |
| Short-lived access + refresh flow | 15-min Ed25519 JWTs, single-use rotating refresh tokens with reuse detection ([service/auth.go](internal/service/auth.go)) | `TestRefresh_RotationReuseDetectionAndExpiry`, `TestTokenManager_RejectsForgedExpiredAndMisdirectedTokens` |
| Concurrency-safe write | Registration inside a transaction holding `SELECT … FOR UPDATE` on the tournament row, plus a DB `CHECK` backstop ([service/league.go](internal/service/league.go)) | `TestRegister_ConcurrentRequestsNeverExceedCapacity` |
| Pagination / filtering / sorting | `GET /v1/tournaments`: keyset cursors, 7 filters, 3 sort keys × 2 directions | `TestListTournaments_KeysetPaginationFiltersAndSorting` |
| 3–5 tests of real logic | 5 test functions (37 sub-cases), run against real Postgres with `-race` | `make test` |

## Quick start

Requires Docker. Go 1.24+ only if you want to run tests or the binary outside Docker.

```bash
docker compose up --build        # Postgres 16 + API on :8080, migrations run automatically
curl localhost:8080/readyz       # {"status":"ready"}
```

The compose file creates a demo admin, `professor_oak` / `gotta-catch-em-all-151`.

### A walk through the league

```bash
API=localhost:8080/v1
J='Content-Type: application/json'

# 1. Brock and Ash sign up (everyone starts as a trainer)
BROCK_ID=$(curl -s -XPOST $API/auth/signup -H "$J" \
  -d '{"username":"brock","email":"brock@pewter.gym","password":"onix-is-my-rock-solid-pal"}' | jq -r .id)
curl -s -XPOST $API/auth/signup -H "$J" -d '{"username":"ash","email":"ash@pallet.town","password":"pikachu-i-choose-you"}'

# 2. Professor Oak (admin) promotes Brock to gym leader
OAK=$(curl -s -XPOST $API/auth/login -H "$J" -d '{"username":"professor_oak","password":"gotta-catch-em-all-151"}' | jq -r .access_token)
curl -s -XPUT $API/admin/trainers/$BROCK_ID/role -H "$J" -H "Authorization: Bearer $OAK" -d '{"role":"gym_leader"}'

# 3. Brock logs in again (his new role is in the new token) and hosts a tournament
BROCK=$(curl -s -XPOST $API/auth/login -H "$J" -d '{"username":"brock","password":"onix-is-my-rock-solid-pal"}' | jq -r .access_token)
TID=$(curl -s -XPOST $API/tournaments -H "$J" -H "Authorization: Bearer $BROCK" \
  -d '{"name":"Pewter City Rock Cup","region":"kanto","type":"rock","capacity":16,"starts_at":"2026-12-01T10:00:00Z"}' | jq -r .id)

# 4. Ash registers with his lead Pokémon
ASH=$(curl -s -XPOST $API/auth/login -H "$J" -d '{"username":"ash","password":"pikachu-i-choose-you"}')
ASH_AT=$(echo "$ASH" | jq -r .access_token); ASH_RT=$(echo "$ASH" | jq -r .refresh_token)
curl -s -XPOST $API/tournaments/$TID/registrations -H "$J" -H "Authorization: Bearer $ASH_AT" -d '{"lead_pokemon":"Pikachu"}'

# 5. Browse: open Kanto tournaments with free spots, latest first, 10 per page
curl -s "$API/tournaments?region=kanto&has_spots=true&sort=-starts_at&limit=10" -H "Authorization: Bearer $ASH_AT"

# 6. Refresh rotates the token; replaying the old one is treated as theft
curl -s -XPOST $API/auth/refresh -H "$J" -d "{\"refresh_token\":\"$ASH_RT\"}"   # 200, new pair
curl -s -XPOST $API/auth/refresh -H "$J" -d "{\"refresh_token\":\"$ASH_RT\"}"   # 401 refresh_token_reused
```

Errors are always [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) problem details with a stable `code`:

```json
{
  "type": "urn:pokeleague:problem:validation_failed",
  "title": "Unprocessable Entity",
  "status": 422,
  "detail": "one or more fields are invalid",
  "instance": "/v1/auth/signup",
  "code": "validation_failed",
  "request_id": "0e956e743a82e68447bc9e52",
  "errors": {
    "email": "must be a valid email address",
    "password": "must be between 12 and 128 characters",
    "username": "must be 3-32 characters of letters, digits or underscores"
  }
}
```

## Endpoints

Full contract: [`api/openapi.yaml`](api/openapi.yaml) (OpenAPI 3.1).

| Method & path | Who | Notes |
|---|---|---|
| `POST /v1/auth/signup` | public | rate-limited; new accounts are `trainer` |
| `POST /v1/auth/login` | public | rate-limited; returns access + refresh token |
| `POST /v1/auth/refresh` | public (needs refresh token) | rotates; reuse revokes the session |
| `POST /v1/auth/logout` | public (needs refresh token) | idempotent |
| `GET /v1/me` | any role | |
| `GET /v1/me/registrations` | any role | |
| `GET /v1/tournaments` | any role | filters, sort, keyset pagination |
| `POST /v1/tournaments` | `gym_leader`, `admin` | caller becomes host |
| `GET /v1/tournaments/{id}` | any role | |
| `PATCH /v1/tournaments/{id}` | host or `admin` | can't drop capacity below registrations |
| `POST /v1/tournaments/{id}/registrations` | `trainer`, `gym_leader` | **concurrency-safe**; host can't enter own event |
| `DELETE /v1/tournaments/{id}/registrations/me` | registered trainer | frees the spot |
| `GET /v1/tournaments/{id}/registrations` | host or `admin` | roster |
| `PUT /v1/admin/trainers/{id}/role` | `admin` | revokes the trainer's refresh tokens |
| `GET /healthz`, `GET /readyz` | probes | liveness / readiness |

List query parameters: `region`, `type`, `status`, `host_id`, `has_spots`, `starts_after`, `starts_before`, `sort` (`starts_at`, `created_at`, `name`; prefix `-` for descending), `limit` (1–100, default 20), `cursor`.

## Tests

```bash
make test         # starts Postgres via compose, runs everything with -race
make test-unit    # no database: integration tests skip themselves
make lint vuln    # gofmt, go vet, staticcheck, govulncheck
```

| Test | Kind | What it proves |
|---|---|---|
| `TestRegister_ConcurrentRequestsNeverExceedCapacity` | integration | 40 simultaneous registrations for 5 spots → exactly 5 succeed; counter = join rows; a double-submitting trainer gets one registration; withdrawing frees a spot |
| `TestRefresh_RotationReuseDetectionAndExpiry` | integration | rotation; replay revokes the family; 8 concurrent refreshes → exactly 1 wins; access-token expiry; absolute session cap; logout |
| `TestListTournaments_KeysetPaginationFiltersAndSorting` | integration | every row exactly once in order (incl. ties); desc = reverse asc; inserts mid-walk cause no duplicates; `has_spots`; cursor/sort mismatch rejected |
| `TestRBAC_RolesAndOwnershipAreEnforcedEndToEnd` | HTTP end-to-end | 17 role/ownership cases through the real router and middleware |
| `TestTokenManager_RejectsForgedExpiredAndMisdirectedTokens` | unit | expired, wrong key, edited payload, `alg: none`, HS256 alg-confusion, wrong audience, unknown role |

The concurrency test was **mutation-checked**: with the row lock and capacity constraint removed, it fails on every run (10–17 trainers admitted to a 5-spot tournament). See [DESIGN.md §4.6](docs/DESIGN.md#46-evidence-the-test-actually-catches-the-race).

## Project layout

```
cmd/api/                 main: config, wiring, HTTP server, graceful shutdown
internal/
  config/                env-var configuration (12-factor), validated at start-up
  rbac/                  roles -> permissions table
  domain/                core types, typed errors, pagination cursor (no I/O)
  auth/                  Argon2id passwords, Ed25519 JWTs, opaque refresh tokens
  db/                    pgx pool, embedded SQL migrations with advisory lock
  store/                 Postgres queries; maps SQL errors to domain errors
  service/               use cases & business rules; owns transactions
  httpapi/               router, middleware, handlers, problem+json
  logging/               JSON slog with request-id propagation
  testdb/                per-test isolated schemas on a real Postgres
api/openapi.yaml         API contract
docs/DESIGN.md           decisions and trade-offs
```

Dependencies are deliberately few: `pgx` (Postgres driver), `golang-jwt` (JWS), `google/uuid` (UUIDv7) and `x/crypto` (Argon2id). Routing, logging and everything else is the Go standard library.
