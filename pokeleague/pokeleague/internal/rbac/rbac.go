// Package rbac defines the roles in the Pokémon League and the permissions
// each role is granted.
//
// Handlers and services ask "can this role do X?" rather than "is this role
// Y?". Keeping the role→permission mapping in one table means adding a role
// (say, "elite_four") is a one-line change here instead of a hunt through
// every `if role == "admin"` in the codebase.
package rbac

// Role is a trainer's league role. It is stored as text in the database and
// embedded in access tokens.
type Role string

const (
	RoleTrainer   Role = "trainer"    // registers for tournaments
	RoleGymLeader Role = "gym_leader" // hosts tournaments, can also compete in others
	RoleAdmin     Role = "admin"      // league staff: manages any tournament and assigns roles
)

// Permission is a single capability checked by the API.
type Permission string

const (
	PermTournamentCreate    Permission = "tournament:create"
	PermTournamentManageOwn Permission = "tournament:manage_own" // edit / view roster of tournaments you host
	PermTournamentManageAny Permission = "tournament:manage_any" // edit / view roster of any tournament
	PermTournamentRegister  Permission = "tournament:register"
	PermTrainerManageRoles  Permission = "trainer:manage_roles"
)

var grants = map[Role]map[Permission]struct{}{
	RoleTrainer: set(
		PermTournamentRegister,
	),
	RoleGymLeader: set(
		PermTournamentRegister,
		PermTournamentCreate,
		PermTournamentManageOwn,
	),
	RoleAdmin: set(
		PermTournamentCreate,
		PermTournamentManageAny,
		PermTrainerManageRoles,
	),
}

// Valid reports whether r is a known role.
func (r Role) Valid() bool {
	_, ok := grants[r]
	return ok
}

// Can reports whether r has been granted p. Unknown roles have no permissions
// (deny by default).
func (r Role) Can(p Permission) bool {
	_, ok := grants[r][p]
	return ok
}

func set(ps ...Permission) map[Permission]struct{} {
	m := make(map[Permission]struct{}, len(ps))
	for _, p := range ps {
		m[p] = struct{}{}
	}
	return m
}
