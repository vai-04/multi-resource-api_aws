package domain

// Kind classifies an application error. The HTTP layer maps each Kind to a
// status code; nothing below the HTTP layer knows about status codes.
type Kind int

const (
	KindValidation Kind = iota + 1
	KindNotFound
	KindConflict
	KindUnauthorized
	KindForbidden
	KindRateLimited
	KindUnavailable
)

// Error is a typed, client-safe application error.
type Error struct {
	Kind   Kind
	Code   string            // stable machine-readable slug, e.g. "tournament_full"
	Detail string            // human-readable explanation, safe to show clients
	Fields map[string]string // per-field validation messages
}

func (e *Error) Error() string { return e.Code + ": " + e.Detail }

// Is makes errors.Is match on Code, so a sentinel matches copies that carry
// extra detail (e.g. validation errors with different field sets).
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Code == e.Code
}

func newErr(k Kind, code, detail string) *Error {
	return &Error{Kind: k, Code: code, Detail: detail}
}

// Validation builds a validation error from a set of field messages.
func Validation(fields map[string]string) *Error {
	return &Error{Kind: KindValidation, Code: "validation_failed", Detail: "one or more fields are invalid", Fields: fields}
}

var (
	ErrValidation = Validation(nil)

	ErrTournamentNotFound   = newErr(KindNotFound, "tournament_not_found", "no tournament with that id exists")
	ErrTrainerNotFound      = newErr(KindNotFound, "trainer_not_found", "no trainer with that id exists")
	ErrRegistrationNotFound = newErr(KindNotFound, "registration_not_found", "you are not registered for this tournament")

	ErrTournamentFull          = newErr(KindConflict, "tournament_full", "this tournament has no spots left")
	ErrAlreadyRegistered       = newErr(KindConflict, "already_registered", "you are already registered for this tournament")
	ErrRegistrationClosed      = newErr(KindConflict, "registration_closed", "registration for this tournament is closed")
	ErrHostCannotRegister      = newErr(KindConflict, "host_cannot_register", "a gym leader cannot compete in a tournament they host")
	ErrCapacityBelowRegistered = newErr(KindConflict, "capacity_below_registered", "capacity cannot be lower than the number of registered trainers")
	ErrTournamentCancelled     = newErr(KindConflict, "tournament_cancelled", "cancelled tournaments cannot be modified")
	ErrUsernameTaken           = newErr(KindConflict, "username_taken", "that username is already taken")
	ErrEmailTaken              = newErr(KindConflict, "email_taken", "an account with that email already exists")
	ErrCannotChangeOwnRole     = newErr(KindConflict, "cannot_change_own_role", "admins cannot change their own role")

	ErrInvalidCredentials = newErr(KindUnauthorized, "invalid_credentials", "invalid username or password")
	ErrInvalidToken       = newErr(KindUnauthorized, "invalid_token", "the token is invalid or expired")
	ErrRefreshTokenReused = newErr(KindUnauthorized, "refresh_token_reused", "this refresh token was already used; all sessions in this login have been revoked")

	ErrForbidden = newErr(KindForbidden, "forbidden", "your role does not allow this action")

	ErrRateLimited = newErr(KindRateLimited, "rate_limited", "too many requests, slow down")
	ErrBusy        = newErr(KindUnavailable, "busy", "the resource is under heavy contention, retry shortly")
	ErrTimeout     = newErr(KindUnavailable, "timeout", "the request took too long to process")
)
