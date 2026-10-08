package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	"pokeleague/internal/domain"
	"pokeleague/internal/logging"
)

// problem is an RFC 9457 "Problem Details for HTTP APIs" body. Every error
// response has this shape, so clients need exactly one error parser.
type problem struct {
	Type      string            `json:"type"`
	Title     string            `json:"title"`
	Status    int               `json:"status"`
	Detail    string            `json:"detail,omitempty"`
	Instance  string            `json:"instance,omitempty"`
	Code      string            `json:"code"`
	RequestID string            `json:"request_id,omitempty"`
	Errors    map[string]string `json:"errors,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeProblem(w http.ResponseWriter, r *http.Request, status int, code, detail string, fields map[string]string) {
	p := problem{
		Type:      "urn:pokeleague:problem:" + code,
		Title:     http.StatusText(status),
		Status:    status,
		Detail:    detail,
		Instance:  r.URL.Path,
		Code:      code,
		RequestID: logging.RequestID(r.Context()),
		Errors:    fields,
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(p)
}

var kindStatus = map[domain.Kind]int{
	domain.KindValidation:   http.StatusUnprocessableEntity,
	domain.KindNotFound:     http.StatusNotFound,
	domain.KindConflict:     http.StatusConflict,
	domain.KindUnauthorized: http.StatusUnauthorized,
	domain.KindForbidden:    http.StatusForbidden,
	domain.KindRateLimited:  http.StatusTooManyRequests,
	domain.KindUnavailable:  http.StatusServiceUnavailable,
}

// writeError maps any error to a response. Domain errors carry a safe
// message; anything else is logged with the request id and returned as a
// generic 500 so internals (SQL, stack traces) never leak to clients.
func (a *API) writeError(w http.ResponseWriter, r *http.Request, err error) {
	var de *domain.Error
	if errors.As(err, &de) {
		status := kindStatus[de.Kind]
		switch de.Kind {
		case domain.KindUnauthorized:
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		case domain.KindUnavailable, domain.KindRateLimited:
			w.Header().Set("Retry-After", "1")
		}
		writeProblem(w, r, status, de.Code, de.Detail, de.Fields)
		return
	}
	var be *badRequestError
	if errors.As(err, &be) {
		writeProblem(w, r, be.status, be.code, be.detail, nil)
		return
	}
	if errors.Is(err, context.DeadlineExceeded) {
		w.Header().Set("Retry-After", "1")
		writeProblem(w, r, http.StatusServiceUnavailable, domain.ErrTimeout.Code, domain.ErrTimeout.Detail, nil)
		return
	}
	if errors.Is(err, context.Canceled) {
		// The client went away; nobody will read a response.
		a.log.InfoContext(r.Context(), "request canceled by client")
		return
	}
	a.log.ErrorContext(r.Context(), "unhandled error", "err", err)
	writeProblem(w, r, http.StatusInternalServerError, "internal_error", "an unexpected error occurred", nil)
}

type badRequestError struct {
	status int
	code   string
	detail string
}

func (e *badRequestError) Error() string { return e.detail }

func badRequest(code, format string, args ...any) error {
	return &badRequestError{status: http.StatusBadRequest, code: code, detail: fmt.Sprintf(format, args...)}
}

const maxBodyBytes = 64 << 10 // 64 KiB: generous for this API, small enough to bound memory per request

// decodeJSON strictly decodes a single JSON object into dst.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	if ct := r.Header.Get("Content-Type"); ct != "" {
		mt, _, err := mime.ParseMediaType(ct)
		if err != nil || mt != "application/json" {
			return &badRequestError{http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json"}
		}
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields() // typos like "capcity" fail loudly instead of being ignored

	if err := dec.Decode(dst); err != nil {
		var (
			syntaxErr *json.SyntaxError
			typeErr   *json.UnmarshalTypeError
			maxErr    *http.MaxBytesError
		)
		switch {
		case errors.As(err, &syntaxErr), errors.Is(err, io.ErrUnexpectedEOF):
			return badRequest("malformed_json", "request body is not valid JSON")
		case errors.As(err, &typeErr):
			return badRequest("malformed_json", "field %q must be of type %s", typeErr.Field, typeErr.Type)
		case strings.HasPrefix(err.Error(), "json: unknown field "):
			return badRequest("unknown_field", "request body contains %s", strings.TrimPrefix(err.Error(), "json: "))
		case errors.Is(err, io.EOF):
			return badRequest("empty_body", "request body must not be empty")
		case errors.As(err, &maxErr):
			return &badRequestError{http.StatusRequestEntityTooLarge, "body_too_large", "request body is too large"}
		default:
			return badRequest("malformed_json", "could not decode request body")
		}
	}
	if dec.More() {
		return badRequest("malformed_json", "request body must contain a single JSON object")
	}
	return nil
}
