// Package store is the Postgres persistence layer. It translates between SQL
// rows and domain types and maps database errors (unique/check violations,
// lock timeouts) to domain errors. Business rules live in package service.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"pokeleague/internal/domain"
)

// DBTX is satisfied by both *pgxpool.Pool and pgx.Tx, so every query method
// works identically inside or outside a transaction.
type DBTX interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Store runs queries against the pool, or against a transaction when
// obtained through WithTx.
type Store struct {
	db   DBTX
	pool *pgxpool.Pool // nil inside a transaction
}

func New(pool *pgxpool.Pool) *Store { return &Store{db: pool, pool: pool} }

// WithTx runs fn in a READ COMMITTED transaction, committing if fn returns
// nil and rolling back otherwise (including on panic).
//
// READ COMMITTED is enough because the critical sections take explicit row
// locks (SELECT ... FOR UPDATE); we don't rely on the isolation level to
// detect conflicts, so we never need to retry serialization failures.
func (s *Store) WithTx(ctx context.Context, fn func(tx *Store) error) error {
	if s.pool == nil {
		return errors.New("store: nested transactions are not supported")
	}
	return pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, func(tx pgx.Tx) error {
		return fn(&Store{db: tx})
	})
}

// SetLockTimeout bounds how long statements in the current transaction wait
// for row locks. Under a stampede on one hot row, requests fail fast with
// ErrBusy instead of each holding a pooled connection while they queue.
func (s *Store) SetLockTimeout(ctx context.Context, d time.Duration) error {
	if s.pool != nil {
		return errors.New("store: SetLockTimeout must be called inside a transaction")
	}
	_, err := s.db.Exec(ctx, "SELECT set_config('lock_timeout', $1, true)", fmt.Sprintf("%dms", d.Milliseconds()))
	return mapErr(err)
}

// Ping checks database connectivity (used by the readiness probe).
func (s *Store) Ping(ctx context.Context) error {
	if s.pool == nil {
		return errors.New("store: ping inside a transaction")
	}
	return s.pool.Ping(ctx)
}

// Postgres SQLSTATE codes we care about.
const (
	pgUniqueViolation = "23505"
	pgCheckViolation  = "23514"
	pgLockNotAvail    = "55P03"
	pgQueryCanceled   = "57014"
)

func pgError(err error) *pgconn.PgError {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr
	}
	return nil
}

// mapErr converts infrastructure errors that have a meaning for clients.
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return domain.ErrTimeout
	}
	if pe := pgError(err); pe != nil {
		switch pe.Code {
		case pgLockNotAvail:
			return domain.ErrBusy
		case pgQueryCanceled:
			return domain.ErrTimeout
		}
	}
	return err
}
