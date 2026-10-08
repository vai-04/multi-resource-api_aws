// Package testdb gives integration tests an isolated, migrated Postgres
// schema against a real database. Concurrency bugs (missing locks, wrong
// isolation) only show up against a real engine, so these tests do not mock
// the database.
package testdb

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"pokeleague/internal/db"
)

// Discard is a logger for tests.
var Discard = slog.New(slog.NewTextHandler(io.Discard, nil))

// New returns a pool whose connections use a fresh schema (via search_path)
// with all migrations applied. The schema is dropped when the test ends, so
// tests can run in parallel without seeing each other's rows.
//
// Set TEST_DATABASE_URL to run; without it the test is skipped (unless
// REQUIRE_DB=1, which CI sets so a misconfigured pipeline can't silently
// skip the most important tests).
func New(t testing.TB) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		if os.Getenv("REQUIRE_DB") == "1" {
			t.Fatal("TEST_DATABASE_URL is not set but REQUIRE_DB=1")
		}
		t.Skip("TEST_DATABASE_URL not set; skipping integration test")
	}
	ctx := context.Background()

	var b [6]byte
	_, _ = rand.Read(b[:])
	schema := "test_" + hex.EncodeToString(b[:])

	admin, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("connecting: %v", err)
	}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("creating schema: %v", err)
	}

	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	cfg.MaxConns = 32 // enough for real lock contention in concurrency tests
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(ctx, pool, Discard); err != nil {
		t.Fatalf("migrating: %v", err)
	}

	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		admin.Close()
	})
	return pool
}
