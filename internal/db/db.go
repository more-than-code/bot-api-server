// Package db is the Postgres implementation of store.Store.
// Queries are parameterized. Token columns hold SHA-256 digests only.
package db

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/more-than-code/bot-api-server/internal/store"
)

// DB is a pgx pool bound to store.Store.
type DB struct {
	pool *pgxpool.Pool
}

var _ store.Store = (*DB)(nil)

// Open connects and pings. It does not run migrations.
func Open(ctx context.Context, databaseURL string) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, errors.New("database config rejected")
	}
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	cfg.ConnConfig.RuntimeParams["timezone"] = "UTC"
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, errors.New("database connection failed")
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, errors.New("database connection failed")
	}
	return &DB{pool: pool}, nil
}

// Close releases the pool.
func (d *DB) Close() { d.pool.Close() }

func isUnique(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505"
}

func isFK(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23503"
}

func mapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return store.ErrNotFound
	}
	if isUnique(err) {
		return store.ErrConflict
	}
	if isFK(err) {
		return store.ErrNotFound
	}
	return fmt.Errorf("database: %w", scrub(err))
}

func scrub(err error) error {
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "://") {
		return errors.New("database error")
	}
	return err
}

type queryer interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

func exec(ctx context.Context, q queryer, sql string, args ...any) error {
	_, err := q.Exec(ctx, sql, args...)
	return err
}

func optTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return *t
}

func optString(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}
