// Package db holds connection helpers and the migration runner.
package db

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"audittrail.dev/packages/ingestion-go/migrations"
)

func Connect(ctx context.Context, dsn string, maxConns int32) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}
	if maxConns > 0 {
		cfg.MaxConns = maxConns
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect %s: %w", redact(dsn), err)
	}
	return pool, nil
}

func redact(dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		return "<dsn>"
	}
	return u.Redacted()
}

// IsRetryable reports serialization failures and deadlocks.
func IsRetryable(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && (pg.Code == "40001" || pg.Code == "40P01")
}

func IsUniqueViolation(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23505"
}

// RolePasswords configures LOGIN roles created by Migrate.
type RolePasswords struct{ App, Worker, Purge, Control string }

func quoteLiteral(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// EnsureDatabase creates the target database if missing (connects to the
// "postgres" maintenance DB on the same server).
func EnsureDatabase(ctx context.Context, adminDSN string) error {
	cfg, err := pgx.ParseConfig(adminDSN)
	if err != nil {
		return err
	}
	name := cfg.Database
	cfg.Database = "postgres"
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return fmt.Errorf("connect maintenance db: %w", err)
	}
	defer conn.Close(ctx)
	var exists bool
	if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname=$1)`, name).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		if _, err := conn.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil {
			return fmt.Errorf("create database %s: %w", name, err)
		}
	}
	return nil
}

// DropDatabase is for tests/dev resets only.
func DropDatabase(ctx context.Context, adminDSN string) error {
	cfg, err := pgx.ParseConfig(adminDSN)
	if err != nil {
		return err
	}
	name := cfg.Database
	cfg.Database = "postgres"
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	_, err = conn.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
	return err
}

// Migrate creates roles and applies embedded migrations as audittrail_owner.
func Migrate(ctx context.Context, adminDSN string, pw RolePasswords, log func(string, ...any)) error {
	if err := EnsureDatabase(ctx, adminDSN); err != nil {
		return err
	}
	conn, err := pgx.Connect(ctx, adminDSN)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)

	// Roles are cluster-wide: create if missing, (re)set passwords.
	roles := []struct {
		name, pw string
		login    bool
	}{
		{"audittrail_owner", "", false},
		{"audittrail_app", pw.App, true},
		{"audittrail_worker", pw.Worker, true},
		{"audittrail_purge", pw.Purge, true},
		{"audittrail_control", pw.Control, true},
	}
	for _, r := range roles {
		var exists bool
		if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=$1)`, r.name).Scan(&exists); err != nil {
			return err
		}
		opts := "NOLOGIN"
		if r.login {
			opts = "LOGIN PASSWORD " + quoteLiteral(r.pw)
		}
		stmt := "CREATE ROLE "
		if exists {
			stmt = "ALTER ROLE "
		}
		if _, err := conn.Exec(ctx, stmt+r.name+" "+opts+" NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS"); err != nil {
			return fmt.Errorf("role %s: %w", r.name, err)
		}
	}
	var dbName string
	if err := conn.QueryRow(ctx, `SELECT current_database()`).Scan(&dbName); err != nil {
		return err
	}
	for _, s := range []string{
		"GRANT CREATE, USAGE ON SCHEMA public TO audittrail_owner",
		"GRANT CONNECT ON DATABASE " + pgx.Identifier{dbName}.Sanitize() + " TO audittrail_app, audittrail_worker, audittrail_purge, audittrail_control",
		"GRANT audittrail_owner TO CURRENT_USER",
	} {
		if _, err := conn.Exec(ctx, s); err != nil && !strings.Contains(err.Error(), "already") {
			return fmt.Errorf("%s: %w", s, err)
		}
	}

	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`); err != nil {
		return err
	}
	if _, err := conn.Exec(ctx, `ALTER TABLE schema_migrations OWNER TO audittrail_owner`); err != nil {
		return err
	}

	files, err := fs.Glob(migrations.FS, "*.sql")
	if err != nil {
		return err
	}
	sort.Strings(files)
	for _, f := range files {
		var done bool
		if err := conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version=$1)`, f).Scan(&done); err != nil {
			return err
		}
		if done {
			continue
		}
		sqlText, err := migrations.FS.ReadFile(f)
		if err != nil {
			return err
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "SET LOCAL ROLE audittrail_owner"); err != nil {
			tx.Rollback(ctx)
			return err
		}
		if _, err := tx.Exec(ctx, string(sqlText)); err != nil {
			tx.Rollback(ctx)
			return fmt.Errorf("migration %s: %w", f, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES ($1)`, f); err != nil {
			tx.Rollback(ctx)
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
		log("applied %s", f)
	}
	return nil
}

// InTenant runs fn in a transaction scoped to one tenant: it sets
// app.tenant_id (SET LOCAL semantics), which the RLS policies require.
func InTenant(ctx context.Context, pool *pgxpool.Pool, tenantID string, fn func(pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenantID); err != nil {
			return err
		}
		return fn(tx)
	})
}
