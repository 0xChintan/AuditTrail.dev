// Package config loads settings from the environment, optionally seeded from
// a .env file found in the working directory or any parent (so commands work
// from the repo root or from packages/ingestion-go).
package config

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// LoadDotEnv sets variables from the nearest .env without overriding ones
// already present in the environment.
func LoadDotEnv() {
	dir, _ := os.Getwd()
	for {
		p := filepath.Join(dir, ".env")
		if f, err := os.Open(p); err == nil {
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				k, v, ok := strings.Cut(line, "=")
				if !ok {
					continue
				}
				k = strings.TrimSpace(strings.TrimPrefix(k, "export "))
				v = strings.Trim(strings.TrimSpace(v), `"'`)
				if _, exists := os.LookupEnv(k); !exists {
					os.Setenv(k, v)
				}
			}
			f.Close()
			return
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return
		}
		dir = parent
	}
}

func Str(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && v != "" {
		return v
	}
	return def
}

func Int(k string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(k)); err == nil {
		return v
	}
	return def
}

func Dur(k string, def time.Duration) time.Duration {
	if v, err := time.ParseDuration(os.Getenv(k)); err == nil {
		return v
	}
	return def
}

func Bool(k string, def bool) bool {
	if v, err := strconv.ParseBool(os.Getenv(k)); err == nil {
		return v
	}
	return def
}

const (
	DefaultAppURL     = "postgres://audittrail_app:audittrail_app@localhost:5432/audittrail?sslmode=disable"
	DefaultWorkerURL  = "postgres://audittrail_worker:audittrail_worker@localhost:5432/audittrail?sslmode=disable"
	DefaultControlURL = "postgres://audittrail_control:audittrail_control@localhost:5432/audittrail?sslmode=disable"
	DefaultPurgeURL   = "postgres://audittrail_purge:audittrail_purge@localhost:5432/audittrail?sslmode=disable"
)

func AppDBURL() string     { return Str("DATABASE_URL", DefaultAppURL) }
func WorkerDBURL() string  { return Str("DATABASE_WORKER_URL", DefaultWorkerURL) }
func PurgeDBURL() string   { return Str("DATABASE_PURGE_URL", DefaultPurgeURL) }
func ControlDBURL() string { return Str("DATABASE_CONTROL_URL", DefaultControlURL) }
func AdminDBURL() string {
	return Str("DATABASE_ADMIN_URL", "postgres://localhost:5432/audittrail?sslmode=disable")
}
