// Command audittrail-migrate creates the database roles and applies schema
// migrations. It is the only component that connects with admin rights.
//
//	audittrail-migrate           # create db/roles, apply pending migrations
//	audittrail-migrate -reset    # DROP the database first (dev/tests only)
package main

import (
	"context"
	"flag"
	"log"
	"time"

	"audittrail.dev/packages/ingestion-go/internal/config"
	"audittrail.dev/packages/ingestion-go/internal/db"
)

func main() {
	reset := flag.Bool("reset", false, "drop and recreate the database (DESTROYS ALL DATA)")
	flag.Parse()
	config.LoadDotEnv()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	admin := config.AdminDBURL()
	if *reset {
		if err := db.DropDatabase(ctx, admin); err != nil {
			log.Fatalf("reset: %v", err)
		}
		log.Printf("dropped database")
	}
	pw := db.RolePasswords{
		App:    config.Str("AUDITTRAIL_APP_DB_PASSWORD", "audittrail_app"),
		Worker: config.Str("AUDITTRAIL_WORKER_DB_PASSWORD", "audittrail_worker"),
		Purge:  config.Str("AUDITTRAIL_PURGE_DB_PASSWORD", "audittrail_purge"),
	}
	if err := db.Migrate(ctx, admin, pw, log.Printf); err != nil {
		log.Fatalf("migrate: %v", err)
	}
	log.Printf("migrations up to date")
}
