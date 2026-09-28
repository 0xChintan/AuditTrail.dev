// Command audittrail-purge applies retention (Task 6.3). It connects as
// audittrail_purge, whose only privilege is EXECUTE on
// purge_expired_events(); that function refuses to run while a tenant is
// under legal hold and only deletes whole, anchored checkpoint ranges older
// than the tenant's retention window.
//
//	audittrail-purge                 # all tenants
//	audittrail-purge -tenant <uuid>  # one tenant
//	audittrail-purge -every 24h      # stay running and purge on an interval (containers)
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5"

	"audittrail.dev/packages/ingestion-go/internal/config"
	"audittrail.dev/packages/ingestion-go/internal/db"
)

func main() {
	only := flag.String("tenant", "", "purge only this tenant")
	every := flag.Duration("every", 0, "keep running and purge on this interval (0 = one pass, then exit)")
	flag.Parse()
	config.LoadDotEnv()
	if *every <= 0 {
		if !run(*only) {
			os.Exit(1)
		}
		return
	}
	for {
		run(*only)
		time.Sleep(*every)
	}
}

// run makes one purge pass; it reports false if a requested tenant failed.
func run(only string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	pool, err := db.Connect(ctx, config.PurgeDBURL(), 2)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return false
	}
	defer pool.Close()

	var tenants []string
	if only != "" {
		tenants = []string{only}
	} else {
		rows, err := pool.Query(ctx, `SELECT id FROM tenants`)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return false
		}
		tenants, err = pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return false
		}
	}
	failed := false
	for _, t := range tenants {
		var through, n int64
		err := pool.QueryRow(ctx, `SELECT purged_through_seq, rows_deleted FROM purge_expired_events($1)`, t).Scan(&through, &n)
		switch {
		case err != nil:
			fmt.Printf("%s  skipped: %v\n", t, err)
			failed = failed || only != ""
		case n == 0:
			fmt.Printf("%s  nothing past retention\n", t)
		default:
			fmt.Printf("%s  purged %d rows (through seq %d)\n", t, n, through)
		}
	}
	return !failed
}
