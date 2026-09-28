package db_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"audittrail.dev/packages/ingestion-go/internal/config"
)

// TestLedgerIsAppendOnlyForAppRole is the Task 1.2 Definition of Done: as the
// application role, UPDATE/DELETE/TRUNCATE on agent_events fail with a
// permission error. Requires a migrated database; skipped otherwise.
func TestLedgerIsAppendOnlyForAppRole(t *testing.T) {
	config.LoadDotEnv()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, config.AppDBURL())
	if err != nil {
		t.Skipf("database not reachable: %v", err)
	}
	defer conn.Close(ctx)

	for _, stmt := range []string{
		`UPDATE agent_events SET outcome = 'allowed'`,
		`DELETE FROM agent_events`,
		`TRUNCATE agent_events`,
		`UPDATE checkpoints SET merkle_root = 'x'`,
		`DELETE FROM checkpoints`,
		`SELECT purge_expired_events(gen_random_uuid())`,
		`INSERT INTO agent_events (tenant_id, seq, timestamp, agent_id, action, target_resource, outcome,
		   previous_hash, hash, signature, key_id, created_at)
		 VALUES (gen_random_uuid(), 1, now(), 'a', 'a', 'a', 'allowed', repeat('0',64), repeat('1',64), 's', 'k', now() - interval '1 year')`,
	} {
		_, err := conn.Exec(ctx, stmt)
		if err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("expected permission denied for %q, got %v", strings.Fields(stmt)[0]+"…", err)
		}
	}
	// ...while INSERT/SELECT remain allowed.
	if _, err := conn.Exec(ctx, `SELECT count(*) FROM agent_events`); err != nil {
		t.Errorf("SELECT should be allowed: %v", err)
	}
}
