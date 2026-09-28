// Command audittrail-admin: operator utilities.
//
//	audittrail-admin gen-master-key
//	audittrail-admin create-tenant -name "Acme" [-retention-days 365]
//	audittrail-admin list-tenants
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"audittrail.dev/packages/ingestion-go/internal/config"
	"audittrail.dev/packages/ingestion-go/internal/contract"
	"audittrail.dev/packages/ingestion-go/internal/db"
	"audittrail.dev/packages/ingestion-go/internal/keys"
	"audittrail.dev/packages/ingestion-go/internal/sequencer"
	"audittrail.dev/packages/ingestion-go/internal/tenant"
)

func usage() {
	fmt.Fprintln(os.Stderr, "usage: audittrail-admin gen-master-key | create-tenant -name NAME [-retention-days N] | list-tenants")
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	config.LoadDotEnv()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	switch os.Args[1] {
	case "gen-master-key":
		fmt.Println(keys.GenerateMasterKey())
	case "create-tenant":
		fs := flag.NewFlagSet("create-tenant", flag.ExitOnError)
		name := fs.String("name", "", "tenant name")
		ret := fs.Int("retention-days", 183, "retention window in days (>=183)")
		fs.Parse(os.Args[2:])
		if *name == "" {
			usage()
		}
		st := store(ctx)
		t, full, _, pk, err := st.Create(ctx, tenant.CreateOptions{Name: *name, RetentionDays: *ret})
		check(err)
		env, err := sequencer.Internal(time.Now(), "audittrail-admin", "tenant.created", "tenant:"+t.ID, "allowed",
			contract.MustFromGo(map[string]string{"id": "admin-cli", "type": "service"}),
			map[string]any{"name": t.Name, "signing_key_id": pk.KeyID, "via": "cli"})
		check(err)
		_, _, err = sequencer.New(st.Pool, st.Master).Submit(ctx, t.ID, env)
		check(err)
		out, _ := json.MarshalIndent(map[string]any{"tenant_id": t.ID, "api_key": full, "signing_key_id": pk.KeyID}, "", "  ")
		fmt.Println(string(out))
		fmt.Fprintln(os.Stderr, "Store the api_key now — it cannot be shown again.")
	case "list-tenants":
		ts, err := store(ctx).List(ctx)
		check(err)
		for _, t := range ts {
			fmt.Printf("%s  %-30s retention=%dd legal_hold=%v\n", t.ID, t.Name, t.RetentionDays, t.LegalHold)
		}
	default:
		usage()
	}
}

func store(ctx context.Context) *tenant.Store {
	m, err := keys.ParseMasterKey(os.Getenv("AUDITTRAIL_MASTER_KEY"))
	check(err)
	pepper, err := keys.ParsePepper(os.Getenv("AUDITTRAIL_KEY_PEPPER"))
	check(err)
	pool, err := db.Connect(ctx, config.AppDBURL(), 4)
	check(err)
	control, err := db.Connect(ctx, config.ControlDBURL(), 2)
	check(err)
	return &tenant.Store{Pool: pool, Control: control, Master: m, Pepper: pepper}
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
