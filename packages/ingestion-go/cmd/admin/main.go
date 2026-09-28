// Command audittrail-admin: operator utilities.
//
//	audittrail-admin gen-master-key
//	audittrail-admin kms-wrap -key awskms://alias/audittrail?region=… [-generate]
//	audittrail-admin kms-rewrap -to gcpkms://projects/…/cryptoKeys/new
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
	"audittrail.dev/packages/ingestion-go/internal/masterkey"
	"audittrail.dev/packages/ingestion-go/internal/sequencer"
	"audittrail.dev/packages/ingestion-go/internal/tenant"
)

func usage() {
	fmt.Fprintln(os.Stderr, "usage: audittrail-admin gen-master-key | kms-wrap -key URL [-generate] | kms-rewrap -to URL | create-tenant -name NAME [-retention-days N] | list-tenants")
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
	case "kms-wrap":
		// Prints AUDITTRAIL_MASTER_KEY_WRAPPED. With -generate the new key is
		// never shown in plaintext; otherwise AUDITTRAIL_MASTER_KEY is wrapped.
		fs := flag.NewFlagSet("kms-wrap", flag.ExitOnError)
		keyURL := fs.String("key", os.Getenv(masterkey.EnvKMSKey), "KMS key URL")
		gen := fs.Bool("generate", false, "generate a new master key instead of wrapping AUDITTRAIL_MASTER_KEY")
		check(fs.Parse(os.Args[2:]))
		plain := os.Getenv(masterkey.EnvPlain)
		if *gen {
			plain = keys.GenerateMasterKey()
		}
		wrapped, err := masterkey.Wrap(ctx, *keyURL, plain)
		check(err)
		fmt.Println(wrapped)
		fmt.Fprintf(os.Stderr, "Deploy this as %s with %s=%s, then remove %s everywhere.\n", masterkey.EnvWrapped, masterkey.EnvKMSKey, *keyURL, masterkey.EnvPlain)
	case "kms-rewrap":
		// Moves to a new KMS key: unwraps with the current configuration and
		// wraps the same master key under -to. No data is re-encrypted.
		fs := flag.NewFlagSet("kms-rewrap", flag.ExitOnError)
		to := fs.String("to", "", "new KMS key URL")
		check(fs.Parse(os.Args[2:]))
		if *to == "" {
			usage()
		}
		cur := os.Getenv(masterkey.EnvPlain)
		if u := os.Getenv(masterkey.EnvKMSKey); u != "" {
			var err error
			cur, err = masterkey.Unwrap(ctx, u, os.Getenv(masterkey.EnvWrapped))
			check(err)
		}
		wrapped, err := masterkey.Wrap(ctx, *to, cur)
		check(err)
		fmt.Println(wrapped)
	case "create-tenant":
		fs := flag.NewFlagSet("create-tenant", flag.ExitOnError)
		name := fs.String("name", "", "tenant name")
		ret := fs.Int("retention-days", 183, "retention window in days (>=183)")
		check(fs.Parse(os.Args[2:]))
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
	m, _, err := masterkey.Load(ctx)
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
