// Command audittrail-worker creates Merkle checkpoints and anchors them with
// an RFC 3161 TSA on an interval.
//
//	audittrail-worker          # loop every CHECKPOINT_INTERVAL
//	audittrail-worker -once    # single pass (cron-friendly)
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"audittrail.dev/packages/ingestion-go/internal/anchor"
	"audittrail.dev/packages/ingestion-go/internal/checkpoint"
	"audittrail.dev/packages/ingestion-go/internal/config"
	"audittrail.dev/packages/ingestion-go/internal/db"
	"audittrail.dev/packages/ingestion-go/internal/keys"
	"audittrail.dev/packages/ingestion-go/internal/treehead"
)

func main() {
	once := flag.Bool("once", false, "run a single pass and exit")
	only := flag.String("tenant", "", "only checkpoint this tenant (anchoring still covers all pending checkpoints)")
	flag.Parse()
	config.LoadDotEnv()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	master, err := keys.ParseMasterKey(os.Getenv("AUDITTRAIL_MASTER_KEY"))
	if err != nil {
		log.Error("config", "err", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	pool, err := db.Connect(ctx, config.WorkerDBURL(), 4)
	if err != nil {
		log.Error("database", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	w := &checkpoint.Worker{Pool: pool, Master: master, MaxRows: config.Int("CHECKPOINT_MAX_ROWS", 10000), Log: log}
	if u := config.Str("TSA_URL", "https://freetsa.org/tsr"); !strings.EqualFold(u, "off") {
		w.TSA = &anchor.TSA{URL: u}
	}
	// v2 tree heads: WITNESSES="name=url,name=url"
	th := &treehead.Worker{Pool: pool, Master: master, TSA: w.TSA, Log: log}
	for _, spec := range strings.Split(config.Str("WITNESSES", ""), ",") {
		if name, url, ok := strings.Cut(strings.TrimSpace(spec), "="); ok {
			th.Witnesses = append(th.Witnesses, treehead.WitnessCfg{Name: name, URL: url})
		}
	}
	interval := config.Dur("CHECKPOINT_INTERVAL", 2*time.Minute)
	for {
		var res checkpoint.Result
		var err error
		if *only != "" {
			res, err = w.RunTenant(ctx, *only)
			if h, herr := th.Run(ctx, *only); herr != nil {
				log.Error("tree head", "err", herr)
				res.Integrity = append(res.Integrity, herr)
			} else if h != nil {
				log.Info("tree head", "tenant", *only, "size", h.TreeSize, "witnesses", h.Witnesses, "anchored", h.Anchored)
			}
		} else {
			res, err = w.RunOnce(ctx)
			heads, errs := th.RunAll(ctx)
			for _, h := range heads {
				log.Info("tree head", "tenant", h.TenantID, "size", h.TreeSize, "witnesses", h.Witnesses, "anchored", h.Anchored)
			}
			for _, e := range errs {
				log.Error("tree head", "err", e)
				res.Integrity = append(res.Integrity, e)
			}
		}
		if err != nil {
			log.Error("run", "err", err)
		} else if len(res.Created) > 0 || res.Anchored > 0 {
			log.Info("pass complete", "checkpoints", len(res.Created), "anchored", res.Anchored, "integrity_failures", len(res.Integrity))
		}
		if *once {
			if len(res.Integrity) > 0 || err != nil {
				os.Exit(1)
			}
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}
