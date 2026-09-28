package api_test

import (
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"audittrail.dev/packages/ingestion-go/internal/api"
	"audittrail.dev/packages/ingestion-go/internal/keys"
	"audittrail.dev/packages/ingestion-go/internal/ratelimit"
	"audittrail.dev/packages/ingestion-go/internal/tenant"
	"audittrail.dev/packages/ingestion-go/internal/v2client"
)

// TestSharedRateLimitAcrossInstances: two limiter instances (two API
// processes) hammering one tenant together must not exceed its limit.
func TestSharedRateLimitAcrossInstances(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	tn, _, _, _, err := e.srv.Tenants.Create(ctx, tenant.CreateOptions{Name: "rate-shared", RateLimitRPS: 40, RateLimitBurst: 40})
	if err != nil {
		t.Fatal(err)
	}
	const rps, burst = 40, 40
	instances := []*ratelimit.Shared{{Pool: e.srv.Control}, {Pool: e.srv.Control}}
	var admitted, denied atomic.Int64
	start := time.Now()
	deadline := start.Add(2 * time.Second)
	var wg sync.WaitGroup
	for _, inst := range instances {
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for time.Now().Before(deadline) {
					if ok, wait := inst.Allow(ctx, tn.ID, rps, burst); ok {
						admitted.Add(1)
					} else {
						if wait <= 0 {
							t.Error("denial without a wait hint")
						}
						denied.Add(1)
					}
					time.Sleep(time.Millisecond)
				}
			}()
		}
	}
	wg.Wait()
	elapsed := time.Since(start).Seconds()
	limit := float64(burst) + rps*elapsed
	got := float64(admitted.Load())
	t.Logf("admitted %v (limit %.0f over %.2fs), denied %d", got, limit, elapsed, denied.Load())
	if got > limit+1 {
		t.Fatalf("two instances admitted %v, above the tenant limit %.0f", got, limit)
	}
	// Leases that expire unused cost a little throughput, never correctness.
	if got < 0.6*limit {
		t.Fatalf("admitted only %v of %.0f: limiter too conservative", got, limit)
	}
}

// TestRateLimit429AcrossServers: two full API servers share one tenant's
// limit; rejected requests get 429 with Retry-After.
func TestRateLimit429AcrossServers(t *testing.T) {
	e := setup(t)
	ctx := context.Background()
	tn, key, _, _, err := e.srv.Tenants.Create(ctx, tenant.CreateOptions{Name: "rate-429", RateLimitRPS: 2, RateLimitBurst: 5})
	if err != nil {
		t.Fatal(err)
	}
	_ = tn
	master, err := keys.ParseMasterKey(os.Getenv("AUDITTRAIL_MASTER_KEY"))
	if err != nil {
		t.Skip(err)
	}
	pepper, _ := keys.ParsePepper(os.Getenv("AUDITTRAIL_KEY_PEPPER"))
	second := api.New(e.app, e.srv.Control, master, pepper, "x", nil, nil)
	api.RegisterExtensions(second)
	hs2 := httptest.NewServer(second)
	t.Cleanup(hs2.Close)
	clients := []*v2client.Client{{BaseURL: e.http.URL, APIKey: key}, {BaseURL: hs2.URL, APIKey: key}}
	ok, limited := 0, 0
	for i := range 20 {
		r, err := clients[i%2].PostOnce(ctx, "/v2/events", mustBody(t, event(fmt.Sprintf("rate.%d", i))))
		if err != nil {
			t.Fatal(err)
		}
		switch r.Status {
		case 202:
			ok++
		case 429:
			limited++
			if s, err := strconv.Atoi(r.Header.Get("Retry-After")); err != nil || s < 1 {
				t.Fatalf("429 without a usable Retry-After: %q", r.Header.Get("Retry-After"))
			}
		default:
			t.Fatalf("unexpected status %d", r.Status)
		}
	}
	// 20 requests in well under a second: burst 5 (+ at most a couple of refilled tokens).
	if ok > 7 || limited < 13 {
		t.Fatalf("across two servers: %d accepted, %d limited; want <= 7 accepted", ok, limited)
	}
}
