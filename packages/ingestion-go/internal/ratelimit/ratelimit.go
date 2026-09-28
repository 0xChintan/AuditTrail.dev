// Package ratelimit enforces per-tenant rate limits across all API
// instances. The token bucket lives in Postgres (rate_take, migration 007);
// each instance leases a small batch of tokens per round-trip and spends
// them locally, so the database sees about 20 calls per second per busy
// tenant per instance instead of one per request. Leased tokens expire
// after LeaseTTL rather than being returned, so the combined admission rate
// never exceeds the limit.
package ratelimit

import (
	"context"
	"log/slog"
	"math"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/time/rate"
)

// LeaseTTL bounds how long leased tokens stay usable on one instance.
const LeaseTTL = time.Second

type bucket struct {
	mu           sync.Mutex
	tokens       int
	expires      time.Time
	blockedUntil time.Time
	fallback     *rate.Limiter
}

// Shared is safe for concurrent use.
type Shared struct {
	Pool *pgxpool.Pool // a role with EXECUTE on rate_take (audittrail_control)
	Log  *slog.Logger
	Now  func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucket
}

func (s *Shared) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Shared) get(tenantID string) *bucket {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.buckets == nil {
		s.buckets = map[string]*bucket{}
	}
	b, ok := s.buckets[tenantID]
	if !ok {
		b = &bucket{}
		s.buckets[tenantID] = b
	}
	return b
}

// Allow admits one request for the tenant, or returns how long to wait.
func (s *Shared) Allow(ctx context.Context, tenantID string, rps, burst int) (bool, time.Duration) {
	if rps <= 0 || burst <= 0 {
		return true, 0
	}
	b := s.get(tenantID)
	// Holding the tenant's lock across the lease call means one instance
	// never has two leases in flight for a tenant (no thundering herd).
	b.mu.Lock()
	defer b.mu.Unlock()
	now := s.now()
	if b.tokens > 0 && now.Before(b.expires) {
		b.tokens--
		return true, 0
	}
	if now.Before(b.blockedUntil) {
		return false, b.blockedUntil.Sub(now)
	}
	want := max(1, min(burst, int(math.Ceil(float64(rps)/20))))
	var granted, waitMS int
	lctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	err := s.Pool.QueryRow(lctx, `SELECT granted, wait_ms FROM rate_take($1, $2, $3, $4)`,
		tenantID, float64(rps), float64(burst), want).Scan(&granted, &waitMS)
	if err != nil {
		// Availability over precision: fall back to this instance's own
		// bucket (the pre-shared behaviour) while the database call fails.
		if s.Log != nil {
			s.Log.Warn("shared rate limit unavailable; using the local limit", "tenant", tenantID, "err", err)
		}
		if b.fallback == nil || b.fallback.Limit() != rate.Limit(rps) || b.fallback.Burst() != burst {
			b.fallback = rate.NewLimiter(rate.Limit(rps), burst)
		}
		res := b.fallback.Reserve()
		if d := res.Delay(); d > 0 {
			res.Cancel()
			return false, d
		}
		return true, 0
	}
	now = s.now()
	if granted <= 0 {
		wait := max(time.Duration(waitMS)*time.Millisecond, 10*time.Millisecond)
		b.blockedUntil = now.Add(wait)
		return false, wait
	}
	b.tokens, b.expires = granted-1, now.Add(LeaseTTL)
	return true, 0
}
