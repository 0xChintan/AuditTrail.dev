package api

import (
	"context"
	"time"
)

// StartMonitor watches MCP sidecars (threat T11): every sidecar event carries
// {sidecar: {id, seq}} and sidecars send periodic heartbeats. A sidecar that
// goes quiet without a clean "stopped" event, or whose seq has holes that
// don't fill in, gets an alert sealed into the tenant's own ledger.
func (s *Server) StartMonitor(ctx context.Context, every time.Duration) {
	if every <= 0 || s.Control == nil {
		return
	}
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.monitorOnce(ctx)
			}
		}
	}()
}

func (s *Server) monitorOnce(ctx context.Context) {
	conn, err := s.Control.Acquire(ctx)
	if err != nil {
		return
	}
	defer conn.Release()
	var locked bool
	if conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtext('audittrail.monitor'))`).Scan(&locked); !locked {
		return // another API instance is monitoring
	}
	defer conn.Exec(context.Background(), `SELECT pg_advisory_unlock(hashtext('audittrail.monitor'))`)

	rows, err := conn.Query(ctx, `
		WITH sc AS (
		  SELECT tenant_id, metadata->'sidecar'->>'id' AS sid,
		         count(*) AS n, max((metadata->'sidecar'->>'seq')::bigint) AS max_seq,
		         max(received_at) AS last_seen,
		         COALESCE(max((metadata->>'heartbeat_seconds')::int) FILTER (WHERE action LIKE 'audittrail.sidecar/%'), 60) AS hb,
		         bool_or(action = 'audittrail.sidecar/stopped') AS stopped
		    FROM agent_events
		   WHERE spec_version = 2 AND metadata ? 'sidecar' AND received_at > NOW() - interval '7 days'
		   GROUP BY 1, 2)
		SELECT sc.tenant_id, sc.sid, sc.n, sc.max_seq, sc.last_seen, sc.hb, sc.stopped,
		       EXISTS (SELECT 1 FROM agent_events a WHERE a.tenant_id = sc.tenant_id
		                  AND a.action IN ('audittrail.monitor/sidecar_silent', 'audittrail.monitor/sidecar_gap')
		                  AND a.target_resource = 'sidecar:' || sc.sid AND a.received_at > sc.last_seen) AS alerted
		  FROM sc`)
	if err != nil {
		if s.Log != nil {
			s.Log.Error("monitor query", "err", err)
		}
		return
	}
	type row struct {
		tenant, sid   string
		n, maxSeq     int64
		lastSeen      time.Time
		hb            int
		stopped, sent bool
	}
	var todo []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.tenant, &r.sid, &r.n, &r.maxSeq, &r.lastSeen, &r.hb, &r.stopped, &r.sent); err == nil {
			todo = append(todo, r)
		}
	}
	rows.Close()
	now := s.Now()
	for _, r := range todo {
		if r.sent || r.hb <= 0 {
			continue
		}
		quiet := now.Sub(r.lastSeen)
		limit := time.Duration(3*r.hb) * time.Second
		payload := map[string]any{"sidecar_id": r.sid, "last_seen": r.lastSeen.UTC().Format(time.RFC3339Nano),
			"heartbeat_seconds": r.hb, "events_received": r.n, "highest_seq": r.maxSeq, "missing": r.maxSeq - r.n}
		switch {
		case !r.stopped && quiet > limit:
			payload["silent_for_seconds"] = int(quiet.Seconds())
			s.Record(ctx, r.tenant, "audittrail-monitor", "audittrail.monitor/sidecar_silent", "sidecar:"+r.sid, "error", nil, payload)
		case r.n < r.maxSeq && quiet > 2*time.Duration(r.hb)*time.Second:
			s.Record(ctx, r.tenant, "audittrail-monitor", "audittrail.monitor/sidecar_gap", "sidecar:"+r.sid, "error", nil, payload)
		}
	}
}
