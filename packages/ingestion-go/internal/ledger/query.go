package ledger

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Filter struct {
	AfterSeq  int64
	BeforeSeq int64
	FromSeq   int64 // inclusive
	ToSeq     int64 // inclusive
	AgentID   string
	Outcome   string
	Action    string
	Principal string
	From      *time.Time
	To        *time.Time
	Limit     int
	Desc      bool
}

type Querier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

func ListEvents(ctx context.Context, q Querier, tenantID string, f Filter) ([]Record, error) {
	where := []string{"tenant_id = $1"}
	args := []any{tenantID}
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, fmt.Sprintf(cond, len(args)))
	}
	if f.AfterSeq > 0 {
		add("seq > $%d", f.AfterSeq)
	}
	if f.BeforeSeq > 0 {
		add("seq < $%d", f.BeforeSeq)
	}
	if f.FromSeq > 0 {
		add("seq >= $%d", f.FromSeq)
	}
	if f.ToSeq > 0 {
		add("seq <= $%d", f.ToSeq)
	}
	if f.AgentID != "" {
		add("agent_id = $%d", f.AgentID)
	}
	if f.Outcome != "" {
		add("outcome = $%d", f.Outcome)
	}
	if f.Action != "" {
		add("action = $%d", f.Action)
	}
	if f.Principal != "" {
		add("human_principal_id = $%d", f.Principal)
	}
	if f.From != nil {
		add("timestamp >= $%d", *f.From)
	}
	if f.To != nil {
		add("timestamp <= $%d", *f.To)
	}
	order := "ASC"
	if f.Desc {
		order = "DESC"
	}
	sql := `SELECT ` + SelectColumns + ` FROM agent_events WHERE ` + strings.Join(where, " AND ") + ` ORDER BY seq ` + order
	if f.Limit > 0 {
		sql += fmt.Sprintf(" LIMIT %d", f.Limit)
	}
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Record{}
	for rows.Next() {
		r, err := ScanRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

var ErrNotFound = errors.New("not found")

func GetEvent(ctx context.Context, q Querier, tenantID, id string) (Record, error) {
	r, err := ScanRecord(q.QueryRow(ctx, `SELECT `+SelectColumns+` FROM agent_events WHERE tenant_id=$1 AND id=$2`, tenantID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return r, ErrNotFound
	}
	return r, err
}

type Stats struct {
	Total      int64            `json:"total"`
	ByOutcome  map[string]int64 `json:"by_outcome"`
	Last24h    int64            `json:"last_24h"`
	TopAgents  []NameCount      `json:"top_agents"`
	TopActions []NameCount      `json:"top_actions"`
	HeadSeq    int64            `json:"head_seq"`
	HeadHash   string           `json:"head_hash"`
	OldestSeq  int64            `json:"oldest_seq"`
}

type NameCount struct {
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

func GetStats(ctx context.Context, pool *pgxpool.Pool, tenantID string) (Stats, error) {
	s := Stats{ByOutcome: map[string]int64{"allowed": 0, "denied": 0, "error": 0}}
	var err error
	if s.HeadHash, s.HeadSeq, err = Head(ctx, pool, tenantID); err != nil {
		return s, err
	}
	rows, err := pool.Query(ctx, `SELECT outcome, count(*) FROM agent_events WHERE tenant_id=$1 GROUP BY outcome`, tenantID)
	if err != nil {
		return s, err
	}
	for rows.Next() {
		var o string
		var n int64
		if err := rows.Scan(&o, &n); err != nil {
			rows.Close()
			return s, err
		}
		s.ByOutcome[o] = n
		s.Total += n
	}
	rows.Close()
	if err := pool.QueryRow(ctx, `SELECT count(*), COALESCE(min(seq),0) FROM agent_events WHERE tenant_id=$1 AND created_at > NOW() - interval '24 hours'`, tenantID).Scan(&s.Last24h, new(int64)); err != nil {
		return s, err
	}
	if err := pool.QueryRow(ctx, `SELECT COALESCE(min(seq),0) FROM agent_events WHERE tenant_id=$1`, tenantID).Scan(&s.OldestSeq); err != nil {
		return s, err
	}
	top := func(col string) ([]NameCount, error) {
		rows, err := pool.Query(ctx, `SELECT `+col+`, count(*) c FROM agent_events WHERE tenant_id=$1 GROUP BY 1 ORDER BY c DESC LIMIT 8`, tenantID)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out := []NameCount{}
		for rows.Next() {
			var nc NameCount
			if err := rows.Scan(&nc.Name, &nc.Count); err != nil {
				return nil, err
			}
			out = append(out, nc)
		}
		return out, rows.Err()
	}
	if s.TopAgents, err = top("agent_id"); err != nil {
		return s, err
	}
	s.TopActions, err = top("action")
	return s, err
}
