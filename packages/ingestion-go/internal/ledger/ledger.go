// Package ledger seals events into a tenant's hash chain (Task 2.2).
//
// Concurrency model: the chain head lives in chain_state (one row per
// tenant). Every append runs in a SERIALIZABLE transaction that takes
// SELECT ... FOR UPDATE on that row, recomputes the hash server-side, inserts
// the row and advances the head — all or nothing. Postgres therefore orders
// appends even across many API instances; serialization failures are retried.
// A per-tenant in-process mutex additionally queues requests inside one
// instance so they don't burn retries fighting each other.
package ledger

import (
	"bytes"

	"audittrail.dev/packages/ingestion-go/internal/record"
	"context"
	"crypto/ed25519"
	crand "crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"audittrail.dev/packages/ingestion-go/internal/canon"
	"audittrail.dev/packages/ingestion-go/internal/db"
	"audittrail.dev/packages/ingestion-go/internal/keys"
)

// Record is a sealed ledger row (defined in package record so the verifier
// can compile without the database driver, e.g. to WebAssembly).
type Record = record.Record

// SelectColumns is the column list ScanRecord expects.
const SelectColumns = `id, tenant_id, seq, timestamp, human_principal_id, agent_id, model_id,
	model_version, delegation_chain, action, target_resource, outcome, metadata,
	previous_hash, hash, signature, key_id, created_at,
	spec_version, received_at, agent, principal, model, payload_hash, pii_ct`

func ScanRecord(row pgx.Row) (Record, error) {
	var r Record
	var ts, created time.Time
	var dc, md, ag, pr, mo, pii []byte
	var recv *time.Time
	var sv int16
	err := row.Scan(&r.ID, &r.TenantID, &r.Seq, &ts, &r.HumanPrincipalID, &r.AgentID, &r.ModelID,
		&r.ModelVersion, &dc, &r.Action, &r.TargetResource, &r.Outcome, &md,
		&r.PreviousHash, &r.Hash, &r.Signature, &r.KeyID, &created,
		&sv, &recv, &ag, &pr, &mo, &r.PayloadHash, &pii)
	if err != nil {
		return r, err
	}
	r.SpecVersion = int(sv)
	if recv != nil {
		s := canon.FormatTime(*recv)
		r.ReceivedAt = &s
	}
	for _, x := range []struct {
		dst *json.RawMessage
		src []byte
	}{{&r.Agent, ag}, {&r.Principal, pr}, {&r.Model, mo}, {&r.PIICT, pii}} {
		if x.src != nil {
			*x.dst = json.RawMessage(x.src)
		}
	}
	r.Timestamp = canon.FormatTime(ts)
	r.CreatedAt = created.UTC().Format(time.RFC3339Nano)
	if dc != nil {
		r.DelegationChain = json.RawMessage(dc)
	}
	if md != nil {
		r.Metadata = json.RawMessage(md)
	}
	return r, nil
}

// Submission is the POST /v1/events body (schemas/event.schema.json).
type Submission struct {
	ID               *string         `json:"id"`
	Timestamp        *string         `json:"timestamp"`
	HumanPrincipalID *string         `json:"human_principal_id"`
	AgentID          string          `json:"agent_id"`
	ModelID          *string         `json:"model_id"`
	ModelVersion     *string         `json:"model_version"`
	DelegationChain  json.RawMessage `json:"delegation_chain"`
	Action           string          `json:"action"`
	TargetResource   string          `json:"target_resource"`
	Outcome          string          `json:"outcome"`
	Metadata         json.RawMessage `json:"metadata"`
	PreviousHash     *string         `json:"previous_hash"`
	Hash             *string         `json:"hash"`
}

// ---- errors ---------------------------------------------------------------

type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }

// ConflictError maps to HTTP 409.
type ConflictError struct {
	Code        string // head_mismatch | hash_mismatch | idempotency_conflict
	Msg         string
	CurrentHead string
	CurrentSeq  int64
	Expected    string
}

func (e *ConflictError) Error() string { return e.Msg }

var ErrTenantNotFound = errors.New("tenant chain not initialized")

// ---- sealer ---------------------------------------------------------------

type Sealer struct {
	Pool       *pgxpool.Pool
	Master     *keys.MasterKey
	MaxRetries int
	Now        func() time.Time

	locks   sync.Map // tenant_id -> *sync.Mutex
	privMu  sync.RWMutex
	privKey map[string]ed25519.PrivateKey // key_id -> key

	statsMu sync.Mutex
	Retries int64 // serialization retries observed (for tests/metrics)
}

func NewSealer(pool *pgxpool.Pool, master *keys.MasterKey) *Sealer {
	return &Sealer{Pool: pool, Master: master, MaxRetries: 50, Now: time.Now, privKey: map[string]ed25519.PrivateKey{}}
}

func (s *Sealer) tenantLock(tenantID string) *sync.Mutex {
	m, _ := s.locks.LoadOrStore(tenantID, &sync.Mutex{})
	return m.(*sync.Mutex)
}

func (s *Sealer) privateKey(tenantID, keyID, sealed string) (ed25519.PrivateKey, error) {
	s.privMu.RLock()
	k, ok := s.privKey[keyID]
	s.privMu.RUnlock()
	if ok {
		return k, nil
	}
	k, err := keys.OpenSigningKey(s.Master, tenantID, keyID, sealed)
	if err != nil {
		return nil, err
	}
	s.privMu.Lock()
	s.privKey[keyID] = k
	s.privMu.Unlock()
	return k, nil
}

var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// prepare validates a submission and resolves defaults (id, timestamp).
func (s *Sealer) prepare(tenantID string, sub Submission) (canon.Event, bool, error) {
	ev := canon.Event{
		TenantID: strings.ToLower(tenantID), HumanPrincipalID: sub.HumanPrincipalID,
		AgentID: sub.AgentID, ModelID: sub.ModelID, ModelVersion: sub.ModelVersion,
		DelegationChain: sub.DelegationChain, Action: sub.Action,
		TargetResource: sub.TargetResource, Outcome: sub.Outcome, Metadata: sub.Metadata,
	}
	if sub.ID != nil {
		if !uuidRe.MatchString(*sub.ID) {
			return ev, false, &ValidationError{"id must be a UUID"}
		}
		ev.ID = strings.ToLower(*sub.ID)
	} else {
		ev.ID = newUUID()
	}
	tsGiven := sub.Timestamp != nil
	if tsGiven {
		t, err := time.Parse(time.RFC3339Nano, *sub.Timestamp)
		if err != nil {
			return ev, false, &ValidationError{"timestamp must be RFC 3339"}
		}
		ev.Timestamp = canon.NormalizeTime(t)
	} else {
		ev.Timestamp = canon.NormalizeTime(s.Now())
	}
	for _, p := range []*string{sub.PreviousHash, sub.Hash} {
		if p != nil && !canon.IsHexHash(*p) {
			return ev, false, &ValidationError{"previous_hash / hash must be 64 lowercase hex chars"}
		}
	}
	if err := canon.Validate(ev); err != nil {
		return ev, false, &ValidationError{err.Error()}
	}
	if _, err := canon.Payload(ev); err != nil {
		return ev, false, &ValidationError{"metadata/delegation_chain not canonicalizable: " + err.Error()}
	}
	return ev, tsGiven, nil
}

// Seal appends one event. replay=true means the id was already sealed with
// identical content and the existing record is returned (idempotent retry).
func (s *Sealer) Seal(ctx context.Context, tenantID string, sub Submission) (rec Record, replay bool, err error) {
	ev, tsGiven, err := s.prepare(tenantID, sub)
	if err != nil {
		return Record{}, false, err
	}
	mu := s.tenantLock(ev.TenantID)
	mu.Lock()
	defer mu.Unlock()

	for attempt := 0; ; attempt++ {
		rec, replay, err = s.sealOnce(ctx, ev, tsGiven, sub)
		if err == nil || !db.IsRetryable(err) || attempt >= s.MaxRetries {
			return rec, replay, err
		}
		s.statsMu.Lock()
		s.Retries++
		s.statsMu.Unlock()
		backoff := time.Duration(1+rand.IntN(4<<min(attempt, 5))) * time.Millisecond // #nosec G404 -- retry jitter, not security-sensitive
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return Record{}, false, ctx.Err()
		}
	}
}

func (s *Sealer) sealOnce(ctx context.Context, ev canon.Event, tsGiven bool, sub Submission) (Record, bool, error) {
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return Record{}, false, err
	}
	defer tx.Rollback(ctx)

	var head string
	var lastSeq int64
	err = tx.QueryRow(ctx, `SELECT previous_hash, last_seq FROM chain_state WHERE tenant_id = $1 FOR UPDATE`, ev.TenantID).Scan(&head, &lastSeq)
	if errors.Is(err, pgx.ErrNoRows) {
		return Record{}, false, ErrTenantNotFound
	}
	if err != nil {
		return Record{}, false, err
	}

	// Idempotency: same id already sealed?
	if existing, err := ScanRecord(tx.QueryRow(ctx, `SELECT `+SelectColumns+` FROM agent_events WHERE tenant_id=$1 AND id=$2`, ev.TenantID, ev.ID)); err == nil {
		cand := ev
		if !tsGiven {
			t, _ := time.Parse(time.RFC3339Nano, existing.Timestamp)
			cand.Timestamp = t
		}
		exEv, _ := existing.CanonEvent()
		a, err1 := canon.Payload(cand)
		b, err2 := canon.Payload(exEv)
		if err1 == nil && err2 == nil && bytes.Equal(a, b) {
			return existing, true, nil
		}
		return Record{}, false, &ConflictError{Code: "idempotency_conflict",
			Msg: "an event with this id was already sealed with different content"}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return Record{}, false, err
	}

	if sub.PreviousHash != nil && *sub.PreviousHash != head {
		return Record{}, false, &ConflictError{Code: "head_mismatch",
			Msg:         "previous_hash is not the current chain head",
			CurrentHead: head, CurrentSeq: lastSeq}
	}
	hash, _, err := canon.HashEvent(head, ev)
	if err != nil {
		return Record{}, false, &ValidationError{err.Error()}
	}
	if sub.Hash != nil && *sub.Hash != hash {
		return Record{}, false, &ConflictError{Code: "hash_mismatch",
			Msg: "claimed hash does not match server recomputation", Expected: hash,
			CurrentHead: head, CurrentSeq: lastSeq}
	}

	var keyID, sealed string
	if err := tx.QueryRow(ctx, `SELECT key_id, private_key_enc FROM signing_keys WHERE tenant_id=$1 AND retired_at IS NULL`, ev.TenantID).Scan(&keyID, &sealed); err != nil {
		return Record{}, false, fmt.Errorf("no active signing key: %w", err)
	}
	priv, err := s.privateKey(ev.TenantID, keyID, sealed)
	if err != nil {
		return Record{}, false, err
	}
	sig := keys.Sign(priv, canon.EventSigningMessage(hash))

	seq := lastSeq + 1
	rec, err := ScanRecord(tx.QueryRow(ctx, `INSERT INTO agent_events
		(id, tenant_id, seq, timestamp, human_principal_id, agent_id, model_id, model_version,
		 delegation_chain, action, target_resource, outcome, metadata, previous_hash, hash, signature, key_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)
		RETURNING `+SelectColumns,
		ev.ID, ev.TenantID, seq, ev.Timestamp, ev.HumanPrincipalID, ev.AgentID, ev.ModelID, ev.ModelVersion,
		nullJSON(ev.DelegationChain), ev.Action, ev.TargetResource, ev.Outcome, nullJSON(ev.Metadata),
		head, hash, sig, keyID))
	if err != nil {
		if db.IsUniqueViolation(err) && strings.Contains(err.Error(), "agent_events_pkey") {
			return Record{}, false, &ConflictError{Code: "idempotency_conflict", Msg: "event id already used"}
		}
		return Record{}, false, err
	}
	// Belt and braces: the row as stored (jsonb round-trip included) must
	// re-canonicalize to the same hash, or we refuse to commit it.
	ce, err := rec.CanonEvent()
	if err != nil {
		return Record{}, false, err
	}
	if h, _, err := canon.HashEvent(rec.PreviousHash, ce); err != nil || h != rec.Hash {
		return Record{}, false, &ValidationError{"event does not round-trip through storage unchanged (unsupported JSON value?)"}
	}
	if _, err := tx.Exec(ctx, `UPDATE chain_state SET previous_hash=$2, last_seq=$3, updated_at=NOW() WHERE tenant_id=$1`, ev.TenantID, hash, seq); err != nil {
		return Record{}, false, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Record{}, false, err
	}
	return rec, false, nil
}

func nullJSON(r json.RawMessage) any {
	t := bytes.TrimSpace(r)
	if len(t) == 0 || bytes.Equal(t, []byte("null")) {
		return nil
	}
	return string(t)
}

// Head returns the tenant's current chain head.
func Head(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, tenantID string) (hash string, seq int64, err error) {
	err = q.QueryRow(ctx, `SELECT previous_hash, last_seq FROM chain_state WHERE tenant_id=$1`, tenantID).Scan(&hash, &seq)
	return
}

func newUUID() string {
	var b [16]byte
	if _, err := crand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
