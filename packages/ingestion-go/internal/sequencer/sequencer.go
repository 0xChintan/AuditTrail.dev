// Package sequencer is the single writer of each tenant's v2 log (v2 task
// 1.3). The server is the only sequencer: clients never supply chain links.
//
// Group commit: requests for one tenant queue on a per-tenant lane. The lane
// takes up to MaxBatch pending requests, locks the tenant's chain head once
// (SELECT … FOR UPDATE), appends the whole batch in one transaction and
// answers every request. Correctness across API instances still comes from
// the row lock, since every instance must hold it to append.
package sequencer

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"audittrail.dev/packages/ingestion-go/internal/contract"
	"audittrail.dev/packages/ingestion-go/internal/db"
	"audittrail.dev/packages/ingestion-go/internal/keys"
)

// Receipt is returned for every accepted (or replayed) event.
type Receipt struct {
	SpecVersion string `json:"spec_version"`
	EventID     string `json:"event_id"`
	TenantID    string `json:"tenant_id"`
	Seq         int64  `json:"seq"`
	OccurredAt  string `json:"occurred_at"`
	ReceivedAt  string `json:"received_at"`
	PrevHash    string `json:"prev_hash"`
	Hash        string `json:"hash"`
	Signature   string `json:"receipt_signature"`
	KeyID       string `json:"key_id"`
}

var (
	ErrConflict       = errors.New("idempotency_conflict")
	ErrTenantNotFound = errors.New("tenant log not initialized")
	ErrPIIDisabled    = errors.New("pii encryption is not configured")
)

// PIIEncrypter turns plaintext PII into the pii_ct object (v2 phase 5).
type PIIEncrypter interface {
	Encrypt(ctx context.Context, tx pgx.Tx, tenantID, eventID string, pii *contract.PII) (*contract.Value, error)
}

type Sequencer struct {
	Pool     *pgxpool.Pool
	Master   *keys.MasterKey
	PII      PIIEncrypter
	MaxBatch int
	Now      func() time.Time

	mu    sync.Mutex
	lanes map[string]chan *item

	privMu sync.Mutex
	priv   map[string]ed25519.PrivateKey

	statsMu sync.Mutex
	Batches int64
	Events  int64
}

type item struct {
	ctx  context.Context
	env  *contract.Envelope
	done chan result
}

type result struct {
	rec    Receipt
	replay bool
	err    error
}

func New(pool *pgxpool.Pool, master *keys.MasterKey) *Sequencer {
	return &Sequencer{Pool: pool, Master: master, MaxBatch: 256, Now: time.Now,
		lanes: map[string]chan *item{}, priv: map[string]ed25519.PrivateKey{}}
}

// Submit sequences one validated envelope. replay=true means the event_id
// was already sealed with an identical body and the original receipt is
// returned.
func (s *Sequencer) Submit(ctx context.Context, tenantID string, env *contract.Envelope) (Receipt, bool, error) {
	it := &item{ctx: ctx, env: env, done: make(chan result, 1)}
	lane := s.lane(tenantID)
	select {
	case lane <- it:
	case <-ctx.Done():
		return Receipt{}, false, ctx.Err()
	}
	select {
	case r := <-it.done:
		return r.rec, r.replay, r.err
	case <-ctx.Done():
		// The batch may still commit; a retry with the same event_id will
		// get the receipt as an idempotent replay.
		return Receipt{}, false, ctx.Err()
	}
}

func (s *Sequencer) lane(tenantID string) chan *item {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch, ok := s.lanes[tenantID]
	if !ok {
		ch = make(chan *item, 8192)
		s.lanes[tenantID] = ch
		go s.run(tenantID, ch)
	}
	return ch
}

func (s *Sequencer) run(tenantID string, ch chan *item) {
	max := s.MaxBatch
	if max < 1 {
		max = 1
	}
	for first := range ch {
		batch := []*item{first}
	drain:
		for len(batch) < max {
			select {
			case it := <-ch:
				batch = append(batch, it)
			default:
				break drain
			}
		}
		// Drop requests whose callers already gave up before we started.
		live := batch[:0]
		for _, it := range batch {
			if it.ctx.Err() == nil {
				live = append(live, it)
			} else {
				it.done <- result{err: it.ctx.Err()}
			}
		}
		if len(live) > 0 {
			s.process(tenantID, live)
		}
	}
}

func (s *Sequencer) process(tenantID string, batch []*item) {
	results := make([]result, len(batch))
	err := s.withRetry(func() error { return s.commit(tenantID, batch, results) })
	if err != nil && len(batch) > 1 {
		// Isolate: one bad event must not fail its neighbours.
		for i, it := range batch {
			one := make([]result, 1)
			if e := s.withRetry(func() error { return s.commit(tenantID, []*item{it}, one) }); e != nil {
				results[i] = result{err: e}
			} else {
				results[i] = one[0]
			}
		}
	} else if err != nil {
		results[0] = result{err: err}
	}
	for i, it := range batch {
		it.done <- results[i]
	}
}

func (s *Sequencer) withRetry(fn func() error) error {
	var err error
	for attempt := 0; attempt < 8; attempt++ {
		if err = fn(); err == nil || !db.IsRetryable(err) {
			return err
		}
		time.Sleep(time.Duration(attempt+1) * 5 * time.Millisecond)
	}
	return err
}

func (s *Sequencer) signer(tenantID, keyID, sealed string) (ed25519.PrivateKey, error) {
	s.privMu.Lock()
	defer s.privMu.Unlock()
	if k, ok := s.priv[keyID]; ok {
		return k, nil
	}
	k, err := keys.OpenSigningKey(s.Master, tenantID, keyID, sealed)
	if err != nil {
		return nil, err
	}
	s.priv[keyID] = k
	return k, nil
}

type existingRow struct {
	digest *string
	rec    Receipt
}

const colsPerRow = 25

// commit appends one batch atomically, filling results.
func (s *Sequencer) commit(tenantID string, batch []*item, results []result) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return db.InTenant(ctx, s.Pool, tenantID, func(tx pgx.Tx) error {
		var prev string
		var lastSeq int64
		err := tx.QueryRow(ctx, `SELECT previous_hash, last_seq FROM chain_state WHERE tenant_id=$1 FOR UPDATE`, tenantID).Scan(&prev, &lastSeq)
		if errors.Is(err, pgx.ErrNoRows) {
			for i := range results {
				results[i] = result{err: ErrTenantNotFound}
			}
			return nil
		}
		if err != nil {
			return err
		}
		ids := make([]string, 0, len(batch))
		for _, it := range batch {
			ids = append(ids, it.env.EventID)
		}
		existing := map[string]existingRow{}
		rows, err := tx.Query(ctx, `SELECT id, request_digest, seq, timestamp, received_at, previous_hash, hash, signature, key_id
			FROM agent_events WHERE tenant_id=$1 AND id = ANY($2::uuid[])`, tenantID, ids)
		if err != nil {
			return err
		}
		for rows.Next() {
			var e existingRow
			var ts time.Time
			var recv *time.Time
			if err := rows.Scan(&e.rec.EventID, &e.digest, &e.rec.Seq, &ts, &recv, &e.rec.PrevHash, &e.rec.Hash, &e.rec.Signature, &e.rec.KeyID); err != nil {
				rows.Close()
				return err
			}
			e.rec.SpecVersion, e.rec.TenantID = "2", tenantID
			e.rec.OccurredAt = ts.UTC().Format(contract.TimeLayout)
			if recv != nil {
				e.rec.ReceivedAt = recv.UTC().Format(contract.TimeLayout)
			}
			existing[e.rec.EventID] = e
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		var keyID, sealed string
		if err := tx.QueryRow(ctx, `SELECT key_id, private_key_enc FROM signing_keys WHERE tenant_id=$1 AND retired_at IS NULL`, tenantID).Scan(&keyID, &sealed); err != nil {
			return fmt.Errorf("no active signing key: %w", err)
		}
		priv, err := s.signer(tenantID, keyID, sealed)
		if err != nil {
			return err
		}

		now := s.Now().UTC().Truncate(time.Millisecond)
		receivedAt := now.Format(contract.TimeLayout)
		var args []any
		var values []string
		inBatch := map[string]int{} // event_id -> index of the item that sealed it
		for i, it := range batch {
			e := it.env
			if ex, ok := existing[e.EventID]; ok {
				if ex.digest != nil && *ex.digest == e.Digest {
					results[i] = result{rec: ex.rec, replay: true}
				} else {
					results[i] = result{err: ErrConflict}
				}
				continue
			}
			if j, ok := inBatch[e.EventID]; ok {
				if batch[j].env.Digest == e.Digest {
					results[i] = result{rec: results[j].rec, replay: true}
				} else {
					results[i] = result{err: ErrConflict}
				}
				continue
			}
			var piiCT *contract.Value
			if e.PII != nil {
				if s.PII == nil {
					results[i] = result{err: ErrPIIDisabled}
					continue
				}
				if piiCT, err = s.PII.Encrypt(ctx, tx, tenantID, e.EventID, e.PII); err != nil {
					return err
				}
			}
			lastSeq++
			rec := contract.Record{TenantID: tenantID, Seq: lastSeq, EventID: e.EventID, OccurredAt: e.OccurredAt,
				ReceivedAt: receivedAt, Agent: e.Agent, Principal: e.Principal, Model: e.Model, Delegation: e.Delegation,
				Action: e.Action, Resource: e.Resource, Outcome: e.Outcome, PayloadHash: e.PayloadHash, PIICT: piiCT, PrevHash: prev}
			hash := rec.Hash()
			sig := keys.Sign(priv, contract.ReceiptMessage(hash))
			occurred, _ := time.Parse(contract.TimeLayout, e.OccurredAt)

			var principalID, modelID, modelVersion *string
			if e.Principal != nil {
				v, _ := e.Principal.Get("id")
				principalID = &v.S
			}
			if e.Model != nil {
				v, _ := e.Model.Get("id")
				modelID = &v.S
				if mv, ok := e.Model.Get("version"); ok && mv.Kind == contract.String {
					modelVersion = &mv.S
				}
			}
			agentID, _ := e.Agent.Get("id")
			base := len(args)
			ph := make([]string, colsPerRow)
			for k := range ph {
				ph[k] = fmt.Sprintf("$%d", base+k+1)
			}
			values = append(values, "("+strings.Join(ph, ",")+")")
			args = append(args,
				e.EventID, tenantID, lastSeq, occurred, principalID, agentID.S, modelID, modelVersion,
				string(contract.JCS(e.Delegation)), e.Action, e.Resource, e.Outcome, jsonOrNil(e.Payload),
				prev, hash, sig, keyID,
				2, now, string(contract.JCS(e.Agent)), jsonOrNil(e.Principal), jsonOrNil(e.Model), e.PayloadHash,
				jsonOrNil(piiCT), e.Digest)
			results[i] = result{rec: Receipt{SpecVersion: "2", EventID: e.EventID, TenantID: tenantID, Seq: lastSeq,
				OccurredAt: e.OccurredAt, ReceivedAt: receivedAt, PrevHash: prev, Hash: hash, Signature: sig, KeyID: keyID}}
			inBatch[e.EventID] = i
			prev = hash
		}
		if len(values) == 0 {
			return nil
		}
		if _, err := tx.Exec(ctx, `INSERT INTO agent_events (id, tenant_id, seq, timestamp, human_principal_id, agent_id,
			model_id, model_version, delegation_chain, action, target_resource, outcome, metadata,
			previous_hash, hash, signature, key_id,
			spec_version, received_at, agent, principal, model, payload_hash, pii_ct, request_digest)
			VALUES `+strings.Join(values, ","), args...); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE chain_state SET previous_hash=$2, last_seq=$3, updated_at=NOW() WHERE tenant_id=$1`, tenantID, prev, lastSeq); err != nil {
			return err
		}
		s.statsMu.Lock()
		s.Batches++
		s.Events += int64(len(values))
		s.statsMu.Unlock()
		return nil
	})
}

func jsonOrNil(v *contract.Value) any {
	if v == nil || v.Kind == contract.Null {
		return nil
	}
	return string(contract.JCS(v))
}

// ---- server-generated events ----------------------------------------------------------

// Internal builds a v2 envelope for an event the server itself records
// (admin changes, monitor alerts, erasures).
func Internal(now time.Time, agentID, action, resource, outcome string, principal *contract.Value, payload any) (*contract.Envelope, error) {
	p, err := contract.FromGo(payload)
	if err != nil {
		return nil, err
	}
	env := &contract.Envelope{
		EventID:    keys.NewUUIDv7(now),
		OccurredAt: now.UTC().Truncate(time.Millisecond).Format(contract.TimeLayout),
		Agent:      contract.MustFromGo(map[string]string{"id": agentID}),
		Principal:  principal,
		Delegation: &contract.Value{Kind: contract.Array, A: []*contract.Value{}},
		Action:     action, Resource: resource, Outcome: outcome,
		Payload: p, PayloadHash: contract.PayloadHash(p),
	}
	// Digest over the canonical envelope, exactly as for client submissions.
	body := map[string]any{"spec_version": "2", "event_id": env.EventID, "occurred_at": env.OccurredAt,
		"agent": json.RawMessage(contract.JCS(env.Agent)), "delegation": []any{}, "action": action,
		"resource": resource, "outcome": outcome, "payload": json.RawMessage(contract.JCS(p)), "payload_hash": env.PayloadHash}
	if principal != nil {
		body["principal"] = json.RawMessage(contract.JCS(principal))
	}
	b, _ := json.Marshal(body)
	full, verr := contract.ValidateEnvelope(b)
	if verr != nil {
		return nil, verr
	}
	return full, nil
}
