package record

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"audittrail.dev/packages/ingestion-go/internal/canon"
	"audittrail.dev/packages/ingestion-go/internal/contract"
)

// Record is a sealed ledger row as returned by the API.
type Record struct {
	ID               string          `json:"id"`
	TenantID         string          `json:"tenant_id"`
	Seq              int64           `json:"seq"`
	Timestamp        string          `json:"timestamp"`
	HumanPrincipalID *string         `json:"human_principal_id"`
	AgentID          string          `json:"agent_id"`
	ModelID          *string         `json:"model_id"`
	ModelVersion     *string         `json:"model_version"`
	DelegationChain  json.RawMessage `json:"delegation_chain"`
	Action           string          `json:"action"`
	TargetResource   string          `json:"target_resource"`
	Outcome          string          `json:"outcome"`
	Metadata         json.RawMessage `json:"metadata"`
	PreviousHash     string          `json:"previous_hash"`
	Hash             string          `json:"hash"`
	Signature        string          `json:"signature"`
	KeyID            string          `json:"key_id"`
	CreatedAt        string          `json:"created_at"`

	// v2 (spec_version 2) fields; absent on v1 rows.
	SpecVersion int             `json:"spec_version"`
	ReceivedAt  *string         `json:"received_at,omitempty"`
	Agent       json.RawMessage `json:"agent,omitempty"`
	Principal   json.RawMessage `json:"principal,omitempty"`
	Model       json.RawMessage `json:"model,omitempty"`
	PayloadHash *string         `json:"payload_hash,omitempty"`
	PIICT       json.RawMessage `json:"pii_ct,omitempty"`
}

// CanonEvent returns the hashed subset of the record.
func (r Record) CanonEvent() (canon.Event, error) {
	ts, err := time.Parse(time.RFC3339Nano, r.Timestamp)
	if err != nil {
		return canon.Event{}, fmt.Errorf("seq %d: bad timestamp %q", r.Seq, r.Timestamp)
	}
	return canon.Event{
		ID: r.ID, TenantID: r.TenantID, Timestamp: ts,
		HumanPrincipalID: r.HumanPrincipalID, AgentID: r.AgentID,
		ModelID: r.ModelID, ModelVersion: r.ModelVersion,
		DelegationChain: r.DelegationChain, Action: r.Action,
		TargetResource: r.TargetResource, Outcome: r.Outcome, Metadata: r.Metadata,
	}, nil
}

func parseOpt(raw []byte) (*contract.Value, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	v, err := contract.Parse(raw)
	if err != nil {
		return nil, errors.New(err.Error())
	}
	if v.Kind == contract.Null {
		return nil, nil
	}
	return v, nil
}

// V2Record rebuilds the hashed fields of a spec_version 2 row.
func (r Record) V2Record() (contract.Record, error) {
	if r.SpecVersion != 2 || r.ReceivedAt == nil || r.PayloadHash == nil {
		return contract.Record{}, fmt.Errorf("seq %d is not a complete v2 record", r.Seq)
	}
	var out contract.Record
	var err error
	if out.Agent, err = parseOpt(r.Agent); err != nil || out.Agent == nil {
		return out, fmt.Errorf("seq %d: bad agent", r.Seq)
	}
	if out.Principal, err = parseOpt(r.Principal); err != nil {
		return out, fmt.Errorf("seq %d: bad principal", r.Seq)
	}
	if out.Model, err = parseOpt(r.Model); err != nil {
		return out, fmt.Errorf("seq %d: bad model", r.Seq)
	}
	if out.PIICT, err = parseOpt(r.PIICT); err != nil {
		return out, fmt.Errorf("seq %d: bad pii_ct", r.Seq)
	}
	d, err := parseOpt(r.DelegationChain)
	if err != nil {
		return out, fmt.Errorf("seq %d: bad delegation", r.Seq)
	}
	if d == nil {
		d = &contract.Value{Kind: contract.Array, A: []*contract.Value{}}
	}
	out.Delegation = d
	out.TenantID, out.Seq, out.EventID = r.TenantID, r.Seq, r.ID
	out.OccurredAt, out.ReceivedAt = r.Timestamp, *r.ReceivedAt
	out.Action, out.Resource, out.Outcome = r.Action, r.TargetResource, r.Outcome
	out.PayloadHash, out.PrevHash = *r.PayloadHash, r.PreviousHash
	return out, nil
}

// RecomputeHash recomputes the row's hash from its stored content under the
// rules of its spec_version.
func (r Record) RecomputeHash() (string, error) {
	if r.SpecVersion == 2 {
		v, err := r.V2Record()
		if err != nil {
			return "", err
		}
		return v.Hash(), nil
	}
	ce, err := r.CanonEvent()
	if err != nil {
		return "", err
	}
	h, _, err := canon.HashEvent(r.PreviousHash, ce)
	return h, err
}

// SigningMessage is the message the row signature covers.
func (r Record) SigningMessage() []byte {
	if r.SpecVersion == 2 {
		return contract.ReceiptMessage(r.Hash)
	}
	return canon.EventSigningMessage(r.Hash)
}

// PayloadIntact reports whether a v2 row's stored payload still matches
// its payload_hash (the payload is committed to via payload_hash only).
func (r Record) PayloadIntact() bool {
	if r.SpecVersion != 2 || r.PayloadHash == nil {
		return true
	}
	p, err := parseOpt(r.Metadata)
	if err != nil {
		return false
	}
	return contract.PayloadHash(p) == *r.PayloadHash
}
