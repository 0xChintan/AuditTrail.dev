// Package canon implements the byte-exact hashing rules in schemas/SPEC.md.
// Every other component (TS core, browser verifier) must agree with it; see
// schemas/test-vectors.json.
package canon

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gowebpki/jcs"
)

// Genesis is the previous_hash of a tenant's first row.
var Genesis = strings.Repeat("0", 64)

const (
	EventSigPrefix = "audittrail.event.v1\n"
	TimeLayout     = "2006-01-02T15:04:05.000Z"
)

// Event holds exactly the fields covered by the chain hash.
type Event struct {
	ID               string
	TenantID         string
	Timestamp        time.Time
	HumanPrincipalID *string
	AgentID          string
	ModelID          *string
	ModelVersion     *string
	DelegationChain  json.RawMessage // JSON array or nil
	Action           string
	TargetResource   string
	Outcome          string
	Metadata         json.RawMessage // JSON object or nil
}

// NormalizeTime truncates to millisecond precision in UTC — the precision
// both Go and JS can round-trip exactly.
func NormalizeTime(t time.Time) time.Time { return t.UTC().Truncate(time.Millisecond) }

func FormatTime(t time.Time) string { return NormalizeTime(t).Format(TimeLayout) }

// Canonicalize returns the RFC 8785 (JCS) form of arbitrary JSON.
func Canonicalize(raw []byte) ([]byte, error) { return jcs.Transform(raw) }

func rawOrNull(r json.RawMessage) json.RawMessage {
	if len(bytes.TrimSpace(r)) == 0 {
		return json.RawMessage("null")
	}
	return r
}

// Payload returns canonical_payload for an event.
func Payload(e Event) ([]byte, error) {
	obj := map[string]any{
		"v":                  1,
		"id":                 strings.ToLower(e.ID),
		"tenant_id":          strings.ToLower(e.TenantID),
		"timestamp":          FormatTime(e.Timestamp),
		"human_principal_id": e.HumanPrincipalID,
		"agent_id":           e.AgentID,
		"model_id":           e.ModelID,
		"model_version":      e.ModelVersion,
		"delegation_chain":   rawOrNull(e.DelegationChain),
		"action":             e.Action,
		"target_resource":    e.TargetResource,
		"outcome":            e.Outcome,
		"metadata":           rawOrNull(e.Metadata),
	}
	raw, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}
	return jcs.Transform(raw)
}

// ChainHash = hex(SHA-256(ascii(prev) || payload)).
func ChainHash(prev string, payload []byte) string {
	h := sha256.New()
	h.Write([]byte(prev))
	h.Write(payload)
	return hex.EncodeToString(h.Sum(nil))
}

// HashEvent is Payload + ChainHash.
func HashEvent(prev string, e Event) (hash string, payload []byte, err error) {
	payload, err = Payload(e)
	if err != nil {
		return "", nil, err
	}
	return ChainHash(prev, payload), payload, nil
}

// EventSigningMessage is the byte string an event signature covers.
func EventSigningMessage(hash string) []byte { return []byte(EventSigPrefix + hash) }

// IsHexHash reports whether s is a 64-char lowercase hex string.
func IsHexHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

var validOutcomes = map[string]bool{"allowed": true, "denied": true, "error": true}

// Validate checks structural rules the hash depends on.
func Validate(e Event) error {
	var errs []string
	if e.AgentID == "" {
		errs = append(errs, "agent_id is required (use \"unknown\" if not known)")
	}
	if e.Action == "" {
		errs = append(errs, "action is required")
	}
	if e.TargetResource == "" {
		errs = append(errs, "target_resource is required")
	}
	if !validOutcomes[e.Outcome] {
		errs = append(errs, "outcome must be one of allowed|denied|error")
	}
	if d := bytes.TrimSpace(e.DelegationChain); len(d) > 0 && !bytes.Equal(d, []byte("null")) && d[0] != '[' {
		errs = append(errs, "delegation_chain must be an array or null")
	}
	if m := bytes.TrimSpace(e.Metadata); len(m) > 0 && !bytes.Equal(m, []byte("null")) && m[0] != '{' {
		errs = append(errs, "metadata must be an object or null")
	}
	for _, r := range [][]byte{e.DelegationChain, e.Metadata} {
		// Postgres jsonb rejects \u0000; reject up front so the stored row
		// always round-trips to the same canonical bytes.
		if bytes.Contains(r, []byte(`\u0000`)) {
			errs = append(errs, "JSON values may not contain \\u0000")
			break
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// CheckpointStatement is the object a checkpoint signs and anchors (SPEC §4).
type CheckpointStatement struct {
	Type               string `json:"type"`
	TenantID           string `json:"tenant_id"`
	FirstSeq           int64  `json:"first_seq"`
	LastSeq            int64  `json:"last_seq"`
	RowCount           int64  `json:"row_count"`
	MerkleRoot         string `json:"merkle_root"`
	HeadHash           string `json:"head_hash"`
	PrevCheckpointHead string `json:"prev_checkpoint_head"`
	CreatedAt          string `json:"created_at"`
}

const CheckpointType = "audittrail.checkpoint.v1"

// Bytes returns the JCS-canonical statement bytes.
func (s CheckpointStatement) Bytes() ([]byte, error) {
	raw, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	return jcs.Transform(raw)
}
