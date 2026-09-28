package contract_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"audittrail.dev/packages/ingestion-go/internal/contract"
)

func seed(f *testing.F) {
	raw, err := os.ReadFile("../../../../schemas/v2/vectors.json")
	if err != nil {
		return
	}
	var vf struct {
		JCS     []struct{ Input string } `json:"jcs"`
		Valid   []struct{ Body string }  `json:"valid_envelopes"`
		Invalid []struct {
			Body    string `json:"body"`
			BodyB64 string `json:"body_b64"`
		} `json:"invalid_envelopes"`
	}
	json.Unmarshal(raw, &vf)
	for _, c := range vf.JCS {
		f.Add([]byte(c.Input))
	}
	for _, c := range vf.Valid {
		f.Add([]byte(c.Body))
	}
	for _, c := range vf.Invalid {
		if c.BodyB64 != "" {
			b, _ := base64.StdEncoding.DecodeString(c.BodyB64)
			f.Add(b)
		} else {
			f.Add([]byte(c.Body))
		}
	}
}

// FuzzParse: the strict parser never panics, and canonicalization is a
// fixed point (JCS of accepted input re-parses to identical bytes).
func FuzzParse(f *testing.F) {
	seed(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := contract.Parse(data)
		if err != nil {
			if err.Status != 400 && err.Status != 413 {
				t.Fatalf("parse error with status %d", err.Status)
			}
			return
		}
		c1 := contract.JCS(v)
		v2, err := contract.Parse(c1)
		if err != nil {
			t.Fatalf("canonical output does not re-parse: %v\n%q", err, c1)
		}
		if c2 := contract.JCS(v2); !bytes.Equal(c1, c2) {
			t.Fatalf("JCS not a fixed point:\n%q\n%q", c1, c2)
		}
	})
}

// FuzzValidateEnvelope: validation never panics and only ever answers
// 400/413/422; accepted envelopes hash deterministically.
func FuzzValidateEnvelope(f *testing.F) {
	seed(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		e, err := contract.ValidateEnvelope(data)
		if err != nil {
			switch err.Status {
			case 400, 413, 422:
			default:
				t.Fatalf("unexpected status %d", err.Status)
			}
			if err.Code == "" {
				t.Fatal("empty error code")
			}
			return
		}
		e2, err2 := contract.ValidateEnvelope(data)
		if err2 != nil || e2.Digest != e.Digest || e2.PayloadHash != e.PayloadHash {
			t.Fatal("validation not deterministic")
		}
		r := contract.Record{TenantID: "t", Seq: 1, EventID: e.EventID, OccurredAt: e.OccurredAt, ReceivedAt: e.OccurredAt,
			Agent: e.Agent, Principal: e.Principal, Model: e.Model, Delegation: e.Delegation, Action: e.Action,
			Resource: e.Resource, Outcome: e.Outcome, PayloadHash: e.PayloadHash, PrevHash: contract.Genesis}
		if r.Hash() != r.Hash() {
			t.Fatal("hash not deterministic")
		}
	})
}
