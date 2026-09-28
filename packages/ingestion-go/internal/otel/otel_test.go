package otel_test

import (
	"os"
	"testing"

	"audittrail.dev/packages/ingestion-go/internal/contract"
	"audittrail.dev/packages/ingestion-go/internal/otel"
)

// v2 task 6.3 gate: the same trace exported by two different SDKs (OTel JS
// over OTLP/JSON, OTel Python over OTLP/protobuf) normalizes to identical
// events. Fixtures and their generators are in testdata/.
func TestTwoSDKsNormalizeToTheSameEvents(t *testing.T) {
	js, _ := os.ReadFile("testdata/js-sdk.json")
	pb, _ := os.ReadFile("testdata/py-sdk.pb")
	a, err := otel.DecodeJSON(js)
	if err != nil {
		t.Fatal(err)
	}
	b, err := otel.DecodeProto(pb)
	if err != nil {
		t.Fatal(err)
	}
	norm := func(spans []otel.Span) map[string]*contract.Envelope {
		out := map[string]*contract.Envelope{}
		for _, sp := range spans {
			body, err := otel.Normalize(sp)
			if err != nil || body == nil {
				t.Fatalf("span %s: %v", sp.Name, err)
			}
			env, cerr := contract.ValidateEnvelope(body)
			if cerr != nil {
				t.Fatalf("span %s fails the contract: %v\n%s", sp.Name, cerr, body)
			}
			out[env.EventID] = env
		}
		return out
	}
	ea, eb := norm(a), norm(b)
	if len(ea) != 3 || len(eb) != 3 {
		t.Fatalf("want 3 events from each SDK, got %d and %d", len(ea), len(eb))
	}
	for id, x := range ea {
		y, ok := eb[id]
		if !ok {
			t.Fatalf("event %s (%s) missing from the Python SDK fixture", id, x.Action)
		}
		if x.Digest != y.Digest {
			t.Errorf("%s %s: normalized envelopes differ between SDKs\nJS: %s\nPY: %s", x.Action, x.Resource,
				contract.JCS(x.Payload), contract.JCS(y.Payload))
		}
	}
	var tool, failed *contract.Envelope
	for _, e := range ea {
		if e.Resource == "tool://lookup_order" {
			tool = e
		}
		if e.Resource == "tool://refund_order" {
			failed = e
		}
	}
	if tool == nil || tool.Outcome != "allowed" || failed == nil || failed.Outcome != "error" {
		t.Fatal("tool spans not mapped to the expected resources/outcomes")
	}
	if p, _ := tool.Principal.Get("id"); p.S != "alice@example.com" {
		t.Fatal("principal not mapped from user.id")
	}
	t.Logf("3 spans from OTel JS (JSON) and OTel Python (protobuf) normalize to byte-identical envelopes")
}
