// Package otel turns OpenTelemetry GenAI spans (OTLP/HTTP, JSON or
// protobuf) into v2 audit envelopes (v2 task 6.3).
//
// The GenAI semantic conventions are still "Development", so attribute names
// move between releases. All knowledge of them lives in one adapter with
// explicitly pinned convention versions. Unknown versions fall back to
// attribute sniffing, and the adapter version used is recorded in every
// event.
package otel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"

	"audittrail.dev/packages/ingestion-go/internal/contract"
)

// Span is the SDK-independent view of one span.
type Span struct {
	TraceID, SpanID, ParentSpanID string // lowercase hex
	Name                          string
	StartNano, EndNano            uint64
	StatusError                   bool
	StatusMessage                 string
	Attrs                         map[string]any
	Resource                      map[string]any
	ScopeName, SchemaURL          string
}

// ---- decoding ---------------------------------------------------------------------------

// DecodeProto parses an OTLP ExportTraceServiceRequest (protobuf).
func DecodeProto(b []byte) ([]Span, error) {
	// ExportTraceServiceRequest and TracesData share the wire format
	// (field 1 = resource_spans); TracesData avoids pulling in gRPC.
	var req tracepb.TracesData
	if err := proto.Unmarshal(b, &req); err != nil {
		return nil, fmt.Errorf("invalid OTLP protobuf: %w", err)
	}
	var out []Span
	for _, rs := range req.ResourceSpans {
		res := kvProto(rs.GetResource().GetAttributes())
		for _, ss := range rs.ScopeSpans {
			schema := ss.SchemaUrl
			if schema == "" {
				schema = rs.SchemaUrl
			}
			for _, sp := range ss.Spans {
				out = append(out, Span{TraceID: hex.EncodeToString(sp.TraceId), SpanID: hex.EncodeToString(sp.SpanId),
					ParentSpanID: hex.EncodeToString(sp.ParentSpanId), Name: sp.Name, StartNano: sp.StartTimeUnixNano,
					EndNano: sp.EndTimeUnixNano, StatusError: sp.GetStatus().GetCode() == tracepb.Status_STATUS_CODE_ERROR,
					StatusMessage: sp.GetStatus().GetMessage(), Attrs: kvProto(sp.Attributes), Resource: res,
					ScopeName: ss.GetScope().GetName(), SchemaURL: schema})
			}
		}
	}
	return out, nil
}

func kvProto(kvs []*commonpb.KeyValue) map[string]any {
	m := map[string]any{}
	for _, kv := range kvs {
		m[kv.Key] = anyProto(kv.Value)
	}
	return m
}

func anyProto(v *commonpb.AnyValue) any {
	switch x := v.GetValue().(type) {
	case *commonpb.AnyValue_StringValue:
		return x.StringValue
	case *commonpb.AnyValue_BoolValue:
		return x.BoolValue
	case *commonpb.AnyValue_IntValue:
		return x.IntValue
	case *commonpb.AnyValue_DoubleValue:
		return x.DoubleValue
	case *commonpb.AnyValue_ArrayValue:
		var a []any
		for _, e := range x.ArrayValue.Values {
			a = append(a, anyProto(e))
		}
		return a
	case *commonpb.AnyValue_KvlistValue:
		return kvProto(x.KvlistValue.Values)
	}
	return nil
}

// OTLP JSON differs from protojson (hex ids, int64 as strings), so it is
// decoded by hand.
type jAny struct {
	StringValue *string                  `json:"stringValue"`
	BoolValue   *bool                    `json:"boolValue"`
	IntValue    json.RawMessage          `json:"intValue"`
	DoubleValue *float64                 `json:"doubleValue"`
	ArrayValue  *struct{ Values []jAny } `json:"arrayValue"`
	KvlistValue *struct{ Values []jKV }  `json:"kvlistValue"`
}
type jKV struct {
	Key   string `json:"key"`
	Value jAny   `json:"value"`
}
type jReq struct {
	ResourceSpans []struct {
		Resource   struct{ Attributes []jKV } `json:"resource"`
		SchemaURL  string                     `json:"schemaUrl"`
		ScopeSpans []struct {
			Scope     struct{ Name string } `json:"scope"`
			SchemaURL string                `json:"schemaUrl"`
			Spans     []struct {
				TraceID, SpanID, ParentSpanID, Name string
				StartTimeUnixNano, EndTimeUnixNano  json.RawMessage
				Attributes                          []jKV
				Status                              struct {
					Code    int
					Message string
				}
			} `json:"spans"`
		} `json:"scopeSpans"`
	} `json:"resourceSpans"`
}

func jNum(r json.RawMessage) (uint64, error) {
	s := strings.Trim(string(r), `"`)
	if s == "" {
		return 0, nil
	}
	return strconv.ParseUint(s, 10, 64)
}

func jVal(v jAny) any {
	switch {
	case v.StringValue != nil:
		return *v.StringValue
	case v.BoolValue != nil:
		return *v.BoolValue
	case len(v.IntValue) > 0:
		n, _ := strconv.ParseInt(strings.Trim(string(v.IntValue), `"`), 10, 64)
		return n
	case v.DoubleValue != nil:
		return *v.DoubleValue
	case v.ArrayValue != nil:
		var a []any
		for _, e := range v.ArrayValue.Values {
			a = append(a, jVal(e))
		}
		return a
	case v.KvlistValue != nil:
		return jKVs(v.KvlistValue.Values)
	}
	return nil
}

func jKVs(kvs []jKV) map[string]any {
	m := map[string]any{}
	for _, kv := range kvs {
		m[kv.Key] = jVal(kv.Value)
	}
	return m
}

// DecodeJSON parses OTLP/HTTP JSON.
func DecodeJSON(b []byte) ([]Span, error) {
	var req jReq
	if err := json.Unmarshal(b, &req); err != nil {
		return nil, fmt.Errorf("invalid OTLP JSON: %w", err)
	}
	var out []Span
	for _, rs := range req.ResourceSpans {
		res := jKVs(rs.Resource.Attributes)
		for _, ss := range rs.ScopeSpans {
			schema := ss.SchemaURL
			if schema == "" {
				schema = rs.SchemaURL
			}
			for _, sp := range ss.Spans {
				start, err1 := jNum(sp.StartTimeUnixNano)
				end, err2 := jNum(sp.EndTimeUnixNano)
				if err1 != nil || err2 != nil {
					return nil, errors.New("invalid span timestamps")
				}
				out = append(out, Span{TraceID: strings.ToLower(sp.TraceID), SpanID: strings.ToLower(sp.SpanID),
					ParentSpanID: strings.ToLower(sp.ParentSpanID), Name: sp.Name, StartNano: start, EndNano: end,
					StatusError: sp.Status.Code == 2, StatusMessage: sp.Status.Message, Attrs: jKVs(sp.Attributes),
					Resource: res, ScopeName: ss.Scope.Name, SchemaURL: schema})
			}
		}
	}
	return out, nil
}

// ---- adapter (pinned semantic-convention versions) ----------------------------------------

// Adapter maps one pinned GenAI semconv version.
type Adapter struct {
	Version  string // e.g. "1.37"
	Provider []string
}

// Pinned: v1.37+ renamed gen_ai.system -> gen_ai.provider.name.
var adapters = []Adapter{
	{Version: "1.37", Provider: []string{"gen_ai.provider.name", "gen_ai.system"}},
	{Version: "1.36", Provider: []string{"gen_ai.system", "gen_ai.provider.name"}},
}

const AdapterID = "otel-genai-adapter/1"

func pick(schemaURL string, attrs map[string]any) Adapter {
	if i := strings.LastIndex(schemaURL, "/"); i >= 0 {
		v := schemaURL[i+1:]
		parts := strings.Split(v, ".")
		if len(parts) >= 2 {
			if minor, err := strconv.Atoi(parts[1]); err == nil && parts[0] == "1" && minor <= 36 {
				return adapters[1]
			}
		}
	}
	if _, legacy := attrs["gen_ai.system"]; legacy {
		if _, newer := attrs["gen_ai.provider.name"]; !newer {
			return adapters[1]
		}
	}
	return adapters[0]
}

func str(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// Operations the adapter records; other spans are ignored.
var operations = map[string]string{"invoke_agent": "agent", "execute_tool": "tool", "chat": "model", "text_completion": "model",
	"generate_content": "model", "create_agent": "agent", "embeddings": "model"}

// Content attributes may carry prompts/PII: never copied into the payload.
var contentAttr = []string{"gen_ai.input.messages", "gen_ai.output.messages", "gen_ai.system_instructions", "gen_ai.prompt", "gen_ai.completion",
	"gen_ai.tool.call.arguments", "gen_ai.tool.call.result"}

func isContent(k string) bool {
	for _, c := range contentAttr {
		if k == c || strings.HasPrefix(k, c+".") {
			return true
		}
	}
	return false
}

// eventID: a deterministic UUIDv7 from the span start and ids, so a
// re-exported span is an idempotent replay, not a duplicate.
func eventID(sp Span) string {
	var b [16]byte
	ms := sp.StartNano / 1_000_000
	b[0], b[1], b[2], b[3], b[4], b[5] = byte(ms>>40), byte(ms>>32), byte(ms>>24), byte(ms>>16), byte(ms>>8), byte(ms) // #nosec G115 -- intentional truncation to the 48-bit UUIDv7 timestamp
	h := sha256.Sum256([]byte("otel|" + sp.TraceID + "|" + sp.SpanID))
	copy(b[6:], h[:10])
	b[6] = b[6]&0x0f | 0x70
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func jsonSafe(v any) any {
	switch x := v.(type) {
	case int64:
		if x > 1<<53 || x < -(1<<53) {
			return strconv.FormatInt(x, 10)
		}
		return x
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) || math.Abs(x) > 1<<53 {
			return fmt.Sprint(x)
		}
		return x
	case string:
		return strings.ReplaceAll(x, "\x00", "")
	case []any:
		for i := range x {
			x[i] = jsonSafe(x[i])
		}
		return x
	case map[string]any:
		for k := range x {
			x[k] = jsonSafe(x[k])
		}
		return x
	}
	return v
}

// Normalize maps one span to an envelope body (nil if not a GenAI span).
// The body goes through exactly the same contract validation as any
// client submission.
func Normalize(sp Span) ([]byte, error) {
	a := sp.Attrs
	op := str(a, "gen_ai.operation.name")
	kind, ok := operations[op]
	if !ok {
		return nil, nil
	}
	ad := pick(sp.SchemaURL, a)
	agentID := str(a, "gen_ai.agent.id", "gen_ai.agent.name")
	if agentID == "" {
		agentID = str(sp.Resource, "service.name")
	}
	if agentID == "" {
		agentID = "unknown"
	}
	agent := map[string]any{"id": agentID}
	if v := str(sp.Resource, "service.version"); v != "" {
		agent["version"] = v
	}
	var principal any
	if u := str(a, "user.id", "enduser.id"); u != "" {
		principal = map[string]any{"id": u, "type": "human"}
	}
	var model any
	if m := str(a, "gen_ai.response.model", "gen_ai.request.model"); m != "" {
		mm := map[string]any{"id": m}
		if p := str(a, ad.Provider...); p != "" {
			mm["provider"] = p
		}
		model = mm
	}
	resource := "otel://" + op
	switch kind {
	case "tool":
		resource = "tool://" + str(a, "gen_ai.tool.name")
	case "agent":
		resource = "agent://" + agentID
	case "model":
		resource = "model://" + str(a, "gen_ai.response.model", "gen_ai.request.model")
	}
	delegation := []any{map[string]any{"type": "otel_trace", "id": sp.TraceID}}
	if c := str(a, "gen_ai.conversation.id"); c != "" {
		delegation = append(delegation, map[string]any{"type": "conversation", "id": c})
	}
	if sp.ParentSpanID != "" && strings.Trim(sp.ParentSpanID, "0") != "" {
		delegation = append(delegation, map[string]any{"type": "parent_span", "id": sp.ParentSpanID})
	}
	delegation = append(delegation, map[string]any{"type": "otel_span", "id": sp.SpanID, "operation": op})
	outcome := "allowed"
	if sp.StatusError {
		outcome = "error"
	}
	attrs := map[string]any{}
	keys := make([]string, 0, len(a))
	for k := range a {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if (strings.HasPrefix(k, "gen_ai.") || k == "error.type") && !isContent(k) {
			attrs[k] = jsonSafe(a[k])
		}
	}
	payload := map[string]any{
		"otel": map[string]any{"trace_id": sp.TraceID, "span_id": sp.SpanID, "parent_span_id": sp.ParentSpanID, "name": sp.Name,
			"duration_ms": float64(sp.EndNano-sp.StartNano) / 1e6, "status_message": sp.StatusMessage,
			"semconv": ad.Version, "adapter": AdapterID},
		"attributes": attrs,
	}
	pv, err := contract.FromGo(payload)
	if err != nil {
		return nil, err
	}
	occurred := time.Unix(0, int64(sp.StartNano)).UTC().Format(contract.TimeLayout) // #nosec G115 -- span time
	body := map[string]any{"spec_version": "2", "event_id": eventID(sp), "occurred_at": occurred, "agent": agent,
		"principal": principal, "model": model, "delegation": delegation, "action": "otel.gen_ai/" + op,
		"resource": resource, "outcome": outcome, "payload": payload, "payload_hash": contract.PayloadHash(pv)}
	return json.Marshal(body)
}
