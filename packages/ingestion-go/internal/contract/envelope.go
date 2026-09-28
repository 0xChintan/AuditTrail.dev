package contract

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const SpecVersion = "2"

var (
	uuidV7Re  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	actionRe  = regexp.MustCompile(`^[A-Za-z0-9._:/-]+$`)
	hexHashRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
	tsRe      = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})$`)
)

const TimeLayout = "2006-01-02T15:04:05.000Z"

// Envelope is a validated, normalized v2 submission (SPEC §1).
type Envelope struct {
	EventID     string
	OccurredAt  string // normalized UTC ms
	Agent       *Value
	Principal   *Value // nil = null
	Model       *Value // nil = null
	Delegation  *Value // array, never nil
	Action      string
	Resource    string
	Outcome     string
	Payload     *Value // nil = null
	PayloadHash string
	PII         *PII
	Digest      string // hex SHA-256(JCS(envelope as submitted))
}

type PII struct {
	Subject string
	Fields  []Member // name -> string value, in submitted order
}

var allowed = map[string]bool{
	"spec_version": true, "event_id": true, "occurred_at": true, "agent": true, "principal": true,
	"model": true, "delegation": true, "action": true, "resource": true, "outcome": true,
	"payload": true, "payload_hash": true, "pii": true,
}

// NormalizeTime converts RFC 3339 to UTC millisecond precision, truncating.
func NormalizeTime(s string) (string, bool) {
	m := tsRe.FindStringSubmatch(s)
	if m == nil {
		return "", false
	}
	frac := strings.TrimPrefix(m[2], ".")
	if len(frac) > 3 {
		frac = frac[:3]
	}
	for len(frac) < 3 {
		frac += "0"
	}
	t, err := time.Parse(time.RFC3339, m[1]+"."+frac+strings.ToUpper(m[3]))
	if err != nil {
		t, err = time.Parse("2006-01-02T15:04:05.000Z07:00", m[1]+"."+frac+strings.ToUpper(m[3]))
		if err != nil {
			return "", false
		}
	}
	return t.UTC().Format(TimeLayout), true
}

func strLen(s string) int { return utf8.RuneCountInString(s) }

func wantString(v *Value, path string, min, max int) (string, *Error) {
	if v == nil || v.Kind != String {
		return "", serr("wrong_type", "%s must be a string", path)
	}
	if n := strLen(v.S); n < min || n > max {
		return "", serr("invalid_value", "%s length must be %d..%d", path, min, max)
	}
	return v.S, nil
}

func isNull(v *Value) bool { return v == nil || v.Kind == Null }

type lim struct {
	key      string
	min, max int
}

// checkObject validates an object's members against required and optional
// string fields (checked in the listed order, so errors are deterministic).
func checkObject(v *Value, path string, required, optional []lim, nullableOpt bool) *Error {
	if v.Kind != Object {
		return serr("wrong_type", "%s must be an object", path)
	}
	known := func(k string) bool {
		for _, l := range append(append([]lim{}, required...), optional...) {
			if l.key == k {
				return true
			}
		}
		return false
	}
	for _, m := range v.O {
		if !known(m.Key) {
			return serr("unknown_field", "%s.%s is not allowed", path, m.Key)
		}
	}
	for _, l := range required {
		f, ok := v.Get(l.key)
		if !ok {
			return serr("missing_field", "%s.%s is required", path, l.key)
		}
		if _, err := wantString(f, path+"."+l.key, l.min, l.max); err != nil {
			return err
		}
	}
	for _, l := range optional {
		f, ok := v.Get(l.key)
		if !ok || (nullableOpt && f.Kind == Null) {
			continue
		}
		if _, err := wantString(f, path+"."+l.key, l.min, l.max); err != nil {
			return err
		}
	}
	return nil
}

// ValidateEnvelope parses and validates a raw submission body.
func ValidateEnvelope(body []byte) (*Envelope, *Error) {
	root, perr := Parse(body)
	if perr != nil {
		return nil, perr
	}
	return ValidateValue(root)
}

// ValidateValue validates an already-parsed envelope.
func ValidateValue(root *Value) (*Envelope, *Error) {
	if root.Kind != Object {
		return nil, serr("wrong_type", "envelope must be a JSON object")
	}
	if hasNUL(root) {
		return nil, serr("invalid_value", "strings and keys may not contain U+0000")
	}
	for _, m := range root.O {
		if !allowed[m.Key] {
			return nil, serr("unknown_field", "%s is not allowed", m.Key)
		}
	}
	get := func(k string) *Value { v, _ := root.Get(k); return v }

	sv := get("spec_version")
	if sv == nil {
		return nil, serr("missing_field", "spec_version is required")
	}
	if sv.Kind != String {
		return nil, serr("wrong_type", "spec_version must be a string")
	}
	if sv.S != SpecVersion {
		return nil, serr("unsupported_spec_version", "spec_version %q is not supported (want \"2\")", trunc(sv.S))
	}
	for _, k := range []string{"event_id", "occurred_at", "agent", "action", "resource", "outcome", "payload_hash"} {
		if get(k) == nil {
			return nil, serr("missing_field", "%s is required", k)
		}
	}
	e := &Envelope{}
	var err *Error
	if e.EventID, err = wantString(get("event_id"), "event_id", 36, 36); err != nil {
		return nil, err
	}
	if !uuidV7Re.MatchString(e.EventID) {
		return nil, serr("invalid_value", "event_id must be a lowercase UUIDv7")
	}
	ts, err := wantString(get("occurred_at"), "occurred_at", 1, 64)
	if err != nil {
		return nil, err
	}
	var ok bool
	if e.OccurredAt, ok = NormalizeTime(ts); !ok {
		return nil, serr("invalid_value", "occurred_at must be RFC 3339")
	}

	e.Agent = get("agent")
	if err := checkObject(e.Agent, "agent", []lim{{"id", 1, 256}}, []lim{{"version", 0, 128}}, false); err != nil {
		return nil, err
	}
	if p := get("principal"); !isNull(p) {
		if err := checkObject(p, "principal", []lim{{"id", 1, 512}, {"type", 1, 16}}, nil, false); err != nil {
			return nil, err
		}
		if t, _ := p.Get("type"); t.S != "human" && t.S != "service" {
			return nil, serr("invalid_value", "principal.type must be human or service")
		}
		e.Principal = p
	}
	if m := get("model"); !isNull(m) {
		if err := checkObject(m, "model", []lim{{"id", 1, 256}}, []lim{{"version", 0, 128}, {"provider", 0, 128}}, true); err != nil {
			return nil, err
		}
		e.Model = m
	}
	e.Delegation = &Value{Kind: Array, A: []*Value{}}
	if d := get("delegation"); !isNull(d) {
		if d.Kind != Array {
			return nil, serr("wrong_type", "delegation must be an array")
		}
		if len(d.A) > 32 {
			return nil, serr("invalid_value", "delegation may have at most 32 frames")
		}
		for i, f := range d.A {
			path := "delegation[" + strconv.Itoa(i) + "]"
			if f.Kind != Object {
				return nil, serr("wrong_type", "%s must be an object", path)
			}
			for _, k := range []struct {
				name string
				max  int
			}{{"type", 64}, {"id", 512}} {
				fv, ok := f.Get(k.name)
				if !ok {
					return nil, serr("missing_field", "%s.%s is required", path, k.name)
				}
				if _, err := wantString(fv, path+"."+k.name, 1, k.max); err != nil {
					return nil, err
				}
			}
			for _, m := range f.O {
				if m.Value.Kind == Object || m.Value.Kind == Array {
					return nil, serr("wrong_type", "%s.%s must be a scalar", path, m.Key)
				}
			}
		}
		e.Delegation = d
	}
	if e.Action, err = wantString(get("action"), "action", 1, 256); err != nil {
		return nil, err
	}
	if !actionRe.MatchString(e.Action) {
		return nil, serr("invalid_value", "action may only contain [A-Za-z0-9._:/-]")
	}
	if e.Resource, err = wantString(get("resource"), "resource", 1, 2048); err != nil {
		return nil, err
	}
	if e.Outcome, err = wantString(get("outcome"), "outcome", 1, 16); err != nil {
		return nil, err
	}
	if e.Outcome != "allowed" && e.Outcome != "denied" && e.Outcome != "error" {
		return nil, serr("invalid_value", "outcome must be allowed, denied or error")
	}
	if p := get("payload"); !isNull(p) {
		if p.Kind != Object {
			return nil, serr("wrong_type", "payload must be an object or null")
		}
		e.Payload = p
	}
	if e.PayloadHash, err = wantString(get("payload_hash"), "payload_hash", 64, 64); err != nil {
		return nil, err
	}
	if !hexHashRe.MatchString(e.PayloadHash) {
		return nil, serr("invalid_value", "payload_hash must be 64 lowercase hex characters")
	}
	if got := PayloadHash(e.Payload); got != e.PayloadHash {
		return nil, serr("payload_hash_mismatch", "payload_hash does not match SHA-256(JCS(payload))")
	}
	if p := get("pii"); !isNull(p) {
		if p.Kind != Object {
			return nil, serr("wrong_type", "pii must be an object or null")
		}
		for _, m := range p.O {
			if m.Key != "subject" && m.Key != "fields" {
				return nil, serr("unknown_field", "pii.%s is not allowed", m.Key)
			}
		}
		sub, ok := p.Get("subject")
		if !ok {
			return nil, serr("missing_field", "pii.subject is required")
		}
		s, err := wantString(sub, "pii.subject", 1, 256)
		if err != nil {
			return nil, err
		}
		fields, ok := p.Get("fields")
		if !ok {
			return nil, serr("missing_field", "pii.fields is required")
		}
		if fields.Kind != Object {
			return nil, serr("wrong_type", "pii.fields must be an object")
		}
		if len(fields.O) == 0 || len(fields.O) > 64 {
			return nil, serr("invalid_value", "pii.fields must have 1..64 members")
		}
		for _, m := range fields.O {
			if _, err := wantString(m.Value, "pii.fields."+m.Key, 0, 65536); err != nil {
				return nil, err
			}
		}
		e.PII = &PII{Subject: s, Fields: fields.O}
	}
	sum := sha256.Sum256(JCS(root))
	e.Digest = hex.EncodeToString(sum[:])
	return e, nil
}

// PayloadHash = hex(SHA-256(JCS(payload))) with nil => "null".
func PayloadHash(p *Value) string {
	sum := sha256.Sum256(JCS(p))
	return hex.EncodeToString(sum[:])
}

// ---- record hash (SPEC §3) -----------------------------------------------------

const RecordDomain = "AuditTrail/v2/record\x00"

var Genesis = strings.Repeat("0", 64)

// Field is one length-prefixed hash input; Null marks JSON null / absent.
type Field struct {
	B    []byte
	Null bool
}

func F(s string) Field  { return Field{B: []byte(s)} }
func FB(b []byte) Field { return Field{B: b} }
func FJ(v *Value) Field {
	if isNull(v) {
		return Field{Null: true}
	}
	return Field{B: JCS(v)}
}

func appendLP(buf []byte, f Field) []byte {
	if f.Null {
		return append(buf, 0xff, 0xff, 0xff, 0xff)
	}
	if len(f.B) >= math.MaxUint32 { // 0xFFFFFFFF is reserved for null
		panic("hash field too large")
	}
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(f.B))) // #nosec G115 -- bounded above
	buf = append(buf, l[:]...)
	return append(buf, f.B...)
}

// Record is everything that enters the v2 record hash.
type Record struct {
	TenantID    string
	Seq         int64
	EventID     string
	OccurredAt  string
	ReceivedAt  string
	Agent       *Value
	Principal   *Value
	Model       *Value
	Delegation  *Value
	Action      string
	Resource    string
	Outcome     string
	PayloadHash string
	PIICT       *Value
	PrevHash    string
}

// HashInput returns the exact bytes that are hashed (useful for vectors).
func (r Record) HashInput() []byte {
	b := []byte(RecordDomain)
	for _, f := range []Field{
		F(SpecVersion), F(r.TenantID), F(strconv.FormatInt(r.Seq, 10)), F(r.EventID),
		F(r.OccurredAt), F(r.ReceivedAt), FJ(r.Agent), FJ(r.Principal), FJ(r.Model),
		FB(JCS(r.Delegation)), F(r.Action), F(r.Resource), F(r.Outcome), F(r.PayloadHash),
		FJ(r.PIICT), F(r.PrevHash),
	} {
		b = appendLP(b, f)
	}
	return b
}

func (r Record) Hash() string {
	sum := sha256.Sum256(r.HashInput())
	return hex.EncodeToString(sum[:])
}

const ReceiptPrefix = "AuditTrail/v2/receipt\n"

func ReceiptMessage(hash string) []byte { return []byte(ReceiptPrefix + hash) }

// hasNUL reports U+0000 anywhere (Postgres jsonb cannot store it, and it has
// no business in audit data).
func hasNUL(v *Value) bool {
	switch v.Kind {
	case String:
		return strings.ContainsRune(v.S, 0)
	case Array:
		for _, e := range v.A {
			if hasNUL(e) {
				return true
			}
		}
	case Object:
		for _, m := range v.O {
			if strings.ContainsRune(m.Key, 0) || hasNUL(m.Value) {
				return true
			}
		}
	}
	return false
}
