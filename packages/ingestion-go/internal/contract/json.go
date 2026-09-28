// Package contract implements the v2 message contract (schemas/v2/SPEC.md):
// a strict JSON parser, RFC 8785 canonicalization, envelope validation, the
// length-prefixed record hash and request signatures.
package contract

import (
	"bytes"
	"fmt"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/gowebpki/jcs"
)

const (
	MaxBodyBytes = 262144
	MaxDepth     = 16
)

// Error is a contract violation with a stable code and HTTP status.
type Error struct {
	Status int
	Code   string
	Msg    string
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func perr(code, format string, a ...any) *Error {
	return &Error{Status: 400, Code: code, Msg: fmt.Sprintf(format, a...)}
}

func serr(code, format string, a ...any) *Error {
	return &Error{Status: 422, Code: code, Msg: fmt.Sprintf(format, a...)}
}

type Kind int

const (
	Null Kind = iota
	Bool
	Number
	String
	Array
	Object
)

type Member struct {
	Key   string
	Value *Value
}

// Value is a parsed JSON value that keeps object member order and the raw
// number text.
type Value struct {
	Kind Kind
	B    bool
	N    float64
	Raw  string // number literal as written
	S    string
	A    []*Value
	O    []Member
}

func (v *Value) Get(key string) (*Value, bool) {
	if v == nil || v.Kind != Object {
		return nil, false
	}
	for _, m := range v.O {
		if m.Key == key {
			return m.Value, true
		}
	}
	return nil, false
}

// Parse runs the strict checks of SPEC §2 (size, UTF-8, syntax, surrogates,
// duplicate keys, depth, unsafe integers, non-finite numbers).
func Parse(data []byte) (*Value, *Error) {
	if len(data) > MaxBodyBytes {
		return nil, &Error{Status: 413, Code: "body_too_large", Msg: fmt.Sprintf("body exceeds %d bytes", MaxBodyBytes)}
	}
	if !utf8.Valid(data) {
		return nil, perr("invalid_utf8", "body is not valid UTF-8")
	}
	p := &parser{d: data}
	p.ws()
	v, err := p.value(1)
	if err != nil {
		return nil, err
	}
	p.ws()
	if p.i != len(p.d) {
		return nil, perr("invalid_json", "trailing data at offset %d", p.i)
	}
	return v, nil
}

type parser struct {
	d []byte
	i int
}

func (p *parser) ws() {
	for p.i < len(p.d) {
		switch p.d[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *parser) syntax(what string) *Error {
	if p.i >= len(p.d) {
		return perr("invalid_json", "unexpected end of input (%s)", what)
	}
	return perr("invalid_json", "unexpected %q at offset %d (%s)", p.d[p.i], p.i, what)
}

func (p *parser) value(depth int) (*Value, *Error) {
	if p.i >= len(p.d) {
		return nil, p.syntax("value")
	}
	switch c := p.d[p.i]; {
	case c == '{':
		if depth > MaxDepth {
			return nil, perr("depth_exceeded", "nesting deeper than %d", MaxDepth)
		}
		return p.object(depth)
	case c == '[':
		if depth > MaxDepth {
			return nil, perr("depth_exceeded", "nesting deeper than %d", MaxDepth)
		}
		return p.array(depth)
	case c == '"':
		s, err := p.str()
		if err != nil {
			return nil, err
		}
		return &Value{Kind: String, S: s}, nil
	case c == 't':
		return p.lit("true", &Value{Kind: Bool, B: true})
	case c == 'f':
		return p.lit("false", &Value{Kind: Bool})
	case c == 'n':
		return p.lit("null", &Value{Kind: Null})
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	default:
		return nil, p.syntax("value")
	}
}

func (p *parser) lit(word string, v *Value) (*Value, *Error) {
	if !bytes.HasPrefix(p.d[p.i:], []byte(word)) {
		return nil, p.syntax("literal")
	}
	p.i += len(word)
	return v, nil
}

func (p *parser) object(depth int) (*Value, *Error) {
	p.i++ // {
	v := &Value{Kind: Object}
	seen := map[string]bool{}
	p.ws()
	if p.i < len(p.d) && p.d[p.i] == '}' {
		p.i++
		return v, nil
	}
	for {
		p.ws()
		if p.i >= len(p.d) || p.d[p.i] != '"' {
			return nil, p.syntax("object key")
		}
		k, err := p.str()
		if err != nil {
			return nil, err
		}
		if seen[k] {
			return nil, perr("duplicate_key", "duplicate object key %q", trunc(k))
		}
		seen[k] = true
		p.ws()
		if p.i >= len(p.d) || p.d[p.i] != ':' {
			return nil, p.syntax("':'")
		}
		p.i++
		p.ws()
		val, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		v.O = append(v.O, Member{k, val})
		p.ws()
		if p.i < len(p.d) && p.d[p.i] == ',' {
			p.i++
			continue
		}
		if p.i < len(p.d) && p.d[p.i] == '}' {
			p.i++
			return v, nil
		}
		return nil, p.syntax("',' or '}'")
	}
}

func (p *parser) array(depth int) (*Value, *Error) {
	p.i++ // [
	v := &Value{Kind: Array, A: []*Value{}}
	p.ws()
	if p.i < len(p.d) && p.d[p.i] == ']' {
		p.i++
		return v, nil
	}
	for {
		p.ws()
		el, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		v.A = append(v.A, el)
		p.ws()
		if p.i < len(p.d) && p.d[p.i] == ',' {
			p.i++
			continue
		}
		if p.i < len(p.d) && p.d[p.i] == ']' {
			p.i++
			return v, nil
		}
		return nil, p.syntax("',' or ']'")
	}
}

func hexv(b byte) int {
	switch {
	case b >= '0' && b <= '9':
		return int(b - '0')
	case b >= 'a' && b <= 'f':
		return int(b-'a') + 10
	case b >= 'A' && b <= 'F':
		return int(b-'A') + 10
	}
	return -1
}

func (p *parser) hex4() (rune, bool) {
	if p.i+4 > len(p.d) {
		return 0, false
	}
	r := 0
	for k := 0; k < 4; k++ {
		h := hexv(p.d[p.i+k])
		if h < 0 {
			return 0, false
		}
		r = r<<4 | h
	}
	p.i += 4
	return rune(r), true
}

func (p *parser) str() (string, *Error) {
	p.i++ // opening quote
	var sb strings.Builder
	for {
		if p.i >= len(p.d) {
			return "", perr("invalid_json", "unterminated string")
		}
		c := p.d[p.i]
		switch {
		case c == '"':
			p.i++
			return sb.String(), nil
		case c < 0x20:
			return "", perr("invalid_json", "unescaped control character in string at offset %d", p.i)
		case c == '\\':
			p.i++
			if p.i >= len(p.d) {
				return "", perr("invalid_json", "unterminated escape")
			}
			e := p.d[p.i]
			p.i++
			switch e {
			case '"', '\\', '/':
				sb.WriteByte(e)
			case 'b':
				sb.WriteByte('\b')
			case 'f':
				sb.WriteByte('\f')
			case 'n':
				sb.WriteByte('\n')
			case 'r':
				sb.WriteByte('\r')
			case 't':
				sb.WriteByte('\t')
			case 'u':
				r, ok := p.hex4()
				if !ok {
					return "", perr("invalid_json", "bad \\u escape")
				}
				if r >= 0xD800 && r <= 0xDBFF {
					if p.i+2 <= len(p.d) && p.d[p.i] == '\\' && p.d[p.i+1] == 'u' {
						p.i += 2
						lo, ok := p.hex4()
						if !ok {
							return "", perr("invalid_json", "bad \\u escape")
						}
						if lo < 0xDC00 || lo > 0xDFFF {
							return "", perr("invalid_surrogate", "high surrogate not followed by a low surrogate")
						}
						sb.WriteRune(utf16.DecodeRune(r, lo))
					} else {
						return "", perr("invalid_surrogate", "unpaired high surrogate")
					}
				} else if r >= 0xDC00 && r <= 0xDFFF {
					return "", perr("invalid_surrogate", "unpaired low surrogate")
				} else {
					sb.WriteRune(r)
				}
			default:
				return "", perr("invalid_json", "invalid escape \\%c", e)
			}
		default:
			_, size := utf8.DecodeRune(p.d[p.i:])
			sb.Write(p.d[p.i : p.i+size])
			p.i += size
		}
	}
}

var maxSafe = new(big.Int).Lsh(big.NewInt(1), 53)

func (p *parser) number() (*Value, *Error) {
	start := p.i
	if p.d[p.i] == '-' {
		p.i++
	}
	if p.i >= len(p.d) {
		return nil, p.syntax("number")
	}
	switch {
	case p.d[p.i] == '0':
		p.i++
	case p.d[p.i] >= '1' && p.d[p.i] <= '9':
		for p.i < len(p.d) && p.d[p.i] >= '0' && p.d[p.i] <= '9' {
			p.i++
		}
	default:
		return nil, p.syntax("number")
	}
	integer := true
	if p.i < len(p.d) && p.d[p.i] == '.' {
		integer = false
		p.i++
		n := p.i
		for p.i < len(p.d) && p.d[p.i] >= '0' && p.d[p.i] <= '9' {
			p.i++
		}
		if p.i == n {
			return nil, p.syntax("fraction digits")
		}
	}
	if p.i < len(p.d) && (p.d[p.i] == 'e' || p.d[p.i] == 'E') {
		integer = false
		p.i++
		if p.i < len(p.d) && (p.d[p.i] == '+' || p.d[p.i] == '-') {
			p.i++
		}
		n := p.i
		for p.i < len(p.d) && p.d[p.i] >= '0' && p.d[p.i] <= '9' {
			p.i++
		}
		if p.i == n {
			return nil, p.syntax("exponent digits")
		}
	}
	raw := string(p.d[start:p.i])
	if integer {
		bi, _ := new(big.Int).SetString(raw, 10)
		if new(big.Int).Abs(bi).Cmp(maxSafe) > 0 {
			return nil, perr("unsafe_integer", "integer %s exceeds 2^53; send it as a string", trunc(raw))
		}
	}
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
		return nil, perr("non_finite_number", "number %s is not a finite double", trunc(raw))
	}
	// Every double above 2^53 is an integer whose canonical (JCS) form is a
	// long digit string; reject them all, whatever the literal syntax, so
	// canonical output always re-parses (found by FuzzParse).
	if math.Abs(f) > 9007199254740992 {
		return nil, perr("unsafe_integer", "number %s exceeds 2^53 in magnitude; send it as a string", trunc(raw))
	}
	return &Value{Kind: Number, N: f, Raw: raw}, nil
}

func trunc(s string) string {
	if len(s) > 40 {
		return s[:40] + "…"
	}
	return s
}

// ---- RFC 8785 serialization ----------------------------------------------------

func lessUTF16(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

func writeString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

func (v *Value) writeJCS(b *bytes.Buffer) {
	switch v.Kind {
	case Null:
		b.WriteString("null")
	case Bool:
		if v.B {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case Number:
		s, err := jcs.NumberToJSON(v.N)
		if err != nil {
			panic(err) // unreachable: non-finite numbers are rejected at parse time
		}
		b.WriteString(s)
	case String:
		writeString(b, v.S)
	case Array:
		b.WriteByte('[')
		for i, e := range v.A {
			if i > 0 {
				b.WriteByte(',')
			}
			e.writeJCS(b)
		}
		b.WriteByte(']')
	case Object:
		ms := append([]Member(nil), v.O...)
		sort.SliceStable(ms, func(i, j int) bool { return lessUTF16(ms[i].Key, ms[j].Key) })
		b.WriteByte('{')
		for i, m := range ms {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, m.Key)
			b.WriteByte(':')
			m.Value.writeJCS(b)
		}
		b.WriteByte('}')
	}
}

// JCS returns the RFC 8785 canonical form. A nil value is "null".
func JCS(v *Value) []byte {
	if v == nil {
		return []byte("null")
	}
	var b bytes.Buffer
	v.writeJCS(&b)
	return b.Bytes()
}

// Canonicalize parses (strictly) and canonicalizes JSON text.
func Canonicalize(data []byte) ([]byte, *Error) {
	v, err := Parse(data)
	if err != nil {
		return nil, err
	}
	return JCS(v), nil
}

// ---- builders (for server-generated values) ------------------------------------

func Str(s string) *Value { return &Value{Kind: String, S: s} }
func Obj(ms ...Member) *Value {
	return &Value{Kind: Object, O: ms}
}
func M(k string, v *Value) Member { return Member{k, v} }
