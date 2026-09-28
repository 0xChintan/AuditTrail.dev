// Package tlog implements C2SP signed notes, tlog-checkpoints and
// Ed25519 cosignature/v1 (see schemas/v2/SPEC.md §6).
package tlog

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	TypeEd25519     = 0x01
	TypeCosignature = 0x04
	Dash            = "— "
)

func KeyID(name string, typ byte, pub []byte) uint32 {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte{'\n', typ})
	h.Write(pub)
	return binary.BigEndian.Uint32(h.Sum(nil)[:4])
}

func validName(n string) bool {
	if n == "" {
		return false
	}
	for _, r := range n {
		if unicode.IsSpace(r) || r == '+' {
			return false
		}
	}
	return true
}

// Vkey encodes a verifier key: name+hex(keyID)+base64(type||pub).
func Vkey(name string, typ byte, pub []byte) string {
	return fmt.Sprintf("%s+%08x+%s", name, KeyID(name, typ, pub), base64.StdEncoding.EncodeToString(append([]byte{typ}, pub...)))
}

// ParseVkey decodes a vkey.
func ParseVkey(v string) (name string, typ byte, pub ed25519.PublicKey, err error) {
	parts := strings.SplitN(v, "+", 3)
	if len(parts) != 3 || !validName(parts[0]) {
		return "", 0, nil, errors.New("malformed vkey")
	}
	raw, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil || len(raw) != 1+ed25519.PublicKeySize {
		return "", 0, nil, errors.New("malformed vkey key material")
	}
	typ, pub = raw[0], ed25519.PublicKey(raw[1:])
	if want := fmt.Sprintf("%08x", KeyID(parts[0], typ, pub)); want != parts[1] {
		return "", 0, nil, errors.New("vkey key ID mismatch")
	}
	return parts[0], typ, pub, nil
}

// Note is a parsed signed note.
type Note struct {
	Text string // includes final newline
	Sigs []Sig
}

type Sig struct {
	Name  string
	KeyID uint32
	Raw   []byte // signature bytes after the key ID
	Line  string
}

// ParseNote splits a signed note at its last blank line.
func ParseNote(b []byte) (*Note, error) {
	s := string(b)
	for _, r := range s {
		if r < 0x20 && r != '\n' {
			return nil, errors.New("note contains control characters")
		}
	}
	i := strings.LastIndex(s, "\n\n")
	if i < 0 {
		return nil, errors.New("note has no signature block")
	}
	n := &Note{Text: s[:i+1]}
	sigBlock := s[i+2:]
	if !strings.HasSuffix(sigBlock, "\n") {
		return nil, errors.New("signature block must end in newline")
	}
	for _, line := range strings.Split(strings.TrimSuffix(sigBlock, "\n"), "\n") {
		sig, err := ParseSigLine(line)
		if err != nil {
			return nil, err
		}
		n.Sigs = append(n.Sigs, sig)
	}
	if len(n.Sigs) == 0 {
		return nil, errors.New("note has no signatures")
	}
	if len(n.Sigs) > 64 {
		return nil, errors.New("too many signatures")
	}
	return n, nil
}

func ParseSigLine(line string) (Sig, error) {
	rest, ok := strings.CutPrefix(line, Dash)
	if !ok {
		return Sig{}, errors.New("signature line must start with em dash")
	}
	name, b64, ok := strings.Cut(rest, " ")
	if !ok || !validName(name) || strings.Contains(b64, " ") {
		return Sig{}, errors.New("malformed signature line")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) < 5 {
		return Sig{}, errors.New("malformed signature encoding")
	}
	return Sig{Name: name, KeyID: binary.BigEndian.Uint32(raw[:4]), Raw: raw[4:], Line: line + "\n"}, nil
}

func (n *Note) Bytes() []byte {
	var b bytes.Buffer
	b.WriteString(n.Text)
	b.WriteString("\n")
	for _, s := range n.Sigs {
		b.WriteString(s.Line)
	}
	return b.Bytes()
}

// ---- log signatures (type 0x01) -------------------------------------------------

type Signer struct {
	Name string
	Priv ed25519.PrivateKey
}

func (s Signer) Pub() ed25519.PublicKey { return s.Priv.Public().(ed25519.PublicKey) }
func (s Signer) Vkey() string           { return Vkey(s.Name, TypeEd25519, s.Pub()) }

// SignLine signs note text and returns a signature line.
func (s Signer) SignLine(text string) string {
	raw := make([]byte, 4, 4+ed25519.SignatureSize)
	binary.BigEndian.PutUint32(raw, KeyID(s.Name, TypeEd25519, s.Pub()))
	raw = append(raw, ed25519.Sign(s.Priv, []byte(text))...)
	return Dash + s.Name + " " + base64.StdEncoding.EncodeToString(raw) + "\n"
}

// VerifyLog checks that the note carries a valid signature from the log key.
// Per the spec, signatures matching name+ID but failing verification reject
// the note.
func VerifyLog(n *Note, name string, pub ed25519.PublicKey) error {
	id := KeyID(name, TypeEd25519, pub)
	found := false
	for _, s := range n.Sigs {
		if s.Name != name || s.KeyID != id {
			continue
		}
		if !ed25519.Verify(pub, []byte(n.Text), s.Raw) {
			return errors.New("log signature does not verify")
		}
		found = true
	}
	if !found {
		return errors.New("no signature from the log key")
	}
	return nil
}

// ---- cosignatures (cosignature/v1, type 0x04) ------------------------------------

func cosignMessage(t uint64, text string) []byte {
	return []byte("cosignature/v1\ntime " + strconv.FormatUint(t, 10) + "\n" + text)
}

type Cosigner struct {
	Name string
	Priv ed25519.PrivateKey
}

func (c Cosigner) Pub() ed25519.PublicKey { return c.Priv.Public().(ed25519.PublicKey) }
func (c Cosigner) Vkey() string           { return Vkey(c.Name, TypeCosignature, c.Pub()) }

func (c Cosigner) CosignLine(text string, at time.Time) string {
	unix := at.Unix()
	if unix < 0 {
		panic("cosignature time before 1970")
	}
	t := uint64(unix)
	raw := make([]byte, 12, 12+ed25519.SignatureSize)
	binary.BigEndian.PutUint32(raw, KeyID(c.Name, TypeCosignature, c.Pub()))
	binary.BigEndian.PutUint64(raw[4:], t)
	raw = append(raw, ed25519.Sign(c.Priv, cosignMessage(t, text))...)
	return Dash + c.Name + " " + base64.StdEncoding.EncodeToString(raw) + "\n"
}

// Witness is a verifier-side witness identity.
type Witness struct {
	Name string
	Pub  ed25519.PublicKey
}

func WitnessFromVkey(v string) (Witness, error) {
	name, typ, pub, err := ParseVkey(v)
	if err != nil {
		return Witness{}, err
	}
	if typ != TypeCosignature {
		return Witness{}, fmt.Errorf("vkey %s is not a cosignature/v1 key", name)
	}
	return Witness{name, pub}, nil
}

// VerifyCosig returns the cosignature time if witness w validly cosigned n.
// ok=false with nil error means no signature from w is present.
func VerifyCosig(n *Note, w Witness) (at time.Time, ok bool, err error) {
	id := KeyID(w.Name, TypeCosignature, w.Pub)
	for _, s := range n.Sigs {
		if s.Name != w.Name || s.KeyID != id {
			continue
		}
		if len(s.Raw) != 8+ed25519.SignatureSize {
			return time.Time{}, false, errors.New("malformed cosignature")
		}
		t := binary.BigEndian.Uint64(s.Raw[:8])
		if t > math.MaxInt64 {
			return time.Time{}, false, errors.New("cosignature timestamp exceeds 2^63-1")
		}
		if !ed25519.Verify(w.Pub, cosignMessage(t, n.Text), s.Raw[8:]) {
			return time.Time{}, false, fmt.Errorf("cosignature from %s does not verify", w.Name)
		}
		return time.Unix(int64(t), 0).UTC(), true, nil // #nosec G115 -- bounded by the MaxInt64 check above
	}
	return time.Time{}, false, nil
}

// ---- checkpoints ---------------------------------------------------------------

type Checkpoint struct {
	Origin string
	Size   uint64
	Root   []byte
}

func (c Checkpoint) Text() string {
	return c.Origin + "\n" + strconv.FormatUint(c.Size, 10) + "\n" + base64.StdEncoding.EncodeToString(c.Root) + "\n"
}

func (c Checkpoint) RootHex() string { return hex.EncodeToString(c.Root) }

// ParseCheckpoint parses a checkpoint note text (extension lines rejected).
func ParseCheckpoint(text string) (Checkpoint, error) {
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) != 3 || !strings.HasSuffix(text, "\n") {
		return Checkpoint{}, errors.New("checkpoint must have exactly origin, size and root lines")
	}
	if lines[0] == "" {
		return Checkpoint{}, errors.New("empty origin")
	}
	size, err := strconv.ParseUint(lines[1], 10, 64)
	if err != nil || (lines[1] != "0" && strings.HasPrefix(lines[1], "0")) {
		return Checkpoint{}, errors.New("bad tree size")
	}
	root, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil || len(root) != 32 {
		return Checkpoint{}, errors.New("bad root hash")
	}
	return Checkpoint{lines[0], size, root}, nil
}

// SignCheckpoint returns a signed note for the checkpoint.
func SignCheckpoint(c Checkpoint, s Signer) []byte {
	t := c.Text()
	return []byte(t + "\n" + s.SignLine(t))
}

func Origin(tenantID string) string { return "audittrail.dev/log/" + tenantID }
