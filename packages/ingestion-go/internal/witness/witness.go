// Package witness implements a C2SP tlog-witness (add-checkpoint) server and
// client with Ed25519 cosignature/v1 (v2 task 3.2, threat T3 split views).
//
// A witness remembers, per log origin, the latest checkpoint it cosigned. It
// only cosigns a new checkpoint that is provably consistent (RFC 9162
// consistency proof) with that one, so a log can't obtain cosignatures for
// two diverging histories from the same witness.
package witness

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"audittrail.dev/packages/ingestion-go/internal/merkle"
	"audittrail.dev/packages/ingestion-go/internal/tlog"
)

// LogKey is a trusted log verification key.
type LogKey struct {
	Name string
	Pub  ed25519.PublicKey
}

// Resolver returns the trusted keys for an origin (nil if unknown).
type Resolver func(ctx context.Context, origin string) ([]LogKey, error)

type state struct {
	Size uint64 `json:"size"`
	Root string `json:"root"` // base64
	Note string `json:"note"`
}

type Server struct {
	Cosigner tlog.Cosigner
	Resolve  Resolver
	Path     string // state file ("" = memory only)
	Now      func() time.Time

	mu     sync.Mutex
	states map[string]state
	// Rejected keeps the last refused checkpoints: possible evidence of log
	// misbehavior (spec: witnesses MAY log them).
	Rejected []string
}

func NewServer(c tlog.Cosigner, resolve Resolver, path string) (*Server, error) {
	s := &Server{Cosigner: c, Resolve: resolve, Path: path, Now: time.Now, states: map[string]state{}}
	if path != "" {
		if b, err := os.ReadFile(path); err == nil {
			if err := json.Unmarshal(b, &s.states); err != nil {
				return nil, fmt.Errorf("witness state %s: %w", path, err)
			}
		}
	}
	return s, nil
}

func (s *Server) persist() error {
	if s.Path == "" {
		return nil
	}
	b, _ := json.Marshal(s.states)
	tmp := s.Path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.Path)
}

// Size returns the latest cosigned size for an origin.
func (s *Server) Size(origin string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.states[origin].Size
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/add-checkpoint"):
		s.addCheckpoint(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/vkey":
		fmt.Fprintln(w, s.Cosigner.Vkey())
	default:
		http.NotFound(w, r)
	}
}

func text(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(code)
	fmt.Fprintln(w, msg)
}

func (s *Server) addCheckpoint(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		text(w, 400, "unreadable body")
		return
	}
	old, proof, noteBytes, err := ParseAddCheckpoint(body)
	if err != nil {
		text(w, 400, err.Error())
		return
	}
	n, err := tlog.ParseNote(noteBytes)
	if err != nil {
		text(w, 400, "malformed note: "+err.Error())
		return
	}
	cp, err := tlog.ParseCheckpoint(n.Text)
	if err != nil {
		text(w, 400, "malformed checkpoint: "+err.Error())
		return
	}
	logKeys, err := s.Resolve(r.Context(), cp.Origin)
	if err != nil || len(logKeys) == 0 {
		text(w, 404, "unknown log origin")
		return
	}
	verified := false
	for _, k := range logKeys {
		switch err := tlog.VerifyLog(n, k.Name, k.Pub); {
		case err == nil:
			verified = true
		case strings.Contains(err.Error(), "does not verify"):
			text(w, 403, "log signature does not verify")
			return
		}
	}
	if !verified {
		text(w, 403, "no signature from a trusted log key")
		return
	}
	if old > cp.Size {
		text(w, 400, "old size exceeds checkpoint size")
		return
	}
	if cp.Size == 0 {
		text(w, 422, "empty tree")
		return
	}

	// Check-and-update must be atomic (spec: avoid rolling back K leaves).
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.states[cp.Origin]
	if old != st.Size {
		w.Header().Set("Content-Type", "text/x.tlog.size")
		w.WriteHeader(409)
		fmt.Fprintf(w, "%d\n", st.Size)
		return
	}
	reject := func(msg string) {
		s.Rejected = append(s.Rejected, string(noteBytes))
		text(w, 422, msg)
	}
	switch {
	case old == 0:
		if len(proof) != 0 {
			reject("consistency proof must be empty for old size 0")
			return
		}
	case old == cp.Size:
		stRoot, _ := base64.StdEncoding.DecodeString(st.Root)
		if !bytes.Equal(stRoot, cp.Root) || len(proof) != 0 {
			reject("same size, different root: refusing to cosign a fork")
			return
		}
	default:
		stRoot, _ := base64.StdEncoding.DecodeString(st.Root)
		if !merkle.VerifyConsistency(old, cp.Size, stRoot, cp.Root, proof) {
			reject("consistency proof does not verify: refusing to cosign a fork")
			return
		}
	}
	s.states[cp.Origin] = state{Size: cp.Size, Root: base64.StdEncoding.EncodeToString(cp.Root), Note: n.Text}
	if err := s.persist(); err != nil {
		text(w, 500, "could not persist state")
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	io.WriteString(w, s.Cosigner.CosignLine(n.Text, s.Now()))
}

// ParseAddCheckpoint splits an add-checkpoint request body.
func ParseAddCheckpoint(body []byte) (old uint64, proof [][]byte, note []byte, err error) {
	sc := bufio.NewReader(bytes.NewReader(body))
	line, err := sc.ReadString('\n')
	if err != nil {
		return 0, nil, nil, errors.New("missing old size line")
	}
	sz, ok := strings.CutPrefix(strings.TrimSuffix(line, "\n"), "old ")
	if !ok {
		return 0, nil, nil, errors.New("first line must be `old <size>`")
	}
	old, err = strconv.ParseUint(sz, 10, 64)
	if err != nil || (sz != "0" && strings.HasPrefix(sz, "0")) {
		return 0, nil, nil, errors.New("bad old size")
	}
	for {
		line, err := sc.ReadString('\n')
		if err != nil {
			return 0, nil, nil, errors.New("missing blank line before checkpoint")
		}
		line = strings.TrimSuffix(line, "\n")
		if line == "" {
			break
		}
		if len(proof) >= 63 {
			return 0, nil, nil, errors.New("too many proof lines")
		}
		h, err := base64.StdEncoding.DecodeString(line)
		if err != nil || len(h) != 32 {
			return 0, nil, nil, errors.New("bad proof hash")
		}
		proof = append(proof, h)
	}
	rest, _ := io.ReadAll(sc)
	return old, proof, rest, nil
}

// ---- client -------------------------------------------------------------------------

// ErrConflict carries the witness's latest cosigned size.
type ErrConflict struct{ Size uint64 }

func (e *ErrConflict) Error() string { return fmt.Sprintf("witness is at size %d", e.Size) }

// AddCheckpoint submits a checkpoint and returns the cosignature line(s).
func AddCheckpoint(ctx context.Context, hc *http.Client, baseURL string, old uint64, proof [][]byte, signedNote []byte) (string, error) {
	var b bytes.Buffer
	fmt.Fprintf(&b, "old %d\n", old)
	for _, p := range proof {
		b.WriteString(base64.StdEncoding.EncodeToString(p) + "\n")
	}
	b.WriteString("\n")
	b.Write(signedNote)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(baseURL, "/")+"/add-checkpoint", &b)
	if err != nil {
		return "", err
	}
	if hc == nil {
		hc = &http.Client{Timeout: 15 * time.Second}
	}
	res, err := hc.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	out, _ := io.ReadAll(io.LimitReader(res.Body, 16<<10))
	switch res.StatusCode {
	case 200:
		return string(out), nil
	case 409:
		sz, err := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 64)
		if err != nil {
			return "", fmt.Errorf("witness 409 with bad body")
		}
		return "", &ErrConflict{Size: sz}
	default:
		return "", fmt.Errorf("witness HTTP %d: %s", res.StatusCode, strings.TrimSpace(string(out)))
	}
}
