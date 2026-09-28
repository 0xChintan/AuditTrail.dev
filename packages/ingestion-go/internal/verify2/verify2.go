// Package verify2 verifies a v2 evidence bundle completely offline (v2
// tasks 3.3–3.4): no network, no database, no trust in the log operator
// beyond keys the verifier pins. It compiles to WebAssembly for the browser.
//
// Every failure names the invariant it breaks.
package verify2

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/rfc6962"

	"audittrail.dev/packages/ingestion-go/internal/anchor"
	"audittrail.dev/packages/ingestion-go/internal/contract"
	"audittrail.dev/packages/ingestion-go/internal/keys"
	"audittrail.dev/packages/ingestion-go/internal/merkle"
	"audittrail.dev/packages/ingestion-go/internal/record"
	"audittrail.dev/packages/ingestion-go/internal/tlog"
)

const Format = "audittrail.bundle.v2"

// Invariants (stable names; see THREAT_MODEL.md test IDs A1–A7).
const (
	InvContentHash   = "content-hash"         // A1: row content → hash
	InvPayloadHash   = "payload-hash"         // A1: payload → payload_hash
	InvChainLink     = "chain-link"           // A3: previous_hash links
	InvSeqContinuity = "seq-continuity"       // A2: no gaps
	InvRowSignature  = "row-signature"        // A1/A7: receipt signature
	InvTreeRoot      = "tree-root"            // A1–A4: leaves → signed root
	InvConsistency   = "consistency"          // A4/A5: heads are append-only
	InvCheckpointSig = "checkpoint-signature" // A7: log signature by a trusted key
	InvKeyAuth       = "key-authorization"    // A7: key pinned / not retired
	InvWitnessQuorum = "witness-quorum"       // A6: N-of-M witnesses cosigned
	InvAnchor        = "anchor"               // RFC 3161 time-stamp
	InvFreshness     = "freshness"            // A5: newest head recent enough
	InvFork          = "fork"                 // A6: two different roots at one size
	InvCoverage      = "coverage"             // A4: rows not covered by a signed head
	InvFormat        = "format"
)

type KeyInfo struct {
	KeyID     string  `json:"key_id"`
	Vkey      string  `json:"vkey"`
	PublicKey string  `json:"public_key"`
	CreatedAt string  `json:"created_at"`
	RetiredAt *string `json:"retired_at"`
}

type TreeHead struct {
	TreeSize  uint64  `json:"tree_size"`
	Note      string  `json:"note"`
	TSAToken  *string `json:"tsa_token,omitempty"`
	TSAStatus string  `json:"tsa_status,omitempty"`
}

type Consistency struct {
	From  uint64   `json:"from"`
	To    uint64   `json:"to"`
	Proof []string `json:"proof"` // hex
}

type Bundle struct {
	Format      string         `json:"format"`
	GeneratedAt string         `json:"generated_at"`
	Tenant      map[string]any `json:"tenant"`
	Log         struct {
		Origin string    `json:"origin"`
		Keys   []KeyInfo `json:"keys"`
	} `json:"log"`
	Prefix struct {
		Size   uint64   `json:"size"`
		Hashes []string `json:"hashes"` // compact range [0,size), hex node hashes
	} `json:"prefix"`
	Events      []record.Record `json:"events"`
	TreeHeads   []TreeHead      `json:"tree_heads"`
	Consistency []Consistency   `json:"consistency"`
}

type Options struct {
	LogKeys        []string       // pinned log vkeys; empty = trust the bundle's keys (reported as UNPINNED)
	Witnesses      []string       // trusted witness vkeys (cosignature/v1)
	Quorum         int            // required cosignatures from Witnesses
	MaxAge         time.Duration  // freshness of the newest head's cosignatures (0 = skip)
	Now            time.Time      // verification time (for freshness)
	TSARoots       *x509.CertPool // nil = verify TSA signature but not its chain
	RequireAnchor  bool
	RequireCovered bool      // rows beyond the newest head are errors instead of warnings
	Others         []*Bundle // other views of the same log (fork detection)
}

type Check struct {
	Status string `json:"status"` // pass | fail | warn | skip
	Detail string `json:"detail"`
}

type Failure struct {
	Invariant string `json:"invariant"`
	Seq       int64  `json:"seq,omitempty"`
	TreeSize  uint64 `json:"tree_size,omitempty"`
	Detail    string `json:"detail"`
}

type Report struct {
	OK           bool             `json:"ok"`
	Origin       string           `json:"origin"`
	Trust        string           `json:"trust"` // pinned | UNPINNED
	FirstSeq     int64            `json:"first_seq"`
	LastSeq      int64            `json:"last_seq"`
	Events       int              `json:"events"`
	Heads        int              `json:"tree_heads"`
	LatestHead   uint64           `json:"latest_head_size"`
	Witnessed    []string         `json:"witnessed_by"`
	AnchoredAt   string           `json:"anchored_at,omitempty"`
	Checks       map[string]Check `json:"checks"`
	Failures     []Failure        `json:"failures"`
	Warnings     []Failure        `json:"warnings"`
	TamperedSeqs []int64          `json:"tampered_seqs"`
}

type rep struct {
	*Report
	tampered map[int64]bool
	failed   map[string]bool
}

func (r *rep) fail(inv string, seq int64, size uint64, format string, a ...any) {
	r.Failures = append(r.Failures, Failure{inv, seq, size, fmt.Sprintf(format, a...)})
	r.failed[inv] = true
	r.OK = false
	if seq > 0 {
		r.tampered[seq] = true
	}
}

func (r *rep) warn(inv string, seq int64, size uint64, format string, a ...any) {
	r.Warnings = append(r.Warnings, Failure{inv, seq, size, fmt.Sprintf(format, a...)})
}

func (r *rep) pass(inv, detail string) {
	if _, ok := r.Checks[inv]; !ok && !r.failed[inv] {
		r.Checks[inv] = Check{"pass", detail}
	}
}

type parsedHead struct {
	TreeHead
	note *tlog.Note
	cp   tlog.Checkpoint
	ok   bool // log signature valid
}

// Verify runs every check and names the invariant behind each failure.
func Verify(b *Bundle, o Options) *Report {
	r := &rep{Report: &Report{OK: true, Checks: map[string]Check{}, Failures: []Failure{}, Warnings: []Failure{}, TamperedSeqs: []int64{}},
		tampered: map[int64]bool{}, failed: map[string]bool{}}
	defer r.finish()
	if b.Format != Format {
		r.fail(InvFormat, 0, 0, "unsupported bundle format %q", b.Format)
		return r.Report
	}
	r.Origin = b.Log.Origin

	// ---- keys: pinned by the verifier, or taken from the bundle ----------------------
	type logKey struct {
		name string
		pub  []byte
		info *KeyInfo
	}
	var trusted []logKey
	rowKeys := map[string]KeyInfo{}
	for i := range b.Log.Keys {
		rowKeys[b.Log.Keys[i].KeyID] = b.Log.Keys[i]
	}
	if len(o.LogKeys) > 0 {
		r.Trust = "pinned"
		for _, v := range o.LogKeys {
			n, typ, pub, err := tlog.ParseVkey(v)
			if err != nil || typ != tlog.TypeEd25519 {
				r.fail(InvKeyAuth, 0, 0, "pinned log key is malformed")
				continue
			}
			trusted = append(trusted, logKey{n, pub, nil})
		}
		// Row signing keys must be among the pinned keys too.
		for id, k := range rowKeys {
			pinned := false
			for _, t := range trusted {
				if base64.StdEncoding.EncodeToString(t.pub) == k.PublicKey {
					pinned = true
				}
			}
			if !pinned {
				delete(rowKeys, id)
			}
		}
	} else {
		r.Trust = "UNPINNED"
		r.warn(InvKeyAuth, 0, 0, "log keys taken from the bundle itself; pin them (--log-key) for independent verification")
		for i := range b.Log.Keys {
			k := &b.Log.Keys[i]
			if n, typ, pub, err := tlog.ParseVkey(k.Vkey); err == nil && typ == tlog.TypeEd25519 {
				trusted = append(trusted, logKey{n, pub, k})
			}
		}
	}
	var witnesses []tlog.Witness
	for _, v := range o.Witnesses {
		if w, err := tlog.WitnessFromVkey(v); err == nil {
			witnesses = append(witnesses, w)
		} else {
			r.fail(InvWitnessQuorum, 0, 0, "trusted witness key is malformed")
		}
	}

	// ---- tree heads: signatures, cosignatures, anchors --------------------------------
	heads := make([]*parsedHead, 0, len(b.TreeHeads))
	for _, th := range b.TreeHeads {
		ph := &parsedHead{TreeHead: th}
		n, err := tlog.ParseNote([]byte(th.Note))
		if err != nil {
			r.fail(InvCheckpointSig, 0, th.TreeSize, "tree head %d: malformed note: %v", th.TreeSize, err)
			continue
		}
		cp, err := tlog.ParseCheckpoint(n.Text)
		if err != nil || cp.Size != th.TreeSize || cp.Origin != b.Log.Origin {
			r.fail(InvCheckpointSig, 0, th.TreeSize, "tree head %d: checkpoint text does not match (origin/size)", th.TreeSize)
			continue
		}
		ph.note, ph.cp = n, cp
		for _, k := range trusted {
			if k.name != cp.Origin {
				continue
			}
			if err := tlog.VerifyLog(n, k.name, k.pub); err == nil {
				ph.ok = true
				if k.info != nil && k.info.RetiredAt != nil {
					r.warn(InvKeyAuth, 0, th.TreeSize, "tree head %d signed by retired key %s", th.TreeSize, k.info.KeyID)
				}
			} else if strings.Contains(err.Error(), "does not verify") {
				r.fail(InvCheckpointSig, 0, th.TreeSize, "tree head %d: log signature does not verify", th.TreeSize)
			}
		}
		if !ph.ok && !r.failed[InvCheckpointSig] {
			r.fail(InvCheckpointSig, 0, th.TreeSize, "tree head %d: no valid signature from a trusted log key (forged or unauthorized key)", th.TreeSize)
		}
		heads = append(heads, ph)
	}
	sort.Slice(heads, func(i, j int) bool { return heads[i].TreeSize < heads[j].TreeSize })
	r.Heads = len(heads)

	// fork: two heads with the same size but different roots (within this
	// bundle or across other views of the same log).
	all := append([]*parsedHead{}, heads...)
	for _, ob := range o.Others {
		for _, th := range ob.TreeHeads {
			if n, err := tlog.ParseNote([]byte(th.Note)); err == nil {
				if cp, err := tlog.ParseCheckpoint(n.Text); err == nil && cp.Origin == b.Log.Origin {
					ok := false
					for _, k := range trusted {
						if tlog.VerifyLog(n, k.name, k.pub) == nil {
							ok = true
						}
					}
					all = append(all, &parsedHead{TreeHead: th, note: n, cp: cp, ok: ok})
				}
			}
		}
	}
	bySize := map[uint64]*parsedHead{}
	for _, h := range all {
		if !h.ok {
			continue
		}
		if prev, dup := bySize[h.TreeSize]; dup && string(prev.cp.Root) != string(h.cp.Root) {
			r.fail(InvFork, 0, h.TreeSize, "SPLIT VIEW: two log-signed checkpoints at size %d with different roots (%x… vs %x…)",
				h.TreeSize, prev.cp.Root[:6], h.cp.Root[:6])
		}
		bySize[h.TreeSize] = h
	}

	// witness quorum + anchors, per head
	var newest *parsedHead
	for _, h := range heads {
		if h.note == nil {
			continue
		}
		newest = h
		if len(witnesses) > 0 || o.Quorum > 0 {
			var names []string
			var latest time.Time
			for _, w := range witnesses {
				at, ok, err := tlog.VerifyCosig(h.note, w)
				if err != nil {
					r.fail(InvWitnessQuorum, 0, h.TreeSize, "tree head %d: %v", h.TreeSize, err)
				}
				if ok {
					names = append(names, w.Name)
					if at.After(latest) {
						latest = at
					}
				}
			}
			h.Status(names)
			if len(names) < o.Quorum {
				r.fail(InvWitnessQuorum, 0, h.TreeSize, "tree head %d has %d of the required %d trusted witness cosignatures", h.TreeSize, len(names), o.Quorum)
			}
			if h == heads[len(heads)-1] {
				r.Witnessed = names
				if o.MaxAge > 0 {
					now := o.Now
					if now.IsZero() {
						now = time.Now()
					}
					if latest.IsZero() || now.Sub(latest) > o.MaxAge {
						r.fail(InvFreshness, 0, h.TreeSize, "newest tree head (%d) was last witnessed %s; older than the allowed %s (stale or replayed checkpoint)",
							h.TreeSize, fmtTime(latest), o.MaxAge)
					}
				}
			}
		}
		if h.TSAToken != nil && *h.TSAToken != "" {
			res, err := anchor.Verify(*h.TSAToken, []byte(h.note.Text), o.TSARoots)
			if err != nil {
				r.fail(InvAnchor, 0, h.TreeSize, "tree head %d: RFC 3161 token invalid: %v", h.TreeSize, err)
			} else if h == heads[len(heads)-1] {
				r.AnchoredAt = res.Time.UTC().Format(time.RFC3339) + " by " + res.Authority
			}
		} else if o.RequireAnchor {
			r.fail(InvAnchor, 0, h.TreeSize, "tree head %d has no RFC 3161 anchor", h.TreeSize)
		}
	}
	if newest != nil {
		r.LatestHead = newest.TreeSize
	}

	// consistency between successive heads (proofs supplied by the bundle)
	proofs := map[[2]uint64][]string{}
	for _, c := range b.Consistency {
		proofs[[2]uint64{c.From, c.To}] = c.Proof
	}
	for i := 1; i < len(heads); i++ {
		a, c := heads[i-1], heads[i]
		if a.note == nil || c.note == nil {
			continue
		}
		p, ok := proofs[[2]uint64{a.TreeSize, c.TreeSize}]
		if !ok {
			r.fail(InvConsistency, 0, c.TreeSize, "no consistency proof from head %d to head %d", a.TreeSize, c.TreeSize)
			continue
		}
		raw, err := decodeHex(p)
		if err != nil || !merkle.VerifyConsistency(a.TreeSize, c.TreeSize, a.cp.Root, c.cp.Root, raw) {
			r.fail(InvConsistency, 0, c.TreeSize, "head %d is NOT an append-only extension of head %d (history rewritten or truncated)", c.TreeSize, a.TreeSize)
		}
	}

	// ---- rows ------------------------------------------------------------------------
	evs := append([]record.Record(nil), b.Events...)
	sort.SliceStable(evs, func(i, j int) bool { return evs[i].Seq < evs[j].Seq })
	r.Events = len(evs)
	if len(evs) > 0 {
		r.FirstSeq, r.LastSeq = evs[0].Seq, evs[len(evs)-1].Seq
		if uint64(evs[0].Seq-1) != b.Prefix.Size { // #nosec G115 -- seq >= 1
			r.fail(InvSeqContinuity, evs[0].Seq, 0, "bundle prefix covers %d leaves but the first row is seq %d", b.Prefix.Size, evs[0].Seq)
		}
	}
	tenantID := fmt.Sprint(b.Tenant["id"])
	for i := range evs {
		e := evs[i]
		if e.TenantID != tenantID {
			r.fail(InvContentHash, e.Seq, 0, "row %d belongs to another tenant", e.Seq)
		}
		if h, err := e.RecomputeHash(); err != nil || h != e.Hash {
			r.fail(InvContentHash, e.Seq, 0, "row %d: content does not hash to its stored hash", e.Seq)
		}
		if !e.PayloadIntact() {
			r.fail(InvPayloadHash, e.Seq, 0, "row %d: payload does not match its payload_hash", e.Seq)
		}
		if i > 0 {
			p := evs[i-1]
			if e.Seq != p.Seq+1 {
				r.fail(InvSeqContinuity, p.Seq+1, 0, "rows %d..%d are missing", p.Seq+1, e.Seq-1)
				for s := p.Seq + 1; s < e.Seq; s++ {
					r.tampered[s] = true
				}
			} else if e.PreviousHash != p.Hash {
				r.fail(InvChainLink, e.Seq, 0, "row %d does not link to row %d (reordered or rewritten)", e.Seq, p.Seq)
			}
		} else if e.Seq == 1 && e.PreviousHash != contract.Genesis {
			r.fail(InvChainLink, 1, 0, "row 1 does not link to genesis")
		}
		k, ok := rowKeys[e.KeyID]
		if !ok {
			r.fail(InvKeyAuth, e.Seq, 0, "row %d signed by key %s that is not trusted", e.Seq, e.KeyID)
		} else if !keys.Verify(k.PublicKey, e.SigningMessage(), e.Signature) {
			r.fail(InvRowSignature, e.Seq, 0, "row %d: receipt signature does not verify", e.Seq)
		}
	}

	// ---- recompute the signed roots from the rows (compact range) ----------------------
	if len(evs) > 0 && !r.failed[InvSeqContinuity] {
		rf := &compact.RangeFactory{Hash: rfc6962.DefaultHasher.HashChildren}
		pre, err := decodeHex(b.Prefix.Hashes)
		var cr *compact.Range
		if err == nil {
			cr, err = rf.NewRange(0, b.Prefix.Size, pre)
		}
		if err != nil {
			r.fail(InvTreeRoot, 0, 0, "bundle prefix is malformed: %v", err)
		} else {
			headAt := map[uint64]*parsedHead{}
			for _, h := range heads {
				if h.note != nil {
					headAt[h.TreeSize] = h
				}
			}
			covered := uint64(0)
			for _, e := range evs {
				leaf, err := hex.DecodeString(e.Hash)
				if err != nil || len(leaf) != 32 {
					r.fail(InvTreeRoot, e.Seq, 0, "row %d: malformed hash", e.Seq)
					break
				}
				if err := cr.Append(rfc6962.DefaultHasher.HashLeaf(leaf), nil); err != nil {
					r.fail(InvTreeRoot, e.Seq, 0, "compact range: %v", err)
					break
				}
				if h, ok := headAt[cr.End()]; ok {
					root, _ := cr.GetRootHash(nil)
					if string(root) != string(h.cp.Root) {
						r.fail(InvTreeRoot, 0, h.TreeSize, "rows 1..%d do not reproduce the signed root of tree head %d (rows altered, removed or reordered)", h.TreeSize, h.TreeSize)
						localize(r, evs, h.TreeSize)
					} else {
						covered = h.TreeSize
					}
				}
			}
			// Heads larger than the rows supplied: truncated tail.
			for _, h := range heads {
				if h.note != nil && h.TreeSize > uint64(r.LastSeq) { // #nosec G115
					r.fail(InvCoverage, r.LastSeq+1, h.TreeSize, "bundle ends at seq %d but tree head %d commits to %d rows: the tail was truncated", r.LastSeq, h.TreeSize, h.TreeSize)
				}
			}
			if uint64(r.LastSeq) > covered { // #nosec G115
				if o.RequireCovered {
					r.fail(InvCoverage, int64(covered)+1, 0, "rows %d..%d are not covered by any signed tree head", covered+1, r.LastSeq) // #nosec G115
				} else {
					r.warn(InvCoverage, int64(covered)+1, 0, "rows %d..%d are not yet covered by a signed tree head", covered+1, r.LastSeq) // #nosec G115
				}
			}
		}
	}
	if len(heads) == 0 && len(evs) > 0 {
		r.warn(InvCoverage, 0, 0, "bundle contains no tree heads: rows are hash-chained and signed but not checkpointed")
	}
	for _, inv := range []string{InvContentHash, InvPayloadHash, InvChainLink, InvSeqContinuity, InvRowSignature, InvTreeRoot,
		InvConsistency, InvCheckpointSig, InvKeyAuth, InvFork, InvCoverage} {
		r.pass(inv, "")
	}
	if len(witnesses) > 0 || o.Quorum > 0 {
		r.pass(InvWitnessQuorum, fmt.Sprintf("%d-of-%d", o.Quorum, len(witnesses)))
	} else {
		r.Checks[InvWitnessQuorum] = Check{"skip", "no trusted witnesses configured"}
	}
	if o.MaxAge > 0 {
		r.pass(InvFreshness, o.MaxAge.String())
	} else {
		r.Checks[InvFreshness] = Check{"skip", "no max age configured"}
	}
	r.pass(InvAnchor, "")
	return r.Report
}

// Status is a no-op hook kept for readability of the quorum loop.
func (h *parsedHead) Status([]string) {}

// localize: when a root mismatches but every row is self-consistent, the
// whole prefix was rewritten (e.g. with a stolen key): flag it.
func localize(r *rep, evs []record.Record, size uint64) {
	for s := range r.tampered {
		if uint64(s) <= size { // #nosec G115
			return
		}
	}
	for _, e := range evs {
		if uint64(e.Seq) <= size { // #nosec G115
			r.tampered[e.Seq] = true
		}
	}
}

func (r *rep) finish() {
	for s := range r.tampered {
		r.TamperedSeqs = append(r.TamperedSeqs, s)
	}
	sort.Slice(r.TamperedSeqs, func(i, j int) bool { return r.TamperedSeqs[i] < r.TamperedSeqs[j] })
	for inv := range r.failed {
		var details []string
		for _, f := range r.Failures {
			if f.Invariant == inv {
				details = append(details, f.Detail)
			}
		}
		r.Checks[inv] = Check{"fail", strings.Join(details, "; ")}
	}
}

func decodeHex(hs []string) ([][]byte, error) {
	out := make([][]byte, len(hs))
	for i, h := range hs {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != 32 {
			return nil, fmt.Errorf("hash %d malformed", i)
		}
		out[i] = b
	}
	return out, nil
}

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.UTC().Format(time.RFC3339)
}

// NoteDigest is SHA-256 of a head's checkpoint text (the RFC 3161 imprint).
func NoteDigest(text string) string {
	s := sha256.Sum256([]byte(text))
	return hex.EncodeToString(s[:])
}
