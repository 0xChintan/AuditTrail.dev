package verify2_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/rfc6962"

	"audittrail.dev/packages/ingestion-go/internal/contract"
	"audittrail.dev/packages/ingestion-go/internal/keys"
	"audittrail.dev/packages/ingestion-go/internal/merkle"
	"audittrail.dev/packages/ingestion-go/internal/record"
	"audittrail.dev/packages/ingestion-go/internal/tlog"
	"audittrail.dev/packages/ingestion-go/internal/verify2"
	"audittrail.dev/packages/ingestion-go/internal/witness"
)

const tenant = "11111111-2222-4333-8444-555555555555"

// ---- a self-contained log: records, tree heads, witnesses ---------------------------

type logSim struct {
	t         *testing.T
	priv      ed25519.PrivateKey
	keyID     string
	events    []record.Record
	witnesses []*httptest.Server
	wservers  []*witness.Server
	wvkeys    []string
	now       time.Time
}

func newLog(t *testing.T, nWitness int) *logSim {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	l := &logSim{t: t, priv: priv, keyID: keys.KeyID(priv.Public().(ed25519.PublicKey)), now: time.Now()}
	origin := tlog.Origin(tenant)
	for i := 0; i < nWitness; i++ {
		_, wp, _ := ed25519.GenerateKey(rand.Reader)
		c := tlog.Cosigner{Name: fmt.Sprintf("witness.test/w%d", i+1), Priv: wp}
		pub := priv.Public().(ed25519.PublicKey)
		ws, _ := witness.NewServer(c, func(ctx context.Context, o string) ([]witness.LogKey, error) {
			if o == origin {
				return []witness.LogKey{{Name: origin, Pub: pub}}, nil
			}
			return nil, nil
		}, "")
		ws.Now = func() time.Time { return l.now }
		l.wservers = append(l.wservers, ws)
		l.witnesses = append(l.witnesses, httptest.NewServer(ws))
		l.wvkeys = append(l.wvkeys, c.Vkey())
	}
	t.Cleanup(func() {
		for _, s := range l.witnesses {
			s.Close()
		}
	})
	return l
}

func (l *logSim) logVkey() string {
	return tlog.Vkey(tlog.Origin(tenant), tlog.TypeEd25519, l.priv.Public().(ed25519.PublicKey))
}

func (l *logSim) append(n int) {
	for i := 0; i < n; i++ {
		seq := int64(len(l.events) + 1)
		prev := contract.Genesis
		if seq > 1 {
			prev = l.events[seq-2].Hash
		}
		payload := contract.MustFromGo(map[string]any{"amount": seq * 100, "note": "payment"})
		agent := contract.MustFromGo(map[string]string{"id": "payments-agent"})
		principal := contract.MustFromGo(map[string]string{"id": "alice", "type": "human"})
		ts := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC).Add(time.Duration(seq) * time.Second).Format(contract.TimeLayout)
		cr := contract.Record{TenantID: tenant, Seq: seq, EventID: keys.NewUUIDv7(time.Now()), OccurredAt: ts, ReceivedAt: ts,
			Agent: agent, Principal: principal, Delegation: &contract.Value{Kind: contract.Array, A: []*contract.Value{}},
			Action: "payment.transfer", Resource: fmt.Sprintf("account/%d", seq), Outcome: []string{"allowed", "denied"}[seq%2],
			PayloadHash: contract.PayloadHash(payload), PrevHash: prev}
		l.events = append(l.events, l.toRecord(cr, payload))
	}
}

func (l *logSim) toRecord(cr contract.Record, payload *contract.Value) record.Record {
	h := cr.Hash()
	recv, ph := cr.ReceivedAt, cr.PayloadHash
	pid := "alice"
	return record.Record{ID: cr.EventID, TenantID: tenant, Seq: cr.Seq, Timestamp: cr.OccurredAt, HumanPrincipalID: &pid,
		AgentID: "payments-agent", DelegationChain: json.RawMessage(contract.JCS(cr.Delegation)), Action: cr.Action,
		TargetResource: cr.Resource, Outcome: cr.Outcome, Metadata: json.RawMessage(contract.JCS(payload)),
		PreviousHash: cr.PrevHash, Hash: h, Signature: keys.Sign(l.priv, contract.ReceiptMessage(h)), KeyID: l.keyID,
		SpecVersion: 2, ReceivedAt: &recv, Agent: json.RawMessage(contract.JCS(cr.Agent)),
		Principal: json.RawMessage(contract.JCS(cr.Principal)), PayloadHash: &ph}
}

func leavesOf(evs []record.Record) [][]byte {
	out := make([][]byte, len(evs))
	for i, e := range evs {
		out[i], _ = hex.DecodeString(e.Hash)
	}
	return out
}

// head signs a checkpoint over evs and gets it cosigned by the witnesses.
func (l *logSim) head(evs []record.Record, signer ed25519.PrivateKey) verify2.TreeHead {
	leaves := leavesOf(evs)
	cp := tlog.Checkpoint{Origin: tlog.Origin(tenant), Size: uint64(len(evs)), Root: merkle.RootRaw(leaves)}
	note := string(tlog.SignCheckpoint(cp, tlog.Signer{Name: cp.Origin, Priv: signer}))
	for i, ws := range l.witnesses {
		old := l.wservers[i].Size(cp.Origin)
		var proof [][]byte
		if old > 0 && old < cp.Size {
			proof, _ = merkle.ConsistencyProof(leaves, int(old))
		}
		if line, err := witness.AddCheckpoint(context.Background(), nil, ws.URL, old, proof, []byte(note)); err == nil {
			note += line
		}
	}
	return verify2.TreeHead{TreeSize: cp.Size, Note: note}
}

func bundle(evs []record.Record, heads []verify2.TreeHead, from int, keysOf ...ed25519.PrivateKey) *verify2.Bundle {
	return bundleWith(evs, evs, heads, from, keysOf...)
}

// bundleWith builds the prefix and consistency proofs from `truth` (what an
// attacker would copy from the genuine log) and ships the (possibly
// tampered) rows `evs`.
func bundleWith(truth, evs []record.Record, heads []verify2.TreeHead, from int, keysOf ...ed25519.PrivateKey) *verify2.Bundle {
	b := &verify2.Bundle{Format: verify2.Format, Tenant: map[string]any{"id": tenant}}
	b.Log.Origin = tlog.Origin(tenant)
	for _, k := range keysOf {
		pub := k.Public().(ed25519.PublicKey)
		b.Log.Keys = append(b.Log.Keys, verify2.KeyInfo{KeyID: keys.KeyID(pub), PublicKey: base64.StdEncoding.EncodeToString(pub),
			Vkey: tlog.Vkey(b.Log.Origin, tlog.TypeEd25519, pub)})
	}
	all := leavesOf(truth)
	rf := &compact.RangeFactory{Hash: rfc6962.DefaultHasher.HashChildren}
	cr := rf.NewEmptyRange(0)
	for i := 0; i < from-1; i++ {
		cr.Append(rfc6962.DefaultHasher.HashLeaf(all[i]), nil)
	}
	b.Prefix.Size = uint64(from - 1)
	b.Prefix.Hashes = []string{}
	for _, h := range cr.Hashes() {
		b.Prefix.Hashes = append(b.Prefix.Hashes, hex.EncodeToString(h))
	}
	b.Events = append([]record.Record(nil), evs[from-1:]...)
	b.TreeHeads = heads
	for i := 1; i < len(heads); i++ {
		p, _ := merkle.ConsistencyProof(all[:heads[i].TreeSize], int(heads[i-1].TreeSize))
		c := verify2.Consistency{From: heads[i-1].TreeSize, To: heads[i].TreeSize, Proof: []string{}}
		for _, h := range p {
			c.Proof = append(c.Proof, hex.EncodeToString(h))
		}
		b.Consistency = append(b.Consistency, c)
	}
	return b
}

func (l *logSim) opts() verify2.Options {
	return verify2.Options{LogKeys: []string{l.logVkey()}, Witnesses: l.wvkeys, Quorum: 2, MaxAge: time.Hour, Now: l.now}
}

func failed(r *verify2.Report) []string {
	var out []string
	for _, f := range r.Failures {
		if !slices.Contains(out, f.Invariant) {
			out = append(out, f.Invariant)
		}
	}
	slices.Sort(out)
	return out
}

func mustFail(t *testing.T, r *verify2.Report, inv string) {
	t.Helper()
	if r.OK || !slices.Contains(failed(r), inv) {
		t.Fatalf("expected invariant %q to fail; got ok=%v failures=%v", inv, r.OK, failed(r))
	}
}

// ---- baseline --------------------------------------------------------------------------

func fixture(t *testing.T) (*logSim, []verify2.TreeHead) {
	l := newLog(t, 3)
	l.append(10)
	h1 := l.head(l.events, l.priv)
	l.append(10)
	h2 := l.head(l.events, l.priv)
	return l, []verify2.TreeHead{h1, h2}
}

func TestBaselineVerifies(t *testing.T) {
	l, heads := fixture(t)
	r := verify2.Verify(bundle(l.events, heads, 1, l.priv), l.opts())
	if !r.OK || len(r.Witnessed) != 3 {
		t.Fatalf("clean log failed: %+v", r.Failures)
	}
	// ...and a sub-range bundle (rows 8..20 with a compact-range prefix) too.
	if r := verify2.Verify(bundle(l.events, heads[1:], 8, l.priv), l.opts()); !r.OK {
		t.Fatalf("sub-range bundle failed: %+v", r.Failures)
	}
}

// A1: editing any field of a row is caught and localized.
func TestA1EditRow(t *testing.T) {
	l, heads := fixture(t)
	evs := slices.Clone(l.events)
	evs[6].Outcome = "allowed"
	evs[6].Outcome = map[string]string{"allowed": "denied", "denied": "allowed"}[l.events[6].Outcome]
	r := verify2.Verify(bundle(evs, heads, 1, l.priv), l.opts())
	mustFail(t, r, verify2.InvContentHash)
	if !slices.Contains(r.TamperedSeqs, 7) {
		t.Fatalf("not localized to seq 7: %v", r.TamperedSeqs)
	}
	// payload-only edit (payload is committed via payload_hash)
	evs = slices.Clone(l.events)
	evs[3].Metadata = json.RawMessage(`{"amount":1,"note":"payment"}`)
	mustFail(t, verify2.Verify(bundle(evs, heads, 1, l.priv), l.opts()), verify2.InvPayloadHash)
}

// A1 (stolen key): a consistent rewrite with re-signed rows is caught by the
// witnessed tree root.
func TestA1RewriteWithStolenKey(t *testing.T) {
	l, heads := fixture(t)
	evs := slices.Clone(l.events)
	for i := 4; i < len(evs); i++ {
		cr, _ := evs[i].V2Record()
		if i == 4 {
			cr.Outcome = "allowed"
		}
		if i > 4 {
			cr.PrevHash = evs[i-1].Hash
		}
		p, _ := contract.Parse(evs[i].Metadata)
		evs[i] = l.toRecord(cr, p)
	}
	mustFail(t, verify2.Verify(bundle(evs, heads, 1, l.priv), l.opts()), verify2.InvTreeRoot)
}

// A2: deleting a row names the missing seq.
func TestA2DeleteRow(t *testing.T) {
	l, heads := fixture(t)
	evs := slices.Delete(slices.Clone(l.events), 11, 12) // seq 12
	r := verify2.Verify(bundleWith(l.events, evs, heads, 1, l.priv), l.opts())
	mustFail(t, r, verify2.InvSeqContinuity)
	if !slices.Contains(r.TamperedSeqs, 12) {
		t.Fatalf("missing seq not named: %v", r.TamperedSeqs)
	}
}

// A3: reordering rows breaks the chain.
func TestA3Reorder(t *testing.T) {
	l, heads := fixture(t)
	evs := slices.Clone(l.events)
	evs[4], evs[5] = evs[5], evs[4]
	evs[4].Seq, evs[5].Seq = 5, 6
	mustFail(t, verify2.Verify(bundle(evs, heads, 1, l.priv), l.opts()), verify2.InvChainLink)
}

// A4: truncating the tail while keeping the newest head is caught; dropping
// the newest head too is caught by freshness once time moves on.
func TestA4Truncate(t *testing.T) {
	l, heads := fixture(t)
	r := verify2.Verify(bundleWith(l.events, l.events[:15], heads, 1, l.priv), l.opts())
	mustFail(t, r, verify2.InvCoverage)
	o := l.opts()
	o.Now = l.now.Add(3 * time.Hour)
	mustFail(t, verify2.Verify(bundle(l.events[:10], heads[:1], 1, l.priv), o), verify2.InvFreshness)
}

// A5: replaying an old checkpoint as current: stale cosignatures fail
// freshness; an old head presented after a newer one fails consistency.
func TestA5ReplayOldCheckpoint(t *testing.T) {
	l := newLog(t, 3)
	l.append(10)
	old := l.head(l.events, l.priv)
	l.now = l.now.Add(2 * time.Hour)
	l.append(5)
	mustFail(t, verify2.Verify(bundle(l.events[:10], []verify2.TreeHead{old}, 1, l.priv), l.opts()), verify2.InvFreshness)

	// A head whose history is not an extension of the previous one.
	l2, heads := fixture(t)
	forged := slices.Clone(l2.events)
	cr, _ := forged[2].V2Record()
	cr.Action = "payment.refund"
	p, _ := contract.Parse(forged[2].Metadata)
	forged[2] = l2.toRecord(cr, p)
	leaves := leavesOf(forged)
	cp := tlog.Checkpoint{Origin: tlog.Origin(tenant), Size: 20, Root: merkle.RootRaw(leaves)}
	bad := verify2.TreeHead{TreeSize: 20, Note: string(tlog.SignCheckpoint(cp, tlog.Signer{Name: cp.Origin, Priv: l2.priv}))}
	b := bundleWith(forged, l2.events, []verify2.TreeHead{heads[0], bad}, 1, l2.priv)
	mustFail(t, verify2.Verify(b, l2.opts()), verify2.InvConsistency)
}

// A6: split view. The log shows history A to everyone, then tries to
// get a forked history B cosigned. Witnesses refuse, so B has no quorum, and
// holding both views proves the fork.
func TestA6SplitView(t *testing.T) {
	l := newLog(t, 3)
	l.append(10)
	hA := l.head(l.events, l.priv)
	if n, _ := tlog.ParseNote([]byte(hA.Note)); len(n.Sigs) != 4 {
		t.Fatalf("history A should be cosigned by 3 witnesses, got %d sigs", len(n.Sigs)-1)
	}
	viewA := bundle(l.events, []verify2.TreeHead{hA}, 1, l.priv)

	// History B: same size, one event rewritten, re-signed with the real log key.
	evB := slices.Clone(l.events)
	cr, _ := evB[5].V2Record()
	cr.Outcome = "error"
	for i := 5; i < len(evB); i++ {
		if i > 5 {
			cr, _ = evB[i].V2Record()
			cr.PrevHash = evB[i-1].Hash
		}
		p, _ := contract.Parse(evB[i].Metadata)
		evB[i] = l.toRecord(cr, p)
	}
	hB := l.head(evB, l.priv) // witnesses are asked to cosign B...
	if n, _ := tlog.ParseNote([]byte(hB.Note)); len(n.Sigs) != 1 {
		t.Fatalf("witnesses cosigned a forked history (%d cosignatures)", len(n.Sigs)-1)
	}
	for _, ws := range l.wservers {
		if len(ws.Rejected) == 0 {
			t.Fatal("witness did not record the refused fork as evidence")
		}
	}
	viewB := bundle(evB, []verify2.TreeHead{hB}, 1, l.priv)
	// A verifier shown only B: no witness quorum.
	mustFail(t, verify2.Verify(viewB, l.opts()), verify2.InvWitnessQuorum)
	// A verifier holding both views: the fork itself is proven.
	o := l.opts()
	o.Others = []*verify2.Bundle{viewB}
	mustFail(t, verify2.Verify(viewA, o), verify2.InvFork)
	// Only-1-witness collusion is not enough either.
	o2 := l.opts()
	o2.Quorum = 3
	if r := verify2.Verify(viewA, o2); !r.OK {
		t.Fatalf("honest view A should satisfy a 3-of-3 quorum: %v", failed(r))
	}
}

// A7: history signed by a forged key is rejected when the log key is pinned.
func TestA7ForgedKey(t *testing.T) {
	l, heads := fixture(t)
	_, evil, _ := ed25519.GenerateKey(rand.Reader)
	forged := l.head(l.events, evil)
	b := bundle(l.events, []verify2.TreeHead{forged}, 1, l.priv, evil)
	r := verify2.Verify(b, l.opts())
	mustFail(t, r, verify2.InvCheckpointSig)
	// Rows re-signed with the attacker key: key-authorization.
	evs := slices.Clone(l.events)
	for i := range evs {
		evs[i].Signature = keys.Sign(evil, contract.ReceiptMessage(evs[i].Hash))
		evs[i].KeyID = keys.KeyID(evil.Public().(ed25519.PublicKey))
	}
	mustFail(t, verify2.Verify(bundle(evs, heads, 1, l.priv, evil), l.opts()), verify2.InvKeyAuth)
	// Without pinning, the verifier says so loudly.
	o := l.opts()
	o.LogKeys = nil
	if r := verify2.Verify(bundle(l.events, heads, 1, l.priv), o); r.Trust != "UNPINNED" {
		t.Fatal("unpinned verification not flagged")
	}
}
