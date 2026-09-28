package verify

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"slices"
	"testing"
	"time"

	"github.com/digitorus/timestamp"

	"audittrail.dev/packages/ingestion-go/internal/canon"
	"audittrail.dev/packages/ingestion-go/internal/keys"
	"audittrail.dev/packages/ingestion-go/internal/ledger"
	"audittrail.dev/packages/ingestion-go/internal/merkle"
)

// ---- a local RFC 3161 TSA for offline tests ----------------------------------

type testTSA struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey
	pool *x509.CertPool
}

func newTSA(t *testing.T) *testTSA {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test TSA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		BasicConstraintsValid: true, IsCA: false,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(c)
	return &testTSA{cert: c, key: k, pool: pool}
}

func (a *testTSA) stamp(t *testing.T, stmt []byte) string {
	sum := sha256.Sum256(stmt)
	ts := timestamp.Timestamp{HashAlgorithm: crypto.SHA256, HashedMessage: sum[:], Time: time.Now(),
		Policy: asn1.ObjectIdentifier{1, 2, 3, 4, 1}, AddTSACertificate: true}
	resp, err := ts.CreateResponseWithOpts(a.cert, a.key, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := timestamp.ParseResponse(resp)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(parsed.RawToken)
}

// ---- building a genuine ledger --------------------------------------------------

const tenant = "11111111-2222-4333-8444-555555555555"

type fixture struct {
	b    Bundle
	priv ed25519.PrivateKey
	kid  string
	tsa  *testTSA
}

func build(t *testing.T, n int) *fixture {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	kid := keys.KeyID(pub)
	f := &fixture{priv: priv, kid: kid, tsa: newTSA(t)}
	f.b = Bundle{Format: BundleFormat, Tenant: BundleTenant{ID: tenant, Name: "t"},
		PublicKeys: []PublicKey{{KeyID: kid, Algorithm: "ed25519", PublicKey: base64.StdEncoding.EncodeToString(pub)}}}
	prev := canon.Genesis
	base := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	for i := 1; i <= n; i++ {
		outcome := "allowed"
		if i%5 == 0 {
			outcome = "denied"
		}
		r := ledger.Record{ID: fmt.Sprintf("00000000-0000-4000-8000-%012d", i), TenantID: tenant, Seq: int64(i),
			Timestamp: canon.FormatTime(base.Add(time.Duration(i) * time.Second)), AgentID: "agent", Action: "pay",
			TargetResource: fmt.Sprintf("acct/%d", i), Outcome: outcome, Metadata: json.RawMessage(fmt.Sprintf(`{"amount":%d}`, i*10)),
			PreviousHash: prev, KeyID: kid}
		f.reseal(t, &r)
		f.b.Events = append(f.b.Events, r)
		prev = r.Hash
	}
	f.b.Checkpoints = []ledger.Checkpoint{f.checkpoint(t, 1, int64(n), canon.Genesis)}
	return f
}

// reseal recomputes hash + signature (what an attacker holding the key could do).
func (f *fixture) reseal(t *testing.T, r *ledger.Record) {
	ce, err := r.CanonEvent()
	if err != nil {
		t.Fatal(err)
	}
	r.Hash, _, _ = canon.HashEvent(r.PreviousHash, ce)
	r.Signature = keys.Sign(f.priv, canon.EventSigningMessage(r.Hash))
}

func (f *fixture) checkpoint(t *testing.T, first, last int64, prevHead string) ledger.Checkpoint {
	var hs []string
	for _, e := range f.b.Events {
		if e.Seq >= first && e.Seq <= last {
			hs = append(hs, e.Hash)
		}
	}
	root, _ := merkle.RootHex(hs)
	st := canon.CheckpointStatement{Type: canon.CheckpointType, TenantID: tenant, FirstSeq: first, LastSeq: last,
		RowCount: last - first + 1, MerkleRoot: root, HeadHash: hs[len(hs)-1], PrevCheckpointHead: prevHead, CreatedAt: "2026-09-01T13:00:00.000Z"}
	sb, _ := st.Bytes()
	proof := f.tsa.stamp(t, sb)
	return ledger.Checkpoint{ID: "cp-1", TenantID: tenant, FirstSeq: first, LastSeq: last, RowCount: last - first + 1,
		MerkleRoot: root, HeadHash: st.HeadHash, PrevCheckpointHead: prevHead, Statement: string(sb),
		Signature: keys.Sign(f.priv, sb), KeyID: f.kid, ExternalAnchorProof: &proof, AnchorStatus: "anchored"}
}

func kinds(r Report) []string {
	var k []string
	for _, i := range r.Issues {
		if i.Severity == "error" && !slices.Contains(k, i.Kind) {
			k = append(k, i.Kind)
		}
	}
	slices.Sort(k)
	return k
}

// ---- the adversary ladder ----------------------------------------------------------

func TestCleanLedgerVerifies(t *testing.T) {
	f := build(t, 20)
	r := Verify(f.b, Options{TSARoots: f.tsa.pool, RequireAnchors: true})
	if !r.OK || r.SignaturesVerified != 20 || r.Anchors[0].Status != "verified" || r.Anchors[0].ChainTrust != "verified" {
		t.Fatalf("clean ledger failed: %+v", r)
	}
}

func TestNaiveEditIsLocalized(t *testing.T) {
	f := build(t, 20)
	f.b.Events[6].Outcome = "allowed" // seq 7
	f.b.Events[6].Metadata = json.RawMessage(`{"amount":1}`)
	r := Verify(f.b, Options{})
	if r.OK || !slices.Equal(r.TamperedSeqs, []int64{7}) {
		t.Fatalf("want tamper at [7], got %v %v", r.TamperedSeqs, kinds(r))
	}
}

func TestRehashForwardWithoutKeyIsCaught(t *testing.T) {
	// Attacker edits seq 10 and recomputes every later hash so links look
	// fine, but cannot produce valid signatures and cannot move the anchored root.
	f := build(t, 20)
	f.b.Events[9].Outcome = "allowed"
	for i := 9; i < 20; i++ {
		if i > 9 {
			f.b.Events[i].PreviousHash = f.b.Events[i-1].Hash
		}
		ce, _ := f.b.Events[i].CanonEvent()
		f.b.Events[i].Hash, _, _ = canon.HashEvent(f.b.Events[i].PreviousHash, ce)
	}
	r := Verify(f.b, Options{})
	if r.OK || r.TamperedSeqs[0] != 10 || !slices.Contains(kinds(r), "bad_signature") || !slices.Contains(kinds(r), "checkpoint_root_mismatch") {
		t.Fatalf("got %v %v", r.TamperedSeqs, kinds(r))
	}
}

func TestRewriteWithStolenKeyIsCaughtByCheckpoint(t *testing.T) {
	// Attacker has the tenant signing key: re-signs every rewritten row. The
	// externally anchored checkpoint root still exposes the rewrite.
	f := build(t, 20)
	f.b.Events[9].Outcome = "allowed"
	for i := 9; i < 20; i++ {
		if i > 9 {
			f.b.Events[i].PreviousHash = f.b.Events[i-1].Hash
		}
		f.reseal(t, &f.b.Events[i])
	}
	r := Verify(f.b, Options{})
	if r.OK || !slices.Contains(kinds(r), "checkpoint_root_mismatch") || len(r.TamperedSeqs) != 20 {
		t.Fatalf("got %v %v", kinds(r), r.TamperedSeqs)
	}
}

func TestForgedCheckpointIsCaughtByExternalAnchor(t *testing.T) {
	// Attacker with the key also rewrites and re-signs the checkpoint
	// statement. They cannot get the TSA to back-date a new time-stamp, so the
	// old token's imprint no longer matches.
	f := build(t, 20)
	f.b.Events[9].Outcome = "allowed"
	for i := 9; i < 20; i++ {
		if i > 9 {
			f.b.Events[i].PreviousHash = f.b.Events[i-1].Hash
		}
		f.reseal(t, &f.b.Events[i])
	}
	oldProof := f.b.Checkpoints[0].ExternalAnchorProof
	f.b.Checkpoints[0] = f.checkpoint(t, 1, 20, canon.Genesis)
	f.b.Checkpoints[0].ExternalAnchorProof = oldProof
	r := Verify(f.b, Options{})
	if r.OK || !slices.Contains(kinds(r), "anchor_invalid") {
		t.Fatalf("got %v", kinds(r))
	}
}

func TestDeletedRowIsNamed(t *testing.T) {
	f := build(t, 20)
	f.b.Events = append(f.b.Events[:11], f.b.Events[12:]...) // drop seq 12
	r := Verify(f.b, Options{})
	if r.OK || !slices.Contains(r.TamperedSeqs, 12) || !slices.Contains(kinds(r), "checkpoint_rows_missing") {
		t.Fatalf("got %v %v", r.TamperedSeqs, kinds(r))
	}
}

func TestUntrustedTSAIsRejectedWhenRootsGiven(t *testing.T) {
	f := build(t, 5)
	other := newTSA(t)
	r := Verify(f.b, Options{TSARoots: other.pool})
	if r.OK || !slices.Contains(kinds(r), "anchor_invalid") {
		t.Fatalf("got %v", kinds(r))
	}
}

func TestPurgedPrefixVerifiesFromCheckpoint(t *testing.T) {
	// Rows 1..10 purged under retention; the chain resumes from checkpoint 1's
	// signed head hash.
	f := build(t, 20)
	cp1 := f.checkpoint(t, 1, 10, canon.Genesis)
	cp1.ID = "cp-a"
	cp2 := f.checkpoint(t, 11, 20, cp1.HeadHash)
	cp2.ID = "cp-b"
	f.b.Checkpoints = []ledger.Checkpoint{cp1, cp2}
	f.b.Events = f.b.Events[10:]
	r := Verify(f.b, Options{})
	if !r.OK || r.ChainStart != "checkpoint:cp-a" {
		t.Fatalf("got ok=%v start=%s %v", r.OK, r.ChainStart, kinds(r))
	}
	// ...and a forged first row after the purge is still caught.
	f.b.Events[0].PreviousHash = bytes.NewBufferString(canon.Genesis).String()
	f.reseal(t, &f.b.Events[0])
	if r := Verify(f.b, Options{}); r.OK {
		t.Fatal("forged chain start accepted")
	}
}
