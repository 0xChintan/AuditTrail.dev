package merkle

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/merkle/testonly"
)

// External RFC 6962 vectors (the certificate-transparency test data, via
// transparency-dev/merkle/testonly).
func TestRFC6962RootVectors(t *testing.T) {
	leaves := testonly.LeafInputs()
	roots := testonly.RootHashes()
	// roots[n] is the root of the first n leaves (roots[0] = empty tree).
	if len(roots) != len(leaves)+1 {
		t.Fatalf("unexpected vector shape %d/%d", len(roots), len(leaves))
	}
	for n := 0; n <= len(leaves); n++ {
		if got := RootRaw(leaves[:n]); !bytes.Equal(got, roots[n]) {
			t.Fatalf("size %d: root %x, want %x", n, got, roots[n])
		}
	}
	if got := RootRaw(nil); !bytes.Equal(got, testonly.EmptyRootHash()) {
		t.Fatalf("empty root %x", got)
	}
}

func data(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		s := sha256.Sum256([]byte(fmt.Sprint("leaf", i)))
		out[i] = s[:]
	}
	return out
}

// Every inclusion and consistency proof must equal the reference
// implementation's, and verify with both verifiers.
func TestProofsMatchReferenceImplementation(t *testing.T) {
	for n := 1; n <= 70; n++ {
		d := data(n)
		ref := testonly.New(rfc6962.DefaultHasher)
		ref.AppendData(d...)
		root := RootRaw(d)
		if !bytes.Equal(root, ref.Hash()) {
			t.Fatalf("n=%d root mismatch", n)
		}
		for m := 0; m < n; m++ {
			p, _ := InclusionProofRaw(d, m)
			rp, err := ref.InclusionProof(uint64(m), uint64(n))
			if err != nil {
				t.Fatal(err)
			}
			if len(p) != len(rp) {
				t.Fatalf("n=%d m=%d incl len %d vs %d", n, m, len(p), len(rp))
			}
			for i := range p {
				if !bytes.Equal(p[i], rp[i]) {
					t.Fatalf("n=%d m=%d incl[%d] differs", n, m, i)
				}
			}
			if !VerifyInclusionRaw(d[m], uint64(m), uint64(n), p, root) {
				t.Fatalf("n=%d m=%d our verifier rejects", n, m)
			}
			if err := proof.VerifyInclusion(rfc6962.DefaultHasher, uint64(m), uint64(n), rfc6962.DefaultHasher.HashLeaf(d[m]), p, root); err != nil {
				t.Fatalf("n=%d m=%d reference verifier rejects: %v", n, m, err)
			}
		}
		for m := 0; m <= n; m++ {
			p, _ := ConsistencyProof(d, m)
			rp, err := ref.ConsistencyProof(uint64(m), uint64(n))
			if err != nil {
				t.Fatal(err)
			}
			if len(p) != len(rp) {
				t.Fatalf("n=%d m=%d cons len %d vs %d", n, m, len(p), len(rp))
			}
			for i := range p {
				if !bytes.Equal(p[i], rp[i]) {
					t.Fatalf("n=%d m=%d cons[%d] differs", n, m, i)
				}
			}
			old := RootRaw(d[:m])
			if !VerifyConsistency(uint64(m), uint64(n), old, root, p) {
				t.Fatalf("n=%d m=%d our consistency verifier rejects", n, m)
			}
			if m > 0 && m < n {
				bad := append([]byte(nil), old...)
				bad[0] ^= 1
				if VerifyConsistency(uint64(m), uint64(n), bad, root, p) {
					t.Fatalf("n=%d m=%d accepted wrong old root", n, m)
				}
				if err := proof.VerifyConsistency(rfc6962.DefaultHasher, uint64(m), uint64(n), p, old, root); err != nil {
					t.Fatalf("n=%d m=%d reference consistency verifier rejects: %v", n, m, err)
				}
			}
		}
	}
}
