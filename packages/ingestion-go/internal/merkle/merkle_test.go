package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
)

func hashes(n int) []string {
	out := make([]string, n)
	for i := range out {
		s := sha256.Sum256([]byte(fmt.Sprint(i)))
		out[i] = hex.EncodeToString(s[:])
	}
	return out
}

func TestInclusionProofsAllSizes(t *testing.T) {
	for n := 1; n <= 70; n++ {
		hs := hashes(n)
		root, err := RootHex(hs)
		if err != nil {
			t.Fatal(err)
		}
		for m := 0; m < n; m++ {
			p, err := InclusionProof(hs, m)
			if err != nil {
				t.Fatal(err)
			}
			if !VerifyInclusion(hs[m], m, n, p, root) {
				t.Fatalf("n=%d m=%d proof failed", n, m)
			}
			if n > 1 && VerifyInclusion(hs[(m+1)%n], m, n, p, root) {
				t.Fatalf("n=%d m=%d wrong leaf accepted", n, m)
			}
		}
	}
}

func TestRootChangesWhenAnyLeafChanges(t *testing.T) {
	hs := hashes(33)
	root, _ := RootHex(hs)
	for i := range hs {
		c := append([]string(nil), hs...)
		c[i] = hashes(34)[33]
		r2, _ := RootHex(c)
		if r2 == root {
			t.Fatalf("leaf %d change not reflected", i)
		}
	}
}
