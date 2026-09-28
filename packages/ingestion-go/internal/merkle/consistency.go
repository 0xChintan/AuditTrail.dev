package merkle

import (
	"bytes"
	"encoding/hex"
	"fmt"
)

// RootRaw computes the RFC 9162 tree head over raw 32-byte leaves.
func RootRaw(leaves [][]byte) []byte { return mth(leaves) }

func decodeAll(hashes []string) ([][]byte, error) {
	out := make([][]byte, len(hashes))
	for i, h := range hashes {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != 32 {
			return nil, fmt.Errorf("leaf %d is not a 32-byte hex hash", i)
		}
		out[i] = b
	}
	return out, nil
}

// ConsistencyProof returns the RFC 9162 §2.1.4 proof that the tree of size
// m is a prefix of the tree over all leaves (size n = len(leaves)).
func ConsistencyProof(leaves [][]byte, m int) ([][]byte, error) {
	n := len(leaves)
	if m < 0 || m > n {
		return nil, fmt.Errorf("old size %d out of range 0..%d", m, n)
	}
	if m == 0 || m == n {
		return [][]byte{}, nil
	}
	var sub func(m int, d [][]byte, b bool) [][]byte
	sub = func(m int, d [][]byte, b bool) [][]byte {
		if m == len(d) {
			if b {
				return nil
			}
			return [][]byte{mth(d)}
		}
		k := splitPoint(len(d))
		if m <= k {
			return append(sub(m, d[:k], b), mth(d[k:]))
		}
		return append(sub(m-k, d[k:], false), mth(d[:k]))
	}
	return sub(m, leaves, true), nil
}

// VerifyConsistency checks an RFC 9162 §2.1.4.2 consistency proof.
func VerifyConsistency(first, second uint64, firstRoot, secondRoot []byte, proof [][]byte) bool {
	if first > second {
		return false
	}
	if first == second {
		return len(proof) == 0 && bytes.Equal(firstRoot, secondRoot)
	}
	if first == 0 {
		return len(proof) == 0
	}
	if len(proof) == 0 {
		return false
	}
	p := proof
	if first&(first-1) == 0 {
		p = append([][]byte{firstRoot}, proof...)
	}
	fn, sn := first-1, second-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	fr, sr := p[0], p[0]
	for _, c := range p[1:] {
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			fr = nodeHash(c, fr)
			sr = nodeHash(c, sr)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			sr = nodeHash(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && bytes.Equal(fr, firstRoot) && bytes.Equal(sr, secondRoot)
}

// InclusionProofRaw is InclusionProof over raw leaves.
func InclusionProofRaw(leaves [][]byte, m int) ([][]byte, error) {
	if m < 0 || m >= len(leaves) {
		return nil, fmt.Errorf("index out of range")
	}
	var path func(m int, d [][]byte) [][]byte
	path = func(m int, d [][]byte) [][]byte {
		if len(d) <= 1 {
			return nil
		}
		k := splitPoint(len(d))
		if m < k {
			return append(path(m, d[:k]), mth(d[k:]))
		}
		return append(path(m-k, d[k:]), mth(d[:k]))
	}
	return path(m, leaves), nil
}

// VerifyInclusionRaw checks an inclusion proof for a raw leaf.
func VerifyInclusionRaw(leaf []byte, index, size uint64, proof [][]byte, root []byte) bool {
	if index >= size {
		return false
	}
	fn, sn := index, size-1
	r := leafHash(leaf)
	for _, p := range proof {
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			r = nodeHash(p, r)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = nodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && bytes.Equal(r, root)
}

// DecodeHex is a helper for callers holding hex leaves.
func DecodeHex(hashes []string) ([][]byte, error) { return decodeAll(hashes) }
