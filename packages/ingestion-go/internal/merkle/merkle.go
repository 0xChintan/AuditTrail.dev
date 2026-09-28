// Package merkle implements RFC 6962 Merkle tree hashing over chain hashes.
package merkle

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

func leafHash(h []byte) []byte {
	s := sha256.New()
	s.Write([]byte{0x00})
	s.Write(h)
	return s.Sum(nil)
}

func nodeHash(l, r []byte) []byte {
	s := sha256.New()
	s.Write([]byte{0x01})
	s.Write(l)
	s.Write(r)
	return s.Sum(nil)
}

func splitPoint(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

func mth(leaves [][]byte) []byte {
	switch len(leaves) {
	case 0:
		e := sha256.Sum256(nil)
		return e[:]
	case 1:
		return leafHash(leaves[0])
	}
	k := splitPoint(len(leaves))
	return nodeHash(mth(leaves[:k]), mth(leaves[k:]))
}

// RootHex computes the Merkle tree head over hex-encoded chain hashes.
func RootHex(hashes []string) (string, error) {
	leaves := make([][]byte, len(hashes))
	for i, h := range hashes {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != 32 {
			return "", fmt.Errorf("leaf %d is not a 32-byte hex hash", i)
		}
		leaves[i] = b
	}
	return hex.EncodeToString(mth(leaves)), nil
}

// InclusionProof returns the RFC 6962 audit path for leaf index m.
func InclusionProof(hashes []string, m int) ([]string, error) {
	if m < 0 || m >= len(hashes) {
		return nil, errors.New("index out of range")
	}
	leaves := make([][]byte, len(hashes))
	for i, h := range hashes {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != 32 {
			return nil, fmt.Errorf("leaf %d is not a 32-byte hex hash", i)
		}
		leaves[i] = b
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
	p := path(m, leaves)
	out := make([]string, len(p))
	for i, b := range p {
		out[i] = hex.EncodeToString(b)
	}
	return out, nil
}

// VerifyInclusion checks an audit path (RFC 9162 §2.1.3.2 algorithm).
func VerifyInclusion(leafHex string, index, size int, proof []string, rootHex string) bool {
	if index < 0 || index >= size {
		return false
	}
	leaf, err := hex.DecodeString(leafHex)
	if err != nil {
		return false
	}
	fn, sn := index, size-1
	r := leafHash(leaf)
	for _, ph := range proof {
		p, err := hex.DecodeString(ph)
		if err != nil || sn == 0 {
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
	return sn == 0 && hex.EncodeToString(r) == rootHex
}
