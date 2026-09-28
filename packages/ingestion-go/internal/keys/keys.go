// Package keys handles API-key hashing, per-tenant Ed25519 signing keys and
// envelope encryption of private keys under the master key (MVP stand-in for
// a KMS; see SECRETS.md).
package keys

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// ---- master key -----------------------------------------------------------

type MasterKey struct{ aead cipher.AEAD }

// ParseMasterKey accepts base64 (std or URL) of exactly 32 random bytes.
func ParseMasterKey(s string) (*MasterKey, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("AUDITTRAIL_MASTER_KEY is not set (generate one with `audittrail-admin gen-master-key`)")
	}
	var b []byte
	var err error
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err = enc.DecodeString(s); err == nil {
			break
		}
	}
	if err != nil || len(b) != 32 {
		return nil, errors.New("AUDITTRAIL_MASTER_KEY must be base64 of 32 bytes")
	}
	block, err := aes.NewCipher(b)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &MasterKey{aead: aead}, nil
}

func GenerateMasterKey() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// Seal encrypts plaintext, binding it to aad (tenant_id|key_id) so a
// ciphertext cannot be swapped onto another tenant's row.
func (m *MasterKey) Seal(plaintext []byte, aad string) string {
	nonce := make([]byte, m.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	ct := m.aead.Seal(nil, nonce, plaintext, []byte(aad))
	return "v1:" + base64.StdEncoding.EncodeToString(append(nonce, ct...))
}

func (m *MasterKey) Open(sealed, aad string) ([]byte, error) {
	rest, ok := strings.CutPrefix(sealed, "v1:")
	if !ok {
		return nil, errors.New("unknown sealed-key format")
	}
	b, err := base64.StdEncoding.DecodeString(rest)
	if err != nil {
		return nil, err
	}
	ns := m.aead.NonceSize()
	if len(b) < ns {
		return nil, errors.New("sealed key too short")
	}
	pt, err := m.aead.Open(nil, b[:ns], b[ns:], []byte(aad))
	if err != nil {
		return nil, errors.New("cannot decrypt signing key (wrong AUDITTRAIL_MASTER_KEY?)")
	}
	return pt, nil
}

// ---- signing keys ---------------------------------------------------------

type SigningKey struct {
	KeyID      string
	Public     ed25519.PublicKey
	Private    ed25519.PrivateKey
	PublicB64  string
	SealedPriv string
}

// KeyID derives a stable id from the public key.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "ed25519:" + hex.EncodeToString(sum[:8])
}

func KeyAAD(tenantID, keyID string) string { return tenantID + "|" + keyID }

func NewSigningKey(m *MasterKey, tenantID string) (*SigningKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	id := KeyID(pub)
	return &SigningKey{
		KeyID:      id,
		Public:     pub,
		Private:    priv,
		PublicB64:  base64.StdEncoding.EncodeToString(pub),
		SealedPriv: m.Seal(priv.Seed(), KeyAAD(tenantID, id)),
	}, nil
}

func OpenSigningKey(m *MasterKey, tenantID, keyID, sealed string) (ed25519.PrivateKey, error) {
	seed, err := m.Open(sealed, KeyAAD(tenantID, keyID))
	if err != nil {
		return nil, err
	}
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("bad seed length")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	if KeyID(priv.Public().(ed25519.PublicKey)) != keyID {
		return nil, fmt.Errorf("key id mismatch for %s", keyID)
	}
	return priv, nil
}

func Sign(priv ed25519.PrivateKey, msg []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg))
}

func Verify(pubB64 string, msg []byte, sigB64 string) bool {
	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, msg, sig)
}

// ---- API keys -------------------------------------------------------------

// API keys look like at_<12 hex prefix>_<43 char secret>. Only the prefix
// (for lookup) and SHA-256 of the whole key are stored.
func NewAPIKey() (full, prefix, hash string) {
	p := make([]byte, 6)
	s := make([]byte, 32)
	if _, err := rand.Read(p); err != nil {
		panic(err)
	}
	if _, err := rand.Read(s); err != nil {
		panic(err)
	}
	prefix = hex.EncodeToString(p)
	full = "at_" + prefix + "_" + base64.RawURLEncoding.EncodeToString(s)
	return full, prefix, HashAPIKey(full)
}

func HashAPIKey(full string) string {
	sum := sha256.Sum256([]byte(full))
	return hex.EncodeToString(sum[:])
}

// ParseAPIKey extracts the lookup prefix.
func ParseAPIKey(full string) (prefix string, ok bool) {
	parts := strings.SplitN(full, "_", 3)
	if len(parts) != 3 || parts[0] != "at" || len(parts[1]) != 12 || len(parts[2]) < 20 {
		return "", false
	}
	return parts[1], true
}

func HashesEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
