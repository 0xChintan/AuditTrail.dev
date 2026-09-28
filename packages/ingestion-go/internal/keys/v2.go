package keys

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"audittrail.dev/packages/ingestion-go/internal/contract"
)

// Pepper is the server-side secret mixed into stored API-key hashes, so a
// database dump alone can't be used to test guessed keys.
type Pepper []byte

func ParsePepper(s string) (Pepper, error) {
	if len(s) < 32 {
		return nil, errors.New("AUDITTRAIL_KEY_PEPPER must be at least 32 characters")
	}
	return Pepper(s), nil
}

func (p Pepper) HMAC(key string) string {
	m := hmac.New(sha256.New, p)
	m.Write([]byte(key))
	return hex.EncodeToString(m.Sum(nil))
}

// NewAPIKeyV2 returns at2_<prefix>_<secret>, its peppered HMAC and the
// public half of its derived request-signing key (SPEC §7).
func NewAPIKeyV2(p Pepper) (full, prefix, keyHMAC, signPub string) {
	pb := make([]byte, 6)
	sb := make([]byte, 32)
	if _, err := rand.Read(pb); err != nil {
		panic(err)
	}
	if _, err := rand.Read(sb); err != nil {
		panic(err)
	}
	prefix = hex.EncodeToString(pb)
	full = "at2_" + prefix + "_" + base64.RawURLEncoding.EncodeToString(sb)
	pub := contract.SigningKeyFromAPIKey(full).Public().(ed25519.PublicKey)
	return full, prefix, p.HMAC(full), base64.StdEncoding.EncodeToString(pub)
}

// ParseAnyAPIKey returns the key version (1 = at_, 2 = at2_) and prefix.
func ParseAnyAPIKey(full string) (version int, prefix string, ok bool) {
	parts := strings.SplitN(full, "_", 3)
	if len(parts) != 3 || len(parts[1]) != 12 || len(parts[2]) < 20 {
		return 0, "", false
	}
	switch parts[0] {
	case "at":
		return 1, parts[1], true
	case "at2":
		return 2, parts[1], true
	}
	return 0, "", false
}

// ---- UUIDv7 ---------------------------------------------------------------------

// NewUUIDv7 returns a RFC 9562 version-7 UUID (ms timestamp + random).
func NewUUIDv7(now time.Time) string {
	var b [16]byte
	if _, err := rand.Read(b[6:]); err != nil {
		panic(err)
	}
	ms := uint64(now.UnixMilli())                                                                                      // #nosec G115 -- current time is positive
	b[0], b[1], b[2], b[3], b[4], b[5] = byte(ms>>40), byte(ms>>32), byte(ms>>24), byte(ms>>16), byte(ms>>8), byte(ms) // #nosec G115 -- intentional truncation to the 48-bit UUIDv7 timestamp
	b[6] = b[6]&0x0f | 0x70
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
