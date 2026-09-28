package contract

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"regexp"
	"strconv"
	"time"
)

// Request authentication (SPEC §7).

const (
	RequestDomain = "AuditTrail/v2/request\n"
	MaxSkew       = 5 * time.Minute
)

var nonceRe = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)

// SigningKeyFromAPIKey derives the Ed25519 request-signing key from the
// API key string. The server stores only the public half.
func SigningKeyFromAPIKey(apiKey string) ed25519.PrivateKey {
	seed, err := hkdf.Key(sha256.New, []byte(apiKey), []byte("AuditTrail/v2"), "request-signing", ed25519.SeedSize)
	if err != nil {
		panic(err)
	}
	return ed25519.NewKeyFromSeed(seed)
}

// RequestMessage is the byte string a request signature covers.
func RequestMessage(method, path, timestamp, nonce string, body []byte) []byte {
	sum := sha256.Sum256(body)
	return []byte(RequestDomain + method + "\n" + path + "\n" + timestamp + "\n" + nonce + "\n" + hex.EncodeToString(sum[:]))
}

// SignRequest returns the X-AT-Signature header value.
func SignRequest(apiKey, method, path, timestamp, nonce string, body []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(SigningKeyFromAPIKey(apiKey), RequestMessage(method, path, timestamp, nonce, body)))
}

// VerifyRequest checks format, skew and signature. It does NOT check the
// nonce cache (the caller must, atomically). Reason codes are for logs only;
// clients always get a generic 401.
func VerifyRequest(pub ed25519.PublicKey, method, path, timestamp, nonce, sigB64 string, body []byte, now time.Time) (ok bool, reason string) {
	ms, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return false, "bad_timestamp"
	}
	if d := now.Sub(time.UnixMilli(ms)); d > MaxSkew || d < -MaxSkew {
		return false, "timestamp_skew"
	}
	if !nonceRe.MatchString(nonce) {
		return false, "bad_nonce"
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false, "bad_signature_encoding"
	}
	if !ed25519.Verify(pub, RequestMessage(method, path, timestamp, nonce, body), sig) {
		return false, "bad_signature"
	}
	return true, ""
}
