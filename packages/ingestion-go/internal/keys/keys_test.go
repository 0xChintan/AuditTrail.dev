package keys

import (
	"strings"
	"testing"
)

func TestAPIKeyRoundTripWithUnderscoresInSecret(t *testing.T) {
	// Regression: base64url secrets may contain '_' and must still parse.
	for i := 0; i < 2000; i++ {
		full, prefix, hash := NewAPIKey()
		p, ok := ParseAPIKey(full)
		if !ok || p != prefix {
			t.Fatalf("parse %q: got %q ok=%v", full, p, ok)
		}
		if !HashesEqual(HashAPIKey(full), hash) {
			t.Fatal("hash mismatch")
		}
	}
	if _, ok := ParseAPIKey("at_short_x"); ok {
		t.Fatal("accepted malformed key")
	}
}

func TestSealOpenBindsTenant(t *testing.T) {
	m, err := ParseMasterKey(GenerateMasterKey())
	if err != nil {
		t.Fatal(err)
	}
	sk, err := NewSigningKey(m, "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSigningKey(m, "tenant-a", sk.KeyID, sk.SealedPriv); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSigningKey(m, "tenant-b", sk.KeyID, sk.SealedPriv); err == nil {
		t.Fatal("sealed key opened under another tenant")
	}
	sig := Sign(sk.Private, []byte("msg"))
	if !Verify(sk.PublicB64, []byte("msg"), sig) || Verify(sk.PublicB64, []byte("msg2"), sig) {
		t.Fatal("signature check wrong")
	}
	if !strings.HasPrefix(sk.KeyID, "ed25519:") {
		t.Fatal(sk.KeyID)
	}
}
