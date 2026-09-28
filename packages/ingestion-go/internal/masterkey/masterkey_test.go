package masterkey

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func newMaster(t *testing.T) string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// fakeAWSKMS speaks the AWS KMS JSON protocol (TrentService.Encrypt/Decrypt)
// and seals with its own AES key, so ciphertexts only open through it.
func fakeAWSKMS(t *testing.T) (*httptest.Server, *atomic.Int32) {
	kek := make([]byte, 32)
	_, _ = rand.Read(kek)
	blk, _ := aes.NewCipher(kek)
	gcm, _ := cipher.NewGCM(blk)
	var decrypts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			http.Error(w, `{"__type":"UnrecognizedClientException"}`, 400)
			return
		}
		var in struct{ KeyId, Plaintext, CiphertextBlob string }
		_ = json.NewDecoder(r.Body).Decode(&in)
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		switch r.Header.Get("X-Amz-Target") {
		case "TrentService.Encrypt":
			pt, _ := base64.StdEncoding.DecodeString(in.Plaintext)
			nonce := make([]byte, gcm.NonceSize())
			_, _ = rand.Read(nonce)
			ct := gcm.Seal(nonce, nonce, pt, []byte(in.KeyId))
			_ = json.NewEncoder(w).Encode(map[string]string{"KeyId": in.KeyId, "CiphertextBlob": base64.StdEncoding.EncodeToString(append([]byte(in.KeyId+"|"), ct...))})
		case "TrentService.Decrypt":
			decrypts.Add(1)
			raw, _ := base64.StdEncoding.DecodeString(in.CiphertextBlob)
			keyID, ct, _ := strings.Cut(string(raw), "|")
			n := gcm.NonceSize()
			if len(ct) < n {
				http.Error(w, `{"__type":"InvalidCiphertextException"}`, 400)
				return
			}
			pt, err := gcm.Open(nil, []byte(ct[:n]), []byte(ct[n:]), []byte(keyID))
			if err != nil {
				http.Error(w, `{"__type":"InvalidCiphertextException"}`, 400)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"KeyId": keyID, "Plaintext": base64.StdEncoding.EncodeToString(pt)})
		default:
			http.Error(w, `{"__type":"UnknownOperationException"}`, 400)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &decrypts
}

func TestAWSKMSRoundTrip(t *testing.T) {
	srv, decrypts := fakeAWSKMS(t)
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDTEST")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test-secret")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	url := "awskms://alias/audittrail?region=eu-central-1&endpoint=" + srv.URL
	ctx := context.Background()
	master := newMaster(t)
	wrapped, err := Wrap(ctx, url, master)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(wrapped, master) {
		t.Fatal("wrapped blob contains the plaintext key")
	}
	t.Setenv(EnvPlain, "")
	t.Setenv(EnvKMSKey, url)
	t.Setenv(EnvWrapped, wrapped)
	t.Setenv(EnvRequireKMS, "true")
	m, src, err := Load(ctx)
	if err != nil || src != FromKMS || m == nil {
		t.Fatalf("load: %v %v", src, err)
	}
	if decrypts.Load() != 1 {
		t.Fatalf("expected exactly one KMS Decrypt, got %d", decrypts.Load())
	}
	// The unwrapped key must be the original: seal with it, open with the original.
	sealed := m.Seal([]byte("tenant seed"), "t1|k1")
	t.Setenv(EnvKMSKey, "")
	t.Setenv(EnvWrapped, "")
	t.Setenv(EnvRequireKMS, "")
	t.Setenv(EnvPlain, master)
	m2, _, err := Load(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := m2.Open(sealed, "t1|k1"); err != nil || string(pt) != "tenant seed" {
		t.Fatalf("the KMS-unwrapped key differs from the original: %v", err)
	}
	// A tampered wrapped blob is rejected by the KMS.
	bad := []byte(wrapped)
	bad[len(bad)-3] ^= 1
	if _, err := Unwrap(ctx, url, string(bad)); err == nil {
		t.Fatal("tampered wrapped key accepted")
	}
}

func TestLoadRules(t *testing.T) {
	ctx := context.Background()
	master := newMaster(t)
	local := "base64key://" + base64.URLEncoding.EncodeToString(make([]byte, 32))
	wrapped, err := Wrap(ctx, local, master)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name                         string
		plain, url, wrapped, require string
		wantErr                      string
		wantSrc                      Source
	}{
		{"plaintext (dev)", master, "", "", "", "", FromEnv},
		{"plaintext refused when KMS required", master, "", "", "true", "REQUIRE_KMS", ""},
		{"both set is ambiguous", master, local, wrapped, "", "both", ""},
		{"kms without wrapped key", "", local, "", "", "WRAPPED is empty", ""},
		{"local key is not a KMS", "", local, wrapped, "true", "not a KMS", ""},
		{"local key allowed for tests", "", local, wrapped, "", "", FromKMS},
		{"wrong KMS key", "", "base64key://" + base64.URLEncoding.EncodeToString([]byte(strings.Repeat("x", 32))), wrapped, "", "decrypt", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv(EnvPlain, c.plain)
			t.Setenv(EnvKMSKey, c.url)
			t.Setenv(EnvWrapped, c.wrapped)
			t.Setenv(EnvRequireKMS, c.require)
			_, src, err := Load(ctx)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("want error containing %q, got %v", c.wantErr, err)
				}
				if strings.Contains(err.Error(), master) {
					t.Fatal("error message leaks the master key")
				}
				return
			}
			if err != nil || src != c.wantSrc {
				t.Fatalf("got %v %v", src, err)
			}
		})
	}
}
