// Package masterkey loads the master key (the KEK that seals tenant signing
// keys and per-subject PII keys) either from the environment (development)
// or by unwrapping a KMS-encrypted copy at startup (production).
//
// With a KMS, the plaintext key never exists on disk or in configuration:
// only AUDITTRAIL_MASTER_KEY_WRAPPED (ciphertext) is deployed, the process
// unwraps it once at startup, and every unwrap is subject to the KMS's
// access policy and audit log. Supported key URLs:
//
//	awskms://alias/audittrail?region=eu-central-1         AWS KMS
//	gcpkms://projects/P/locations/L/keyRings/R/cryptoKeys/K  Google Cloud KMS
//	azurekeyvault://VAULT.vault.azure.net/keys/K           Azure Key Vault
//	hashivault://audittrail                                HashiCorp Vault transit
//	base64key://<32 bytes b64>                             local only: NOT a KMS (tests)
package masterkey

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"gocloud.dev/secrets"
	_ "gocloud.dev/secrets/awskms"
	_ "gocloud.dev/secrets/azurekeyvault"
	_ "gocloud.dev/secrets/gcpkms"
	_ "gocloud.dev/secrets/hashivault"
	_ "gocloud.dev/secrets/localsecrets"

	"audittrail.dev/packages/ingestion-go/internal/keys"
)

// Environment variables (each also accepts the *_FILE form).
const (
	EnvPlain      = "AUDITTRAIL_MASTER_KEY"
	EnvKMSKey     = "AUDITTRAIL_KMS_KEY_URL"
	EnvWrapped    = "AUDITTRAIL_MASTER_KEY_WRAPPED"
	EnvRequireKMS = "AUDITTRAIL_REQUIRE_KMS"
)

// Source says where the loaded key came from (for startup logs).
type Source string

const (
	FromEnv Source = "environment"
	FromKMS Source = "kms"
)

// Load returns the master key from the environment or the KMS.
func Load(ctx context.Context) (*keys.MasterKey, Source, error) {
	plain := strings.TrimSpace(os.Getenv(EnvPlain))
	keyURL := strings.TrimSpace(os.Getenv(EnvKMSKey))
	wrapped := strings.TrimSpace(os.Getenv(EnvWrapped))
	requireKMS := os.Getenv(EnvRequireKMS) == "true"

	switch {
	case keyURL != "" && plain != "":
		return nil, "", fmt.Errorf("both %s and %s are set: deploy only the wrapped key when using a KMS", EnvPlain, EnvKMSKey)
	case keyURL == "":
		if requireKMS {
			return nil, "", fmt.Errorf("%s=true but %s is not set: refusing a plaintext master key", EnvRequireKMS, EnvKMSKey)
		}
		m, err := keys.ParseMasterKey(plain)
		return m, FromEnv, err
	}
	if requireKMS && strings.HasPrefix(keyURL, "base64key://") {
		return nil, "", fmt.Errorf("%s=true: base64key:// is not a KMS", EnvRequireKMS)
	}
	if wrapped == "" {
		return nil, "", fmt.Errorf("%s is set but %s is empty (create it with `audittrail-admin kms-wrap`)", EnvKMSKey, EnvWrapped)
	}
	b64, err := Unwrap(ctx, keyURL, wrapped)
	if err != nil {
		return nil, "", err
	}
	m, err := keys.ParseMasterKey(b64)
	return m, FromKMS, err
}

// Wrap encrypts a base64 master key with the KMS key and returns base64
// ciphertext for AUDITTRAIL_MASTER_KEY_WRAPPED.
func Wrap(ctx context.Context, keyURL, masterB64 string) (string, error) {
	if _, err := keys.ParseMasterKey(masterB64); err != nil {
		return "", err
	}
	k, err := open(ctx, keyURL)
	if err != nil {
		return "", err
	}
	defer k.Close()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	ct, err := k.Encrypt(ctx, []byte(strings.TrimSpace(masterB64)))
	if err != nil {
		return "", fmt.Errorf("kms encrypt: %w", err)
	}
	return base64.StdEncoding.EncodeToString(ct), nil
}

// Unwrap decrypts AUDITTRAIL_MASTER_KEY_WRAPPED with the KMS key.
func Unwrap(ctx context.Context, keyURL, wrapped string) (string, error) {
	ct, err := base64.StdEncoding.DecodeString(strings.TrimSpace(wrapped))
	if err != nil {
		return "", fmt.Errorf("%s: not base64: %w", EnvWrapped, err)
	}
	k, err := open(ctx, keyURL)
	if err != nil {
		return "", err
	}
	defer k.Close()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	pt, err := k.Decrypt(ctx, ct)
	if err != nil {
		// The KMS's reason (permission denied, wrong key) is useful to the
		// operator and contains no secret material.
		return "", fmt.Errorf("kms decrypt of the wrapped master key: %w", err)
	}
	return string(pt), nil
}

func open(ctx context.Context, keyURL string) (*secrets.Keeper, error) {
	if keyURL == "" {
		return nil, errors.New("KMS key URL is empty")
	}
	k, err := secrets.OpenKeeper(ctx, keyURL)
	if err != nil {
		return nil, fmt.Errorf("open KMS key %s: %w", redactURL(keyURL), err)
	}
	return k, nil
}

// redactURL hides base64key:// material in error messages.
func redactURL(u string) string {
	if strings.HasPrefix(u, "base64key://") {
		return "base64key://…"
	}
	return u
}
