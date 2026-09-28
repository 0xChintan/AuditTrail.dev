package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileSecrets(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "pepper")
	if err := os.WriteFile(p, []byte("from-file-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AT_TEST_SECRET_FILE", p)
	t.Setenv("AT_TEST_SECRET", "")
	t.Setenv("AT_TEST_KEEP", "explicit")
	t.Setenv("AT_TEST_KEEP_FILE", p)
	resolveFiles()
	if got := os.Getenv("AT_TEST_SECRET"); got != "from-file-secret" {
		t.Fatalf("X_FILE not resolved: %q", got)
	}
	if got := os.Getenv("AT_TEST_KEEP"); got != "explicit" {
		t.Fatalf("an explicit value must win over X_FILE: %q", got)
	}
}

// An explicit X_FILE in the environment beats X from a .env file.
func TestFileSecretBeatsDotEnv(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("AT_TEST_DSN=postgres://from-dotenv\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "dsn")
	if err := os.WriteFile(p, []byte("postgres://from-secret-file"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AT_TEST_DSN_FILE", p)
	os.Unsetenv("AT_TEST_DSN")
	t.Cleanup(func() { os.Unsetenv("AT_TEST_DSN") })
	loadDotEnvFrom(dir)
	resolveFiles()
	if got := os.Getenv("AT_TEST_DSN"); got != "postgres://from-secret-file" {
		t.Fatalf("got %q, want the secret file's value", got)
	}
}
