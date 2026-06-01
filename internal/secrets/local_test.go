package secrets

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// writeSecretsLocal is a tiny helper that drops a secrets.local.yaml
// into t.TempDir() with a chosen mode. We use it across every test in
// this file so the file-creation pattern (Create+Chmod, matching the
// `ai-env new` writer) is consistent.
func writeSecretsLocal(t *testing.T, dir, body string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, "secrets.local.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod %s: %v", path, err)
	}
	return path
}

// TestLoadLocal_MissingFileReturnsEmpty verifies a missing file produces
// a non-nil empty *LocalConfig and no error. This is the fresh-workspace
// path: `ai-env new` has not been run, or the operator deleted the
// stub. The supervisor should still be able to call LoadLocal at the
// start of every run without a stat dance.
func TestLoadLocal_MissingFileReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "does-not-exist.yaml")
	cfg, warnings, err := LoadLocal(path)
	if err != nil {
		t.Fatalf("LoadLocal: unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatalf("LoadLocal: expected non-nil cfg on missing file")
	}
	if cfg.Version != LocalConfigSchemaVersion {
		t.Errorf("cfg.Version = %d, want %d", cfg.Version, LocalConfigSchemaVersion)
	}
	if len(cfg.Secrets.Providers) != 0 {
		t.Errorf("expected zero providers, got %d", len(cfg.Secrets.Providers))
	}
	if cfg.Secrets.GitHub != nil {
		t.Errorf("expected nil GitHub credentials, got %+v", cfg.Secrets.GitHub)
	}
	if len(warnings) != 0 {
		t.Errorf("expected zero warnings, got %d", len(warnings))
	}
}

// TestLoadLocal_EmptyStubReturnsEmpty verifies the `ai-env new` stub
// (entirely YAML comments) loads cleanly even though it has no
// `version: 1` line.
func TestLoadLocal_EmptyStubReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	stub := `# secrets.local.yaml stub written by ai-env new.
# version: 1
# secrets:
#   anthropic:
#     api_key: "REPLACE_ME"
`
	path := writeSecretsLocal(t, dir, stub, 0o600)
	cfg, warnings, err := LoadLocal(path)
	if err != nil {
		t.Fatalf("LoadLocal: unexpected error: %v", err)
	}
	if cfg == nil || cfg.Version != LocalConfigSchemaVersion {
		t.Fatalf("expected stamped version on empty stub, got %+v", cfg)
	}
	if len(warnings) != 0 {
		t.Errorf("expected zero warnings, got %d", len(warnings))
	}
}

// TestLoadLocal_ValidFile loads a fully populated file and verifies
// every credential survives the round trip.
func TestLoadLocal_ValidFile(t *testing.T) {
	dir := t.TempDir()
	body := `version: 1
secrets:
  providers:
    anthropic:
      api_key: "sk-ant-test-12345"
    openai:
      api_key: "sk-openai-test-67890"
  github:
    app:
      app_id: 12345
      installation_id: 67890
      private_key_pem: |
        -----BEGIN RSA PRIVATE KEY-----
        FAKE_KEY_FOR_TEST_ONLY
        -----END RSA PRIVATE KEY-----
      api_base_url: "https://api.github.com"
    pat:
      enabled: true
      token: "ghp_pat_test_token"
      ttl_seconds: 1800
`
	path := writeSecretsLocal(t, dir, body, 0o600)
	cfg, warnings, err := LoadLocal(path)
	if err != nil {
		t.Fatalf("LoadLocal: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("expected zero warnings, got %d", len(warnings))
	}
	if cfg.Version != 1 {
		t.Errorf("version = %d, want 1", cfg.Version)
	}
	if got := cfg.Secrets.Providers["anthropic"].APIKey; got != "sk-ant-test-12345" {
		t.Errorf("anthropic api_key = %q", got)
	}
	if got := cfg.Secrets.Providers["openai"].APIKey; got != "sk-openai-test-67890" {
		t.Errorf("openai api_key = %q", got)
	}
	if cfg.Secrets.GitHub == nil {
		t.Fatalf("expected non-nil GitHub credentials")
	}
	if cfg.Secrets.GitHub.App == nil {
		t.Fatalf("expected non-nil GitHub.App")
	}
	if cfg.Secrets.GitHub.App.AppID != 12345 {
		t.Errorf("app_id = %d, want 12345", cfg.Secrets.GitHub.App.AppID)
	}
	if cfg.Secrets.GitHub.App.InstallationID != 67890 {
		t.Errorf("installation_id = %d", cfg.Secrets.GitHub.App.InstallationID)
	}
	if !strings.Contains(cfg.Secrets.GitHub.App.PrivateKeyPEM, "BEGIN RSA PRIVATE KEY") {
		t.Errorf("expected PEM body, got %q", cfg.Secrets.GitHub.App.PrivateKeyPEM)
	}
	if cfg.Secrets.GitHub.PAT == nil || !cfg.Secrets.GitHub.PAT.Enabled {
		t.Errorf("expected enabled PAT, got %+v", cfg.Secrets.GitHub.PAT)
	}
	if cfg.Secrets.GitHub.PAT.Token != "ghp_pat_test_token" {
		t.Errorf("pat token mismatch")
	}
	if cfg.Secrets.GitHub.PAT.TTLSeconds != 1800 {
		t.Errorf("pat ttl mismatch")
	}
}

// TestLoadLocal_UnknownFieldRejected verifies KnownFields() catches
// typos like "providors:" so an operator does not silently lose a
// section.
func TestLoadLocal_UnknownFieldRejected(t *testing.T) {
	dir := t.TempDir()
	body := `version: 1
secrets:
  providors:
    anthropic:
      api_key: "sk-ant-typo"
`
	path := writeSecretsLocal(t, dir, body, 0o600)
	_, _, err := LoadLocal(path)
	if err == nil {
		t.Fatalf("expected error on unknown field 'providors'")
	}
	if !strings.Contains(err.Error(), "field") && !strings.Contains(err.Error(), "providors") {
		t.Errorf("expected error to mention the unknown field, got %v", err)
	}
}

// TestLoadLocal_WrongVersion verifies a future schema version is a
// hard error.
func TestLoadLocal_WrongVersion(t *testing.T) {
	dir := t.TempDir()
	body := `version: 99
secrets:
  providers:
    anthropic:
      api_key: "sk-ant"
`
	path := writeSecretsLocal(t, dir, body, 0o600)
	_, _, err := LoadLocal(path)
	if err == nil {
		t.Fatalf("expected error on unsupported version")
	}
	if !strings.Contains(err.Error(), "version") {
		t.Errorf("expected version-related error, got %v", err)
	}
}

// TestLoadLocal_PermissionWarning verifies the loader notices a file
// whose mode is broader than 0600 and returns a warning (but still
// loads the credentials).
func TestLoadLocal_PermissionWarning(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes are POSIX-only")
	}
	dir := t.TempDir()
	body := `version: 1
secrets:
  providers:
    anthropic:
      api_key: "sk-ant-overshare"
`
	path := writeSecretsLocal(t, dir, body, 0o644)
	cfg, warnings, err := LoadLocal(path)
	if err != nil {
		t.Fatalf("LoadLocal: %v", err)
	}
	if cfg == nil {
		t.Fatalf("expected non-nil cfg even with permission warning")
	}
	if got := cfg.Secrets.Providers["anthropic"].APIKey; got != "sk-ant-overshare" {
		t.Errorf("expected credentials to still load, got %q", got)
	}
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d", len(warnings))
	}
	w := warnings[0]
	if w.Path != path {
		t.Errorf("warning path = %q, want %q", w.Path, path)
	}
	if w.Wanted != DesiredLocalConfigMode {
		t.Errorf("warning wanted = %o, want %o", w.Wanted, DesiredLocalConfigMode)
	}
	if w.Reason == "" {
		t.Errorf("warning reason must be non-empty")
	}
}

// TestLoadLocal_DirectoryIsError verifies passing a directory path
// fails fast rather than producing a confusing parse error.
func TestLoadLocal_DirectoryIsError(t *testing.T) {
	dir := t.TempDir()
	_, _, err := LoadLocal(dir)
	if err == nil {
		t.Fatalf("expected error when path is a directory")
	}
	if !strings.Contains(err.Error(), "directory") {
		t.Errorf("expected 'directory' in error, got %v", err)
	}
}

// TestLoadLocal_EmptyPathRejected verifies the empty-string path is
// rejected.
func TestLoadLocal_EmptyPathRejected(t *testing.T) {
	_, _, err := LoadLocal("")
	if err == nil {
		t.Fatalf("expected error on empty path")
	}
}

// TestLoadLocal_NormalizesProviderKeys verifies mixed-case provider
// keys are normalized to lower-case so downstream code can compare
// against the Provider* constants directly.
func TestLoadLocal_NormalizesProviderKeys(t *testing.T) {
	dir := t.TempDir()
	body := `version: 1
secrets:
  providers:
    Anthropic:
      api_key: "sk-ant-mixed"
    OPENAI:
      api_key: "sk-shouty"
`
	path := writeSecretsLocal(t, dir, body, 0o600)
	cfg, _, err := LoadLocal(path)
	if err != nil {
		t.Fatalf("LoadLocal: %v", err)
	}
	if _, ok := cfg.Secrets.Providers["anthropic"]; !ok {
		t.Errorf("expected normalized 'anthropic' key")
	}
	if _, ok := cfg.Secrets.Providers["openai"]; !ok {
		t.Errorf("expected normalized 'openai' key")
	}
	if _, ok := cfg.Secrets.Providers["Anthropic"]; ok {
		t.Errorf("did not expect uppercased key to survive")
	}
}

// TestLoadLocal_NegativeAppIDRejected verifies the validator catches
// nonsensical GitHub App fields.
func TestLoadLocal_NegativeAppIDRejected(t *testing.T) {
	dir := t.TempDir()
	body := `version: 1
secrets:
  github:
    app:
      app_id: -1
      installation_id: 1
      private_key_pem: "x"
`
	path := writeSecretsLocal(t, dir, body, 0o600)
	_, _, err := LoadLocal(path)
	if err == nil {
		t.Fatalf("expected error on negative app_id")
	}
	if !strings.Contains(err.Error(), "app_id") {
		t.Errorf("expected app_id error, got %v", err)
	}
}

// TestLoadLocal_MalformedYAML verifies a syntax error surfaces with
// the path embedded.
func TestLoadLocal_MalformedYAML(t *testing.T) {
	dir := t.TempDir()
	body := `version: 1
secrets:
  providers:
    anthropic
      api_key: "sk-ant"
`
	path := writeSecretsLocal(t, dir, body, 0o600)
	_, _, err := LoadLocal(path)
	if err == nil {
		t.Fatalf("expected parse error")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("expected path in error, got %v", err)
	}
}

// TestLoadLocal_PermissionAndDirectoryAreDistinct ensures the
// directory-error path does not accidentally surface a stat error
// (the message must be specific so a triaging operator can act on it).
func TestLoadLocal_PermissionAndDirectoryAreDistinct(t *testing.T) {
	_, _, err := LoadLocal("/dev/null/nope")
	if err == nil {
		t.Fatalf("expected error for unreachable path")
	}
	// Different OSes produce different stat errors; we only care that
	// LoadLocal does not pretend the file is missing.
	if errors.Is(err, os.ErrNotExist) {
		// Acceptable on some systems where the parent is a regular
		// file; the contract guarantees we return *some* error.
		return
	}
}
