package mcp

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// writeFile drops a YAML fixture into the test temp dir. Mirrors
// the helper used by internal/config's loader tests so test
// authors don't have to relearn the convention.
func writeFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// validRegistryYAML is the canonical fixture: two registered
// servers (filesystem + github) covering both supported scope
// kinds, both supported source kinds, and a digest pin. Tests
// mutate copies of this to exercise individual error paths.
const validRegistryYAML = `version: 1
default: deny
servers:
  filesystem:
    source: npm:@modelcontextprotocol/server-filesystem@1.2.3
    digest: sha256:abc123
    schema_hash: sha256:def456
    scope:
      filesystem:
        root: workspace_only
    policy: allow
  github:
    source: oci:ghcr.io/example/server-github:1.1.0
    digest: sha256:ghi789
    schema_hash: sha256:jkl012
    scope:
      github:
        repos: current_repo_only
        operations: read_only
    policy: warn
`

func TestLoadRegistry_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.yaml")
	writeFile(t, path, validRegistryYAML)

	reg, err := LoadRegistry(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := reg.DefaultPolicy(), DefaultPolicyDeny; got != want {
		t.Errorf("DefaultPolicy = %q, want %q", got, want)
	}
	if got, want := reg.Names(), []string{"filesystem", "github"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Names = %v, want %v", got, want)
	}
	fs, err := reg.Lookup("filesystem")
	if err != nil {
		t.Fatalf("Lookup(filesystem): %v", err)
	}
	if fs.Source != "npm:@modelcontextprotocol/server-filesystem@1.2.3" {
		t.Errorf("filesystem source = %q", fs.Source)
	}
	if fs.Scope[ScopeKindFilesystem].Root != FilesystemRootWorkspaceOnly {
		t.Errorf("filesystem scope root = %q", fs.Scope[ScopeKindFilesystem].Root)
	}
}

func TestLoadRegistry_FileMissing(t *testing.T) {
	_, err := LoadRegistry(filepath.Join(t.TempDir(), "nope.yaml"))
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
	if !strings.Contains(err.Error(), "read") {
		t.Errorf("error should mention read: %v", err)
	}
}

func TestLoadRegistry_UnknownFieldRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.yaml")
	writeFile(t, path, validRegistryYAML+"\nbogus_unknown_field: true\n")

	_, err := LoadRegistry(path)
	if err == nil {
		t.Fatal("expected error for unknown field, got nil")
	}
	if !strings.Contains(err.Error(), "parse") {
		t.Errorf("error should mention parse: %v", err)
	}
}

func TestValidateRegistry_NilConfig(t *testing.T) {
	if err := ValidateRegistry(nil); err == nil {
		t.Fatal("expected error for nil config")
	}
}

func TestValidateRegistry_VersionMismatch(t *testing.T) {
	cfg := mustParseRegistry(t, validRegistryYAML)
	cfg.Version = 2
	requireFieldErr(t, ValidateRegistry(cfg), "version")
}

func TestValidateRegistry_DefaultMustBeDeny(t *testing.T) {
	cfg := mustParseRegistry(t, validRegistryYAML)
	cfg.Default = "allow"
	requireFieldErr(t, ValidateRegistry(cfg), "default")
}

func TestValidateRegistry_EmptyServers(t *testing.T) {
	cfg := mustParseRegistry(t, validRegistryYAML)
	cfg.Servers = map[string]RegistryServer{}
	requireFieldErr(t, ValidateRegistry(cfg), "servers")
}

func TestValidateRegistry_SourceRules(t *testing.T) {
	cases := []struct {
		name      string
		mutate    func(*RegistryServer)
		fieldHint string
	}{
		{"empty_source", func(s *RegistryServer) { s.Source = "" }, "servers.filesystem.source"},
		{"unknown_kind", func(s *RegistryServer) { s.Source = "git:https://example/repo@1.0.0" }, "servers.filesystem.source"},
		{"npm_no_version", func(s *RegistryServer) { s.Source = "npm:@scope/pkg" }, "servers.filesystem.source"},
		{"npm_trailing_at", func(s *RegistryServer) { s.Source = "npm:@scope/pkg@" }, "servers.filesystem.source"},
		{"oci_no_tag", func(s *RegistryServer) { s.Source = "oci:ghcr.io/example/server" }, "servers.filesystem.source"},
		{"oci_trailing_colon", func(s *RegistryServer) { s.Source = "oci:ghcr.io/example/server:" }, "servers.filesystem.source"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := mustParseRegistry(t, validRegistryYAML)
			fs := cfg.Servers["filesystem"]
			tc.mutate(&fs)
			cfg.Servers["filesystem"] = fs
			requireFieldErr(t, ValidateRegistry(cfg), tc.fieldHint)
		})
	}
}

func TestValidateRegistry_DigestShape(t *testing.T) {
	cfg := mustParseRegistry(t, validRegistryYAML)
	fs := cfg.Servers["filesystem"]
	fs.Digest = "md5:nope"
	cfg.Servers["filesystem"] = fs
	requireFieldErr(t, ValidateRegistry(cfg), "servers.filesystem.digest")
}

func TestValidateRegistry_EmptyDigestAllowed(t *testing.T) {
	cfg := mustParseRegistry(t, validRegistryYAML)
	fs := cfg.Servers["filesystem"]
	fs.Digest = ""
	cfg.Servers["filesystem"] = fs
	if err := ValidateRegistry(cfg); err != nil {
		t.Fatalf("empty digest must be permitted: %v", err)
	}
}

func TestValidateRegistry_SchemaHashShape(t *testing.T) {
	cfg := mustParseRegistry(t, validRegistryYAML)
	fs := cfg.Servers["filesystem"]
	fs.SchemaHash = "not-a-hash"
	cfg.Servers["filesystem"] = fs
	requireFieldErr(t, ValidateRegistry(cfg), "servers.filesystem.schema_hash")
}

func TestValidateRegistry_PolicyEnum(t *testing.T) {
	cfg := mustParseRegistry(t, validRegistryYAML)
	fs := cfg.Servers["filesystem"]
	fs.Policy = "maybe"
	cfg.Servers["filesystem"] = fs
	requireFieldErr(t, ValidateRegistry(cfg), "servers.filesystem.policy")
}

func TestValidateRegistry_UnknownScopeKind(t *testing.T) {
	cfg := mustParseRegistry(t, validRegistryYAML)
	fs := cfg.Servers["filesystem"]
	fs.Scope = map[string]ScopeSection{
		"network": {Root: "workspace_only"},
	}
	cfg.Servers["filesystem"] = fs
	requireFieldErr(t, ValidateRegistry(cfg), "servers.filesystem.scope.network")
}

func TestValidateRegistry_FilesystemScopeForbidsGithubFields(t *testing.T) {
	cfg := mustParseRegistry(t, validRegistryYAML)
	fs := cfg.Servers["filesystem"]
	fs.Scope = map[string]ScopeSection{
		ScopeKindFilesystem: {Root: FilesystemRootWorkspaceOnly, Repos: GitHubReposCurrentRepoOnly},
	}
	cfg.Servers["filesystem"] = fs
	requireFieldErr(t, ValidateRegistry(cfg), "servers.filesystem.scope.filesystem")
}

func TestValidateRegistry_GitHubScopeForbidsFilesystemFields(t *testing.T) {
	cfg := mustParseRegistry(t, validRegistryYAML)
	gh := cfg.Servers["github"]
	gh.Scope = map[string]ScopeSection{
		ScopeKindGitHub: {
			Root:       FilesystemRootWorkspaceOnly,
			Repos:      GitHubReposCurrentRepoOnly,
			Operations: GitHubOperationsReadOnly,
		},
	}
	cfg.Servers["github"] = gh
	requireFieldErr(t, ValidateRegistry(cfg), "servers.github.scope.github")
}

func TestValidateRegistry_FilesystemRootEnum(t *testing.T) {
	cfg := mustParseRegistry(t, validRegistryYAML)
	fs := cfg.Servers["filesystem"]
	fs.Scope = map[string]ScopeSection{
		ScopeKindFilesystem: {Root: "host_home"},
	}
	cfg.Servers["filesystem"] = fs
	requireFieldErr(t, ValidateRegistry(cfg), "servers.filesystem.scope.filesystem.root")
}

func TestValidateRegistry_GitHubReposEnum(t *testing.T) {
	cfg := mustParseRegistry(t, validRegistryYAML)
	gh := cfg.Servers["github"]
	gh.Scope = map[string]ScopeSection{
		ScopeKindGitHub: {Repos: "all_repos", Operations: GitHubOperationsReadOnly},
	}
	cfg.Servers["github"] = gh
	requireFieldErr(t, ValidateRegistry(cfg), "servers.github.scope.github.repos")
}

func TestValidateRegistry_GitHubOperationsEnum(t *testing.T) {
	cfg := mustParseRegistry(t, validRegistryYAML)
	gh := cfg.Servers["github"]
	gh.Scope = map[string]ScopeSection{
		ScopeKindGitHub: {Repos: GitHubReposCurrentRepoOnly, Operations: "delete"},
	}
	cfg.Servers["github"] = gh
	requireFieldErr(t, ValidateRegistry(cfg), "servers.github.scope.github.operations")
}

func TestRegistry_LookupUnknownServer(t *testing.T) {
	reg := mustLoadRegistry(t, validRegistryYAML)
	_, err := reg.Lookup("does-not-exist")
	if !errors.Is(err, ErrUnknownServer) {
		t.Fatalf("expected ErrUnknownServer, got %v", err)
	}
}

func TestRegistry_MatchVersion(t *testing.T) {
	reg := mustLoadRegistry(t, validRegistryYAML)

	if err := reg.MatchVersion("filesystem", "npm:@modelcontextprotocol/server-filesystem@1.2.3"); err != nil {
		t.Fatalf("MatchVersion exact: %v", err)
	}
	err := reg.MatchVersion("filesystem", "npm:@modelcontextprotocol/server-filesystem@9.9.9")
	if !errors.Is(err, ErrVersionMismatch) {
		t.Fatalf("expected ErrVersionMismatch, got %v", err)
	}
	err = reg.MatchVersion("missing", "anything")
	if !errors.Is(err, ErrUnknownServer) {
		t.Fatalf("expected ErrUnknownServer, got %v", err)
	}
}

func TestRegistry_MatchDigest(t *testing.T) {
	reg := mustLoadRegistry(t, validRegistryYAML)

	if err := reg.MatchDigest("filesystem", "sha256:abc123"); err != nil {
		t.Fatalf("MatchDigest exact: %v", err)
	}
	err := reg.MatchDigest("filesystem", "sha256:wrong")
	if !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("expected ErrDigestMismatch, got %v", err)
	}
	err = reg.MatchDigest("missing", "sha256:abc123")
	if !errors.Is(err, ErrUnknownServer) {
		t.Fatalf("expected ErrUnknownServer, got %v", err)
	}
}

func TestRegistry_MatchDigestEmptyAcceptsAnything(t *testing.T) {
	// A server with no registered digest is in version-only-pin
	// mode; MatchDigest must accept any candidate. The version
	// pin still has to be checked separately via MatchVersion.
	cfg := mustParseRegistry(t, validRegistryYAML)
	fs := cfg.Servers["filesystem"]
	fs.Digest = ""
	cfg.Servers["filesystem"] = fs
	if err := ValidateRegistry(cfg); err != nil {
		t.Fatalf("validate: %v", err)
	}
	reg := NewRegistry(cfg)
	if err := reg.MatchDigest("filesystem", "sha256:literally-anything"); err != nil {
		t.Fatalf("MatchDigest with empty registered digest: %v", err)
	}
}

func TestRegistry_NamesIsSorted(t *testing.T) {
	reg := mustLoadRegistry(t, validRegistryYAML)
	names := reg.Names()
	for i := 1; i < len(names); i++ {
		if names[i-1] > names[i] {
			t.Fatalf("Names not sorted: %v", names)
		}
	}
}

// mustParseRegistry parses (but does not validate) a fixture so
// each test can mutate one field and then assert on the
// validation error it produces.
func mustParseRegistry(t *testing.T, yamlStr string) *RegistryConfig {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.yaml")
	writeFile(t, path, yamlStr)
	var cfg RegistryConfig
	if err := readYAML(path, &cfg); err != nil {
		t.Fatalf("parse fixture mcp.yaml: %v", err)
	}
	return &cfg
}

// mustLoadRegistry parses + validates + wraps the fixture into a
// Registry. Used by lookup / matcher tests that don't care about
// the YAML layer.
func mustLoadRegistry(t *testing.T, yamlStr string) *Registry {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "mcp.yaml")
	writeFile(t, path, yamlStr)
	reg, err := LoadRegistry(path)
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	return reg
}

// requireFieldErr mirrors the helper in internal/config so the
// two packages assert on validation errors the same way.
func requireFieldErr(t *testing.T, err error, fieldHint string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error for field containing %q, got nil", fieldHint)
	}
	var fe *FieldError
	if !errors.As(err, &fe) {
		t.Fatalf("expected *FieldError, got %T: %v", err, err)
	}
	if !strings.Contains(fe.Field, fieldHint) {
		t.Fatalf("field = %q, want substring %q (full error: %v)", fe.Field, fieldHint, err)
	}
}
