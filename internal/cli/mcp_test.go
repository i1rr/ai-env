package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rivan1986/ai-env/internal/mcp"
)

// scaffoldProjectForMCP creates a fresh project scaffold via RunNew so
// findAIEnvDir succeeds when the mcp commands look for .ai-env/. Each
// test calls this independently so the fixtures stay isolated.
func scaffoldProjectForMCP(t *testing.T) string {
	t.Helper()
	cwd := t.TempDir()
	if err := RunNew(NewOptions{EnvName: "demo", Cwd: cwd, Stdout: &bytes.Buffer{}}); err != nil {
		t.Fatalf("RunNew: %v", err)
	}
	return cwd
}

// addSampleServer is a shared fixture: a filesystem MCP server with a
// workspace-only scope. The tests build on top of this so they don't
// repeat the add-flag boilerplate.
func addSampleServer(t *testing.T, cwd string, name string) {
	t.Helper()
	if err := RunMCPAdd(MCPAddOptions{
		Name:                name,
		Source:              "npm:@modelcontextprotocol/server-filesystem@1.2.3",
		Digest:              "sha256:abc123",
		Policy:              mcp.ServerPolicyAllow,
		ScopeFilesystemRoot: mcp.FilesystemRootWorkspaceOnly,
		Cwd:                 cwd,
		Stdout:              &bytes.Buffer{},
		Stderr:              &bytes.Buffer{},
	}); err != nil {
		t.Fatalf("RunMCPAdd(%s): %v", name, err)
	}
}

func TestRunMCPAdd_CreatesRegistryWhenMissing(t *testing.T) {
	cwd := scaffoldProjectForMCP(t)
	registryPath := filepath.Join(cwd, ".ai-env", mcpFileName)
	if _, err := os.Stat(registryPath); !os.IsNotExist(err) {
		t.Fatalf("expected mcp.yaml missing before add, stat err = %v", err)
	}

	var stdout, stderr bytes.Buffer
	if err := RunMCPAdd(MCPAddOptions{
		Name:                "filesystem",
		Source:              "npm:@modelcontextprotocol/server-filesystem@1.2.3",
		Digest:              "sha256:abc123",
		Policy:              mcp.ServerPolicyAllow,
		ScopeFilesystemRoot: mcp.FilesystemRootWorkspaceOnly,
		Cwd:                 cwd,
		Stdout:              &stdout,
		Stderr:              &stderr,
	}); err != nil {
		t.Fatalf("RunMCPAdd: %v", err)
	}

	if _, err := os.Stat(registryPath); err != nil {
		t.Fatalf("mcp.yaml not written: %v", err)
	}
	if !strings.Contains(stderr.String(), "created") {
		t.Errorf("expected 'created' notice on stderr, got %q", stderr.String())
	}
	if !strings.Contains(stdout.String(), "filesystem") {
		t.Errorf("expected server name in stdout, got %q", stdout.String())
	}

	reg, err := mcp.LoadRegistry(registryPath)
	if err != nil {
		t.Fatalf("LoadRegistry after add: %v", err)
	}
	if got, want := reg.DefaultPolicy(), mcp.DefaultPolicyDeny; got != want {
		t.Errorf("default policy = %q, want %q", got, want)
	}
	s, err := reg.Lookup("filesystem")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if s.Source != "npm:@modelcontextprotocol/server-filesystem@1.2.3" {
		t.Errorf("source = %q", s.Source)
	}
	if s.Digest != "sha256:abc123" {
		t.Errorf("digest = %q", s.Digest)
	}
	if s.Scope[mcp.ScopeKindFilesystem].Root != mcp.FilesystemRootWorkspaceOnly {
		t.Errorf("scope root = %q", s.Scope[mcp.ScopeKindFilesystem].Root)
	}
	if s.Policy != mcp.ServerPolicyAllow {
		t.Errorf("policy = %q", s.Policy)
	}
}

func TestRunMCPAdd_RefusesDuplicateWithoutForce(t *testing.T) {
	cwd := scaffoldProjectForMCP(t)
	addSampleServer(t, cwd, "filesystem")

	err := RunMCPAdd(MCPAddOptions{
		Name:                "filesystem",
		Source:              "npm:@modelcontextprotocol/server-filesystem@1.2.4",
		Policy:              mcp.ServerPolicyAllow,
		ScopeFilesystemRoot: mcp.FilesystemRootWorkspaceOnly,
		Cwd:                 cwd,
		Stdout:              &bytes.Buffer{},
		Stderr:              &bytes.Buffer{},
	})
	if err == nil {
		t.Fatal("expected duplicate error, got nil")
	}
	if !strings.Contains(err.Error(), "--force") {
		t.Errorf("error %q does not mention --force", err.Error())
	}
}

func TestRunMCPAdd_ForceReplaces(t *testing.T) {
	cwd := scaffoldProjectForMCP(t)
	addSampleServer(t, cwd, "filesystem")

	var stderr bytes.Buffer
	if err := RunMCPAdd(MCPAddOptions{
		Name:                "filesystem",
		Source:              "npm:@modelcontextprotocol/server-filesystem@2.0.0",
		Policy:              mcp.ServerPolicyWarn,
		ScopeFilesystemRoot: mcp.FilesystemRootWorkspaceOnly,
		Force:               true,
		Cwd:                 cwd,
		Stdout:              &bytes.Buffer{},
		Stderr:              &stderr,
	}); err != nil {
		t.Fatalf("RunMCPAdd(--force): %v", err)
	}
	if !strings.Contains(stderr.String(), "replacing") {
		t.Errorf("expected replacing notice, got %q", stderr.String())
	}

	registryPath := filepath.Join(cwd, ".ai-env", mcpFileName)
	reg, err := mcp.LoadRegistry(registryPath)
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	s, err := reg.Lookup("filesystem")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if s.Source != "npm:@modelcontextprotocol/server-filesystem@2.0.0" {
		t.Errorf("source not replaced: %q", s.Source)
	}
	if s.Policy != mcp.ServerPolicyWarn {
		t.Errorf("policy not replaced: %q", s.Policy)
	}
}

func TestRunMCPAdd_RequiresSource(t *testing.T) {
	cwd := scaffoldProjectForMCP(t)
	err := RunMCPAdd(MCPAddOptions{
		Name:   "filesystem",
		Cwd:    cwd,
		Stdout: &bytes.Buffer{},
		Stderr: &bytes.Buffer{},
	})
	if err == nil {
		t.Fatal("expected error for missing --source, got nil")
	}
	if !strings.Contains(err.Error(), "--source") {
		t.Errorf("error %q does not mention --source", err.Error())
	}
}

func TestRunMCPAdd_RequiresName(t *testing.T) {
	cwd := scaffoldProjectForMCP(t)
	err := RunMCPAdd(MCPAddOptions{
		Name:   "",
		Source: "npm:@modelcontextprotocol/server-filesystem@1.2.3",
		Cwd:    cwd,
		Stdout: &bytes.Buffer{},
		Stderr: &bytes.Buffer{},
	})
	if err == nil {
		t.Fatal("expected error for empty name, got nil")
	}
}

func TestRunMCPAdd_RejectsInvalidSource(t *testing.T) {
	cwd := scaffoldProjectForMCP(t)
	err := RunMCPAdd(MCPAddOptions{
		Name:                "filesystem",
		Source:              "git:https://example/repo@1.0.0", // unknown kind
		Policy:              mcp.ServerPolicyAllow,
		ScopeFilesystemRoot: mcp.FilesystemRootWorkspaceOnly,
		Cwd:                 cwd,
		Stdout:              &bytes.Buffer{},
		Stderr:              &bytes.Buffer{},
	})
	if err == nil {
		t.Fatal("expected validation error for git source, got nil")
	}
	if !strings.Contains(err.Error(), "source") {
		t.Errorf("error %q does not mention source field: %v", err.Error(), err)
	}
}

func TestRunMCPAdd_GitHubScope(t *testing.T) {
	cwd := scaffoldProjectForMCP(t)
	if err := RunMCPAdd(MCPAddOptions{
		Name:             "github",
		Source:           "oci:ghcr.io/example/server-github:1.1.0",
		Policy:           mcp.ServerPolicyAllow,
		ScopeGitHubRepos: mcp.GitHubReposCurrentRepoOnly,
		// Operations intentionally omitted to exercise the
		// read_only default behavior.
		Cwd:    cwd,
		Stdout: &bytes.Buffer{},
		Stderr: &bytes.Buffer{},
	}); err != nil {
		t.Fatalf("RunMCPAdd: %v", err)
	}
	reg, err := mcp.LoadRegistry(filepath.Join(cwd, ".ai-env", mcpFileName))
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	s, err := reg.Lookup("github")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	ghScope := s.Scope[mcp.ScopeKindGitHub]
	if ghScope.Repos != mcp.GitHubReposCurrentRepoOnly {
		t.Errorf("repos = %q", ghScope.Repos)
	}
	if ghScope.Operations != mcp.GitHubOperationsReadOnly {
		t.Errorf("operations default = %q, want %q", ghScope.Operations, mcp.GitHubOperationsReadOnly)
	}
}

func TestRunMCPAdd_NoAIEnvDir(t *testing.T) {
	cwd := t.TempDir()
	err := RunMCPAdd(MCPAddOptions{
		Name:                "filesystem",
		Source:              "npm:@modelcontextprotocol/server-filesystem@1.2.3",
		Policy:              mcp.ServerPolicyAllow,
		ScopeFilesystemRoot: mcp.FilesystemRootWorkspaceOnly,
		Cwd:                 cwd,
		Stdout:              &bytes.Buffer{},
		Stderr:              &bytes.Buffer{},
	})
	if err == nil {
		t.Fatal("expected error for missing .ai-env, got nil")
	}
	if !strings.Contains(err.Error(), ".ai-env") {
		t.Errorf("error %q does not mention .ai-env", err.Error())
	}
}

func TestRunMCPList_RendersTable(t *testing.T) {
	cwd := scaffoldProjectForMCP(t)
	addSampleServer(t, cwd, "filesystem")
	if err := RunMCPAdd(MCPAddOptions{
		Name:             "github",
		Source:           "oci:ghcr.io/example/server-github:1.1.0",
		Policy:           mcp.ServerPolicyWarn,
		ScopeGitHubRepos: mcp.GitHubReposCurrentRepoOnly,
		Cwd:              cwd,
		Stdout:           &bytes.Buffer{},
		Stderr:           &bytes.Buffer{},
	}); err != nil {
		t.Fatalf("seed github: %v", err)
	}

	var stdout, stderr bytes.Buffer
	if err := RunMCPList(MCPListOptions{Cwd: cwd, Stdout: &stdout, Stderr: &stderr}); err != nil {
		t.Fatalf("RunMCPList: %v", err)
	}
	out := stdout.String()
	for _, want := range []string{
		"registry:",
		"default:",
		"deny",
		"NAME",
		"SOURCE",
		"DIGEST",
		"SCHEMA HASH",
		"SCOPE",
		"POLICY",
		"filesystem",
		"github",
		"npm:@modelcontextprotocol/server-filesystem@1.2.3",
		"oci:ghcr.io/example/server-github:1.1.0",
		"warn",
		"allow",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in list output:\n%s", want, out)
		}
	}
}

func TestRunMCPList_MissingFile(t *testing.T) {
	cwd := scaffoldProjectForMCP(t)
	err := RunMCPList(MCPListOptions{Cwd: cwd, Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
	if err == nil {
		t.Fatal("expected error when mcp.yaml missing, got nil")
	}
	if !strings.Contains(err.Error(), "mcp add") {
		t.Errorf("error %q does not point at `ai-env mcp add`", err.Error())
	}
}

func TestRunMCPPin_RecordsHash(t *testing.T) {
	cwd := scaffoldProjectForMCP(t)
	addSampleServer(t, cwd, "filesystem")

	hash := "sha256:def456"
	var stdout, stderr bytes.Buffer
	if err := RunMCPPin(MCPPinOptions{
		Name:       "filesystem",
		SchemaHash: hash,
		Cwd:        cwd,
		Stdout:     &stdout,
		Stderr:     &stderr,
	}); err != nil {
		t.Fatalf("RunMCPPin: %v", err)
	}
	if !strings.Contains(stdout.String(), hash) {
		t.Errorf("stdout %q does not include pinned hash", stdout.String())
	}

	reg, err := mcp.LoadRegistry(filepath.Join(cwd, ".ai-env", mcpFileName))
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	s, _ := reg.Lookup("filesystem")
	if s.SchemaHash != hash {
		t.Errorf("schema hash = %q, want %q", s.SchemaHash, hash)
	}
}

func TestRunMCPPin_ReplaceSurfacesPrevious(t *testing.T) {
	cwd := scaffoldProjectForMCP(t)
	addSampleServer(t, cwd, "filesystem")

	if err := RunMCPPin(MCPPinOptions{
		Name:       "filesystem",
		SchemaHash: "sha256:def456",
		Cwd:        cwd,
		Stdout:     &bytes.Buffer{},
		Stderr:     &bytes.Buffer{},
	}); err != nil {
		t.Fatalf("first pin: %v", err)
	}
	var stderr bytes.Buffer
	if err := RunMCPPin(MCPPinOptions{
		Name:       "filesystem",
		SchemaHash: "sha256:newhash",
		Cwd:        cwd,
		Stdout:     &bytes.Buffer{},
		Stderr:     &stderr,
	}); err != nil {
		t.Fatalf("replace pin: %v", err)
	}
	if !strings.Contains(stderr.String(), "sha256:def456") {
		t.Errorf("expected previous hash in stderr, got %q", stderr.String())
	}
}

func TestRunMCPPin_NoOpWhenIdentical(t *testing.T) {
	cwd := scaffoldProjectForMCP(t)
	addSampleServer(t, cwd, "filesystem")

	hash := "sha256:def456"
	if err := RunMCPPin(MCPPinOptions{Name: "filesystem", SchemaHash: hash, Cwd: cwd, Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}); err != nil {
		t.Fatalf("first pin: %v", err)
	}
	var stderr bytes.Buffer
	if err := RunMCPPin(MCPPinOptions{Name: "filesystem", SchemaHash: hash, Cwd: cwd, Stdout: &bytes.Buffer{}, Stderr: &stderr}); err != nil {
		t.Fatalf("idempotent pin: %v", err)
	}
	if !strings.Contains(stderr.String(), "already") {
		t.Errorf("expected 'already' notice in stderr, got %q", stderr.String())
	}
}

func TestRunMCPPin_UnknownServer(t *testing.T) {
	cwd := scaffoldProjectForMCP(t)
	addSampleServer(t, cwd, "filesystem")
	err := RunMCPPin(MCPPinOptions{Name: "missing", SchemaHash: "sha256:abc", Cwd: cwd, Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
	if err == nil {
		t.Fatal("expected error for unknown server, got nil")
	}
	if !strings.Contains(err.Error(), "not registered") {
		t.Errorf("error %q does not mention 'not registered'", err.Error())
	}
}

func TestRunMCPPin_RejectsBadHash(t *testing.T) {
	cwd := scaffoldProjectForMCP(t)
	addSampleServer(t, cwd, "filesystem")
	err := RunMCPPin(MCPPinOptions{Name: "filesystem", SchemaHash: "not-a-hash", Cwd: cwd, Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
	if err == nil {
		t.Fatal("expected validation error for bad hash, got nil")
	}
	if !strings.Contains(err.Error(), "sha256") {
		t.Errorf("error %q does not mention sha256: %v", err.Error(), err)
	}
}

func TestRunMCPScan_AllowsWhenAllChecksPass(t *testing.T) {
	cwd := scaffoldProjectForMCP(t)
	addSampleServer(t, cwd, "filesystem")

	var stdout, stderr bytes.Buffer
	err := RunMCPScan(MCPScanOptions{
		Name:   "filesystem",
		Source: "npm:@modelcontextprotocol/server-filesystem@1.2.3",
		Digest: "sha256:abc123",
		Cwd:    cwd,
		Stdout: &stdout,
		Stderr: &stderr,
	})
	if err != nil {
		t.Fatalf("RunMCPScan: %v", err)
	}
	out := stdout.String()
	for _, want := range []string{"server:", "filesystem", "decision:", "allow"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in scan output:\n%s", want, out)
		}
	}
}

func TestRunMCPScan_BlocksOnSourceMismatch(t *testing.T) {
	cwd := scaffoldProjectForMCP(t)
	addSampleServer(t, cwd, "filesystem")

	var stdout, stderr bytes.Buffer
	err := RunMCPScan(MCPScanOptions{
		Name:   "filesystem",
		Source: "npm:@modelcontextprotocol/server-filesystem@9.9.9",
		Cwd:    cwd,
		Stdout: &stdout,
		Stderr: &stderr,
	})
	if err == nil {
		t.Fatal("expected error for source mismatch, got nil")
	}
	if !strings.Contains(stdout.String(), "block") {
		t.Errorf("stdout %q does not include block decision", stdout.String())
	}
}

func TestRunMCPScan_BlocksOnSchemaMismatch(t *testing.T) {
	cwd := scaffoldProjectForMCP(t)
	addSampleServer(t, cwd, "filesystem")
	if err := RunMCPPin(MCPPinOptions{Name: "filesystem", SchemaHash: "sha256:expected", Cwd: cwd, Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}); err != nil {
		t.Fatalf("pin: %v", err)
	}

	err := RunMCPScan(MCPScanOptions{
		Name:       "filesystem",
		SchemaHash: "sha256:drifted",
		Cwd:        cwd,
		Stdout:     &bytes.Buffer{},
		Stderr:     &bytes.Buffer{},
	})
	if err == nil {
		t.Fatal("expected error for schema mismatch, got nil")
	}
	if !strings.Contains(err.Error(), "schema") && !strings.Contains(err.Error(), "mismatch") {
		t.Errorf("error %q does not mention schema mismatch", err.Error())
	}
}

func TestRunMCPScan_WarnsWithoutFailing(t *testing.T) {
	cwd := scaffoldProjectForMCP(t)
	// Register with policy=warn so a launch produces a warn verdict.
	if err := RunMCPAdd(MCPAddOptions{
		Name:                "filesystem",
		Source:              "npm:@modelcontextprotocol/server-filesystem@1.2.3",
		Policy:              mcp.ServerPolicyWarn,
		ScopeFilesystemRoot: mcp.FilesystemRootWorkspaceOnly,
		Cwd:                 cwd,
		Stdout:              &bytes.Buffer{},
		Stderr:              &bytes.Buffer{},
	}); err != nil {
		t.Fatalf("RunMCPAdd: %v", err)
	}

	var stdout, stderr bytes.Buffer
	if err := RunMCPScan(MCPScanOptions{Name: "filesystem", Cwd: cwd, Stdout: &stdout, Stderr: &stderr}); err != nil {
		t.Fatalf("RunMCPScan: %v", err)
	}
	if !strings.Contains(stdout.String(), "warn") {
		t.Errorf("stdout %q does not include warn decision", stdout.String())
	}
	if !strings.Contains(stderr.String(), "warning:") {
		t.Errorf("stderr %q does not include warning prefix", stderr.String())
	}
}

func TestRunMCPScan_UnknownServer(t *testing.T) {
	cwd := scaffoldProjectForMCP(t)
	addSampleServer(t, cwd, "filesystem")

	err := RunMCPScan(MCPScanOptions{Name: "missing", Cwd: cwd, Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
	if err == nil {
		t.Fatal("expected unknown-server error, got nil")
	}
	if !errors.Is(err, mcp.ErrUnknownServer) {
		t.Errorf("error %v is not ErrUnknownServer", err)
	}
}

func TestRunMCPScan_MissingFile(t *testing.T) {
	cwd := scaffoldProjectForMCP(t)
	err := RunMCPScan(MCPScanOptions{Name: "filesystem", Cwd: cwd, Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
	if err == nil {
		t.Fatal("expected error when mcp.yaml missing, got nil")
	}
	if !strings.Contains(err.Error(), "mcp add") {
		t.Errorf("error %q does not point at `ai-env mcp add`", err.Error())
	}
}

func TestRunMCPRemove_DeletesEntry(t *testing.T) {
	cwd := scaffoldProjectForMCP(t)
	addSampleServer(t, cwd, "filesystem")
	if err := RunMCPAdd(MCPAddOptions{
		Name:             "github",
		Source:           "oci:ghcr.io/example/server-github:1.1.0",
		Policy:           mcp.ServerPolicyAllow,
		ScopeGitHubRepos: mcp.GitHubReposCurrentRepoOnly,
		Cwd:              cwd,
		Stdout:           &bytes.Buffer{},
		Stderr:           &bytes.Buffer{},
	}); err != nil {
		t.Fatalf("seed github: %v", err)
	}

	var stdout bytes.Buffer
	if err := RunMCPRemove(MCPRemoveOptions{Name: "github", Cwd: cwd, Stdout: &stdout, Stderr: &bytes.Buffer{}}); err != nil {
		t.Fatalf("RunMCPRemove: %v", err)
	}
	if !strings.Contains(stdout.String(), "Removed") {
		t.Errorf("stdout %q does not confirm removal", stdout.String())
	}

	reg, err := mcp.LoadRegistry(filepath.Join(cwd, ".ai-env", mcpFileName))
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	if _, err := reg.Lookup("github"); !errors.Is(err, mcp.ErrUnknownServer) {
		t.Errorf("server still present after remove: %v", err)
	}
	if _, err := reg.Lookup("filesystem"); err != nil {
		t.Errorf("unrelated server lost during remove: %v", err)
	}
}

func TestRunMCPRemove_UnknownServer(t *testing.T) {
	cwd := scaffoldProjectForMCP(t)
	addSampleServer(t, cwd, "filesystem")
	err := RunMCPRemove(MCPRemoveOptions{Name: "missing", Cwd: cwd, Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
	if err == nil {
		t.Fatal("expected unknown-server error, got nil")
	}
	if !strings.Contains(err.Error(), "not registered") {
		t.Errorf("error %q does not mention 'not registered'", err.Error())
	}
}

func TestRunMCPRemove_RefusesLastServer(t *testing.T) {
	cwd := scaffoldProjectForMCP(t)
	addSampleServer(t, cwd, "filesystem")

	err := RunMCPRemove(MCPRemoveOptions{Name: "filesystem", Cwd: cwd, Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
	if err == nil {
		t.Fatal("expected refusal for last server, got nil")
	}
	if !strings.Contains(err.Error(), "last") {
		t.Errorf("error %q does not mention 'last'", err.Error())
	}

	// Registry still readable.
	if _, err := mcp.LoadRegistry(filepath.Join(cwd, ".ai-env", mcpFileName)); err != nil {
		t.Errorf("registry corrupted after refusal: %v", err)
	}
}

func TestRunMCPRemove_MissingFile(t *testing.T) {
	cwd := scaffoldProjectForMCP(t)
	err := RunMCPRemove(MCPRemoveOptions{Name: "filesystem", Cwd: cwd, Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}})
	if err == nil {
		t.Fatal("expected error when mcp.yaml missing, got nil")
	}
	if !strings.Contains(err.Error(), "mcp add") {
		t.Errorf("error %q does not point at `ai-env mcp add`", err.Error())
	}
}

func TestRunMCPAdd_GitHubOperationsRequiresRepos(t *testing.T) {
	cwd := scaffoldProjectForMCP(t)
	err := RunMCPAdd(MCPAddOptions{
		Name:                  "github",
		Source:                "oci:ghcr.io/example/server-github:1.1.0",
		Policy:                mcp.ServerPolicyAllow,
		ScopeGitHubOperations: mcp.GitHubOperationsReadOnly,
		Cwd:                   cwd,
		Stdout:                &bytes.Buffer{},
		Stderr:                &bytes.Buffer{},
	})
	if err == nil {
		t.Fatal("expected error when operations is set without repos, got nil")
	}
	if !strings.Contains(err.Error(), "scope-github-repos") {
		t.Errorf("error %q does not mention --scope-github-repos", err.Error())
	}
}
