package mcp

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// fsServer is a small RegistryServer factory the filesystem-scope
// tests reuse. It returns a server with the canonical workspace_only
// scope so each test only states the policy when it cares about it.
func fsServer(policy string) RegistryServer {
	if policy == "" {
		policy = ServerPolicyAllow
	}
	return RegistryServer{
		Source: "npm:@modelcontextprotocol/server-filesystem@1.2.3",
		Scope: map[string]ScopeSection{
			ScopeKindFilesystem: {Root: FilesystemRootWorkspaceOnly},
		},
		Policy: policy,
	}
}

func TestNewFilesystemScopeEnforcer_RejectsEmptyRoot(t *testing.T) {
	if _, err := NewFilesystemScopeEnforcer(""); err == nil {
		t.Fatal("expected error for empty workspace root")
	}
}

func TestNewFilesystemScopeEnforcer_AcceptsNonExistentRoot(t *testing.T) {
	// The supervisor may construct the enforcer before the workspace
	// is materialized; the constructor must not require it to exist.
	dir := filepath.Join(t.TempDir(), "not-yet-materialized")
	e, err := NewFilesystemScopeEnforcer(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The root should be absolute even when the directory doesn't
	// exist, so per-call resolution has a stable anchor.
	if !filepath.IsAbs(e.WorkspaceRoot()) {
		t.Errorf("WorkspaceRoot = %q, want absolute", e.WorkspaceRoot())
	}
}

func TestFilesystemScopeEnforcer_AllowsPathInsideWorkspace(t *testing.T) {
	ws := t.TempDir()
	e := mustFSEnforcer(t, ws)
	must := func(path string) {
		t.Helper()
		if err := e.EnforceScope(fsServer(""), ScopeKindFilesystem, ScopeRequest{
			Tool: "read_file",
			Path: path,
		}); err != nil {
			t.Errorf("path %q rejected: %v", path, err)
		}
	}
	must(ws)                            // root itself
	must(filepath.Join(ws, "a.txt"))    // direct child (does not exist yet)
	must(filepath.Join(ws, "sub", "b")) // nested non-existent child
	// Create one and re-check to exercise the existing-file path.
	if err := os.WriteFile(filepath.Join(ws, "a.txt"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	must(filepath.Join(ws, "a.txt"))
}

func TestFilesystemScopeEnforcer_RejectsPathOutsideWorkspace(t *testing.T) {
	ws := t.TempDir()
	outside := t.TempDir() // separate temp dir, not under ws
	e := mustFSEnforcer(t, ws)

	cases := []string{
		"/etc/passwd",
		outside,
		filepath.Join(outside, "secret"),
	}
	for _, p := range cases {
		err := e.EnforceScope(fsServer(""), ScopeKindFilesystem, ScopeRequest{
			Tool: "read_file",
			Path: p,
		})
		if !errors.Is(err, ErrFilesystemPathOutsideWorkspace) {
			t.Errorf("path %q: err = %v, want wraps ErrFilesystemPathOutsideWorkspace", p, err)
		}
	}
}

func TestFilesystemScopeEnforcer_RejectsParentTraversal(t *testing.T) {
	ws := t.TempDir()
	e := mustFSEnforcer(t, ws)
	// "../../etc/passwd" relative to ws resolves to a sibling of
	// the temp dir's parent, which is outside ws.
	err := e.EnforceScope(fsServer(""), ScopeKindFilesystem, ScopeRequest{
		Tool: "read_file",
		Path: "../../etc/passwd",
	})
	if !errors.Is(err, ErrFilesystemPathOutsideWorkspace) {
		t.Errorf("err = %v, want wraps ErrFilesystemPathOutsideWorkspace", err)
	}
}

func TestFilesystemScopeEnforcer_RejectsSiblingWithSamePrefix(t *testing.T) {
	// The classic "/workspace" vs "/workspace2" false-positive bug:
	// a naive HasPrefix check would allow "/workspace2/foo" when
	// the root is "/workspace". The enforcer must reject it.
	root := t.TempDir()
	ws := filepath.Join(root, "workspace")
	if err := os.MkdirAll(ws, 0o755); err != nil {
		t.Fatalf("mkdir ws: %v", err)
	}
	sibling := filepath.Join(root, "workspace-evil")
	if err := os.MkdirAll(sibling, 0o755); err != nil {
		t.Fatalf("mkdir sibling: %v", err)
	}
	e := mustFSEnforcer(t, ws)

	err := e.EnforceScope(fsServer(""), ScopeKindFilesystem, ScopeRequest{
		Tool: "read_file",
		Path: filepath.Join(sibling, "foo"),
	})
	if !errors.Is(err, ErrFilesystemPathOutsideWorkspace) {
		t.Errorf("sibling path: err = %v, want wraps ErrFilesystemPathOutsideWorkspace", err)
	}
}

func TestFilesystemScopeEnforcer_ResolvesSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics differ on windows")
	}
	ws := t.TempDir()
	outside := t.TempDir()
	// Create a symlink inside the workspace that points outside.
	linkPath := filepath.Join(ws, "escape")
	if err := os.Symlink(outside, linkPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	e := mustFSEnforcer(t, ws)

	err := e.EnforceScope(fsServer(""), ScopeKindFilesystem, ScopeRequest{
		Tool: "read_file",
		Path: filepath.Join(linkPath, "secret"),
	})
	if !errors.Is(err, ErrFilesystemPathOutsideWorkspace) {
		t.Errorf("symlink escape: err = %v, want wraps ErrFilesystemPathOutsideWorkspace", err)
	}
}

func TestFilesystemScopeEnforcer_AllowsRelativePathAnchoredInWorkspace(t *testing.T) {
	ws := t.TempDir()
	e := mustFSEnforcer(t, ws)
	err := e.EnforceScope(fsServer(""), ScopeKindFilesystem, ScopeRequest{
		Tool: "read_file",
		Path: "subdir/file.txt", // relative; resolves to ws/subdir/file.txt
	})
	if err != nil {
		t.Errorf("relative inside path rejected: %v", err)
	}
}

func TestFilesystemScopeEnforcer_RejectsEmptyPath(t *testing.T) {
	ws := t.TempDir()
	e := mustFSEnforcer(t, ws)
	err := e.EnforceScope(fsServer(""), ScopeKindFilesystem, ScopeRequest{
		Tool: "read_file",
		Path: "",
	})
	if !errors.Is(err, ErrFilesystemEmptyPath) {
		t.Errorf("err = %v, want wraps ErrFilesystemEmptyPath", err)
	}
}

func TestFilesystemScopeEnforcer_RejectsUnknownRootToken(t *testing.T) {
	ws := t.TempDir()
	e := mustFSEnforcer(t, ws)
	server := fsServer("")
	server.Scope[ScopeKindFilesystem] = ScopeSection{Root: "future_token"}
	err := e.EnforceScope(server, ScopeKindFilesystem, ScopeRequest{
		Tool: "read_file",
		Path: filepath.Join(ws, "x"),
	})
	if !errors.Is(err, ErrFilesystemScopeUnsupported) {
		t.Errorf("err = %v, want wraps ErrFilesystemScopeUnsupported", err)
	}
}

func TestFilesystemScopeEnforcer_RejectsWrongKindRegistration(t *testing.T) {
	ws := t.TempDir()
	e := mustFSEnforcer(t, ws)
	err := e.EnforceScope(fsServer(""), ScopeKindGitHub, ScopeRequest{
		Tool: "read_file",
		Path: filepath.Join(ws, "x"),
	})
	if err == nil {
		t.Fatal("expected error for wrong kind dispatch")
	}
}

func TestFilesystemScopeEnforcer_RejectsServerWithoutFilesystemSection(t *testing.T) {
	ws := t.TempDir()
	e := mustFSEnforcer(t, ws)
	server := RegistryServer{
		Source: "npm:@modelcontextprotocol/server-filesystem@1.2.3",
		Policy: ServerPolicyAllow,
		Scope:  map[string]ScopeSection{}, // no filesystem section
	}
	err := e.EnforceScope(server, ScopeKindFilesystem, ScopeRequest{
		Tool: "read_file",
		Path: filepath.Join(ws, "x"),
	})
	if err == nil {
		t.Fatal("expected error for missing filesystem section")
	}
}

func TestFilesystemScopeEnforcer_WorkspaceItselfIsAccepted(t *testing.T) {
	// A call that targets the workspace root directory (e.g.
	// list_directory on the workspace) must be allowed: the rule is
	// "inside or equal to the workspace", not "strictly inside".
	ws := t.TempDir()
	e := mustFSEnforcer(t, ws)
	if err := e.EnforceScope(fsServer(""), ScopeKindFilesystem, ScopeRequest{
		Tool: "list_directory",
		Path: ws,
	}); err != nil {
		t.Errorf("workspace root rejected: %v", err)
	}
}

func TestFilesystemScopeEnforcer_GatewayIntegration_PlugsInAsScopeEnforcer(t *testing.T) {
	// End-to-end check that the enforcer satisfies the ScopeEnforcer
	// interface and is rejected/allowed correctly via the gateway's
	// AuthorizeCall pipeline.
	ws := t.TempDir()
	e := mustFSEnforcer(t, ws)

	logger := &recordingLogger{}
	gw := newTestGateway(t, logger, map[string]ScopeEnforcer{
		ScopeKindFilesystem: e,
	})

	// Inside the workspace -> allow.
	dec, err := gw.AuthorizeCall(CallRequest{
		Server: "filesystem",
		Tool:   "read_file",
		Path:   filepath.Join(ws, "ok.txt"),
	})
	if err != nil {
		t.Fatalf("AuthorizeCall (inside): %v", err)
	}
	if dec.Outcome != GatewayOutcomeAllow {
		t.Fatalf("inside path Outcome = %v, want Allow (Err=%v)", dec.Outcome, dec.Err)
	}

	// Outside the workspace -> block, wrapped with ErrScopeViolation
	// (the gateway's wrapper) and the enforcer-specific sentinel.
	dec, err = gw.AuthorizeCall(CallRequest{
		Server: "filesystem",
		Tool:   "read_file",
		Path:   "/etc/passwd",
	})
	if err != nil {
		t.Fatalf("AuthorizeCall (outside): %v", err)
	}
	if dec.Outcome != GatewayOutcomeBlock {
		t.Fatalf("outside path Outcome = %v, want Block", dec.Outcome)
	}
	if !errors.Is(dec.Err, ErrScopeViolation) {
		t.Errorf("Err = %v, want wraps ErrScopeViolation", dec.Err)
	}
	if !errors.Is(dec.Err, ErrFilesystemPathOutsideWorkspace) {
		t.Errorf("Err = %v, want wraps ErrFilesystemPathOutsideWorkspace", dec.Err)
	}
}

func mustFSEnforcer(t *testing.T, root string) *FilesystemScopeEnforcer {
	t.Helper()
	e, err := NewFilesystemScopeEnforcer(root)
	if err != nil {
		t.Fatalf("NewFilesystemScopeEnforcer: %v", err)
	}
	return e
}
