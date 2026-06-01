// Tests for Plan Batch 3.1 (BuildRunGateway) and Plan Batch 3.3
// (Turn-ID flows). The two batches share a wire-up site so we
// exercise them in one file: BuildRunGateway is the constructor under
// test, and the turn-id flow is verified by stamping a BeginTurn on
// the supplied ControlSocket before driving the gateway and asserting
// the on-disk MCPCallRecord carries the same turn id.

package cli

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/rivan1986/ai-env/internal/mcp"
	"github.com/rivan1986/ai-env/internal/run"
)

// TestBuildRunGateway_RejectsMissingRequiredFields enforces the
// constructor's fail-loud contract: an empty RunDir, RunID, or Registry
// must produce an error rather than silently constructing a half-wired
// bundle.
func TestBuildRunGateway_RejectsMissingRequiredFields(t *testing.T) {
	registry := newTestRegistry(t)
	dir := newTestRunDir(t)

	cases := []struct {
		name string
		opts BuildRunGatewayOptions
	}{
		{
			name: "missing RunDir",
			opts: BuildRunGatewayOptions{RunID: "id", Registry: registry},
		},
		{
			name: "missing RunID",
			opts: BuildRunGatewayOptions{RunDir: dir, Registry: registry},
		},
		{
			name: "missing Registry",
			opts: BuildRunGatewayOptions{RunDir: dir, RunID: "id"},
		},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			if _, err := BuildRunGateway(c.opts); err == nil {
				t.Fatalf("BuildRunGateway: expected error, got nil")
			}
		})
	}
}

// TestBuildRunGateway_HappyPath_WiresGatewayAndWriter exercises the
// canonical assembly: a valid registry, a workspace root, and a current
// repo. The returned bundle must expose a usable gateway whose verdict
// lands as a single MCPCallRecord on disk via the bridged writer.
func TestBuildRunGateway_HappyPath_WiresGatewayAndWriter(t *testing.T) {
	registry := newTestRegistry(t)
	dir := newTestRunDir(t)
	workspace := t.TempDir()

	bundle, err := BuildRunGateway(BuildRunGatewayOptions{
		RunDir:        dir,
		RunID:         "20260601-120000-aaaaaa",
		Registry:      registry,
		WorkspaceRoot: workspace,
		CurrentRepo:   "rivan1986/ai-env",
	})
	if err != nil {
		t.Fatalf("BuildRunGateway: %v", err)
	}
	t.Cleanup(func() { _ = bundle.Close() })

	if bundle.Gateway == nil {
		t.Fatalf("bundle.Gateway is nil")
	}
	if bundle.Writer == nil {
		t.Fatalf("bundle.Writer is nil")
	}
	if bundle.Logger == nil {
		t.Fatalf("bundle.Logger is nil")
	}
	if bundle.FilesystemEnforcer == nil {
		t.Fatalf("FilesystemEnforcer is nil (WorkspaceRoot was non-empty)")
	}
	if bundle.GitHubEnforcer == nil {
		t.Fatalf("GitHubEnforcer is nil (CurrentRepo was non-empty)")
	}

	// Drive a launch decision through the gateway; the bridge should
	// land a single record on disk through the bundle's writer.
	dec, err := bundle.Gateway.AuthorizeLaunch(mcp.LaunchRequest{Server: "filesystem"})
	if err != nil {
		t.Fatalf("AuthorizeLaunch: %v", err)
	}
	if dec.Outcome != mcp.GatewayOutcomeAllow {
		t.Fatalf("AuthorizeLaunch outcome = %v, want Allow", dec.Outcome)
	}

	if err := bundle.Close(); err != nil {
		t.Fatalf("bundle.Close: %v", err)
	}
	records, err := run.ReadMCPCalls(dir)
	if err != nil {
		t.Fatalf("ReadMCPCalls: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].Decision != run.MCPCallDecisionAllow {
		t.Errorf("Decision = %q, want %q", records[0].Decision, run.MCPCallDecisionAllow)
	}
	if records[0].TurnID != "" {
		t.Errorf("TurnID = %q, want empty (no ControlSocket wired)", records[0].TurnID)
	}
}

// TestBuildRunGateway_TurnIDStamped_WithControlSocket covers Plan Batch
// 3.3: a BeginTurn against the supplied ControlSocket must surface as
// the TurnID on every subsequent MCPCallRecord written through the
// gateway bridge.
func TestBuildRunGateway_TurnIDStamped_WithControlSocket(t *testing.T) {
	registry := newTestRegistry(t)
	dir := newTestRunDir(t)

	// Stand up a control socket so the bridge can read the current
	// turn id at log time. The Plan Batch 3.3 path uses the
	// in-process CurrentTurnID accessor, not the RPC, so we do not
	// need to Start the socket — we seed a turn id via
	// AllocateTurnID and the bridge reads it back via CurrentTurnID.
	sock, err := run.NewControlSocket(run.ControlSocketOptions{
		RunDir:       dir,
		PrimaryToken: "test-primary-token",
	})
	if err != nil {
		t.Fatalf("NewControlSocket: %v", err)
	}

	turnID := sock.AllocateTurnID("agent")
	if turnID == "" {
		t.Fatalf("AllocateTurnID produced empty turn id")
	}

	// Build the gateway with the control socket so the bridge stamps
	// the active turn id.
	bundle, err := BuildRunGateway(BuildRunGatewayOptions{
		RunDir:        dir,
		RunID:         "20260601-120100-aaaaaa",
		Registry:      registry,
		ControlSocket: sock,
	})
	if err != nil {
		t.Fatalf("BuildRunGateway: %v", err)
	}
	t.Cleanup(func() { _ = bundle.Close() })

	if _, err := bundle.Gateway.AuthorizeLaunch(mcp.LaunchRequest{Server: "filesystem"}); err != nil {
		t.Fatalf("AuthorizeLaunch: %v", err)
	}

	if err := bundle.Close(); err != nil {
		t.Fatalf("bundle.Close: %v", err)
	}

	records, err := run.ReadMCPCalls(dir)
	if err != nil {
		t.Fatalf("ReadMCPCalls: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].TurnID != turnID {
		t.Errorf("records[0].TurnID = %q, want %q", records[0].TurnID, turnID)
	}
}

// TestBuildRunGateway_CustomTurnRole verifies the bridge consults the
// configured TurnRole (not the default) when looking up the current
// turn id. We allocate a "subagent" turn through the RPC and check the
// bridge picks it up under that role rather than the default "agent"
// counter (which has no entry).
func TestBuildRunGateway_CustomTurnRole(t *testing.T) {
	registry := newTestRegistry(t)
	dir := newTestRunDir(t)

	sock, err := run.NewControlSocket(run.ControlSocketOptions{
		RunDir:       dir,
		PrimaryToken: "tok",
	})
	if err != nil {
		t.Fatalf("NewControlSocket: %v", err)
	}

	turnID := sock.AllocateTurnID("subagent")
	if turnID == "" {
		t.Fatalf("AllocateTurnID produced empty subagent turn id")
	}

	bundle, err := BuildRunGateway(BuildRunGatewayOptions{
		RunDir:        dir,
		RunID:         "20260601-120200-aaaaaa",
		Registry:      registry,
		ControlSocket: sock,
		TurnRole:      "subagent",
	})
	if err != nil {
		t.Fatalf("BuildRunGateway: %v", err)
	}
	t.Cleanup(func() { _ = bundle.Close() })

	if _, err := bundle.Gateway.AuthorizeLaunch(mcp.LaunchRequest{Server: "filesystem"}); err != nil {
		t.Fatalf("AuthorizeLaunch: %v", err)
	}
	if err := bundle.Close(); err != nil {
		t.Fatalf("bundle.Close: %v", err)
	}

	records, err := run.ReadMCPCalls(dir)
	if err != nil {
		t.Fatalf("ReadMCPCalls: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].TurnID != turnID {
		t.Errorf("TurnID = %q, want %q (custom role)", records[0].TurnID, turnID)
	}
}

// TestBuildRunGateway_ScopeEnforcersBlockOutOfScope ensures the
// constructor wired the FilesystemScopeEnforcer correctly: a server
// declaring a filesystem scope on a path outside WorkspaceRoot must
// be blocked.
func TestBuildRunGateway_ScopeEnforcersBlockOutOfScope(t *testing.T) {
	dir := newTestRunDir(t)
	workspace := t.TempDir()

	regCfg := mcp.RegistryConfig{
		Version: 1,
		Default: mcp.DefaultPolicyDeny,
		Servers: map[string]mcp.RegistryServer{
			"filesystem": {
				Source: "npm:@modelcontextprotocol/server-filesystem@1.2.3",
				Policy: mcp.ServerPolicyAllow,
				Scope: map[string]mcp.ScopeSection{
					mcp.ScopeKindFilesystem: {Root: mcp.FilesystemRootWorkspaceOnly},
				},
			},
		},
	}
	if err := mcp.ValidateRegistry(&regCfg); err != nil {
		t.Fatalf("ValidateRegistry: %v", err)
	}
	registry := mcp.NewRegistry(&regCfg)

	bundle, err := BuildRunGateway(BuildRunGatewayOptions{
		RunDir:        dir,
		RunID:         "20260601-120300-aaaaaa",
		Registry:      registry,
		WorkspaceRoot: workspace,
	})
	if err != nil {
		t.Fatalf("BuildRunGateway: %v", err)
	}
	t.Cleanup(func() { _ = bundle.Close() })

	dec, err := bundle.Gateway.AuthorizeCall(mcp.CallRequest{
		Server: "filesystem",
		Tool:   "read_file",
		Path:   "/etc/passwd",
	})
	if err != nil {
		t.Fatalf("AuthorizeCall: %v", err)
	}
	if dec.Outcome != mcp.GatewayOutcomeBlock {
		t.Fatalf("AuthorizeCall outcome = %v, want Block (path outside workspace)", dec.Outcome)
	}
}

// TestBuildRunGateway_DenyUnknownScope_NoEnforcer covers the
// "deny unknown scope" rule: a server declares a github scope but the
// caller omitted CurrentRepo so no enforcer is wired. The gateway must
// block any call against that server with the
// ErrMissingScopeEnforcer sentinel.
func TestBuildRunGateway_DenyUnknownScope_NoEnforcer(t *testing.T) {
	dir := newTestRunDir(t)

	regCfg := mcp.RegistryConfig{
		Version: 1,
		Default: mcp.DefaultPolicyDeny,
		Servers: map[string]mcp.RegistryServer{
			"github": {
				Source: "npm:@modelcontextprotocol/server-github@1.0.0",
				Policy: mcp.ServerPolicyAllow,
				Scope: map[string]mcp.ScopeSection{
					mcp.ScopeKindGitHub: {
						Repos:      mcp.GitHubReposCurrentRepoOnly,
						Operations: mcp.GitHubOperationsReadOnly,
					},
				},
			},
		},
	}
	if err := mcp.ValidateRegistry(&regCfg); err != nil {
		t.Fatalf("ValidateRegistry: %v", err)
	}
	registry := mcp.NewRegistry(&regCfg)

	bundle, err := BuildRunGateway(BuildRunGatewayOptions{
		RunDir:   dir,
		RunID:    "20260601-120400-aaaaaa",
		Registry: registry,
		// CurrentRepo deliberately omitted.
	})
	if err != nil {
		t.Fatalf("BuildRunGateway: %v", err)
	}
	t.Cleanup(func() { _ = bundle.Close() })

	dec, _ := bundle.Gateway.AuthorizeCall(mcp.CallRequest{
		Server: "github",
		Tool:   "list_issues",
		Repo:   "rivan1986/ai-env",
	})
	if dec.Outcome != mcp.GatewayOutcomeBlock {
		t.Fatalf("AuthorizeCall outcome = %v, want Block (no enforcer wired)", dec.Outcome)
	}
}

// TestNewMCPCallLoggerWithOptions_DefaultRole verifies the bridge falls
// back to DefaultTurnRole when MCPCallLoggerOptions.TurnRole is empty.
// The bridge's recorded role is unexported, so we exercise the
// behavior end-to-end: stamp a turn under the default role, then drive
// a record through the bridge and assert TurnID matches.
func TestNewMCPCallLoggerWithOptions_DefaultRole(t *testing.T) {
	dir := newTestRunDir(t)
	registry := newTestRegistry(t)

	sock, err := run.NewControlSocket(run.ControlSocketOptions{
		RunDir:       dir,
		PrimaryToken: "tok",
	})
	if err != nil {
		t.Fatalf("NewControlSocket: %v", err)
	}

	turnID := sock.AllocateTurnID("agent")

	bundle, err := BuildRunGateway(BuildRunGatewayOptions{
		RunDir:        dir,
		RunID:         "20260601-120500-aaaaaa",
		Registry:      registry,
		ControlSocket: sock,
		// TurnRole empty -> falls back to DefaultTurnRole ("agent").
	})
	if err != nil {
		t.Fatalf("BuildRunGateway: %v", err)
	}
	t.Cleanup(func() { _ = bundle.Close() })

	if _, err := bundle.Gateway.AuthorizeLaunch(mcp.LaunchRequest{Server: "filesystem"}); err != nil {
		t.Fatalf("AuthorizeLaunch: %v", err)
	}
	if err := bundle.Close(); err != nil {
		t.Fatalf("bundle.Close: %v", err)
	}
	records, err := run.ReadMCPCalls(dir)
	if err != nil {
		t.Fatalf("ReadMCPCalls: %v", err)
	}
	if len(records) != 1 || records[0].TurnID != turnID {
		t.Fatalf("records[0].TurnID = %q, want %q", records[0].TurnID, turnID)
	}
}

// --- helpers ----------------------------------------------------------------

// newTestRegistry builds a minimal valid Registry with a single
// "filesystem" server whose Policy is "allow" and no declared scope.
// Used by the tests that do not care about scope enforcement.
func newTestRegistry(t *testing.T) *mcp.Registry {
	t.Helper()
	regCfg := mcp.RegistryConfig{
		Version: 1,
		Default: mcp.DefaultPolicyDeny,
		Servers: map[string]mcp.RegistryServer{
			"filesystem": {
				Source: "npm:@modelcontextprotocol/server-filesystem@1.2.3",
				Policy: mcp.ServerPolicyAllow,
			},
		},
	}
	if err := mcp.ValidateRegistry(&regCfg); err != nil {
		t.Fatalf("ValidateRegistry: %v", err)
	}
	return mcp.NewRegistry(&regCfg)
}

// newTestRunDir materializes a run directory via the production
// helper and returns the absolute path. Used to keep the test bodies
// from repeating the same six lines.
func newTestRunDir(t *testing.T) string {
	t.Helper()
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	runID := "20260601-000000-aaaaaa"
	dir, err := run.CreateRunDirectory(aiEnvDir, runID, time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}
	return dir.Path
}
