//go:build acceptance

// Package acceptance MCP gateway acceptance tests (plan 09, step 9).
//
// This file implements plan.md lines 83-87 (plan 09 task 9):
//
//   - Unknown MCP server is blocked.
//   - Changed tool schema triggers warning or block.
//   - Filesystem MCP cannot read outside workspace.
//   - MCP calls appear in audit logs.
//
// Each scenario maps to one top-level test (or one t.Run subtest) so a
// failing assertion points at exactly one plan bullet. The tests
// exercise the real binaries and real on-disk artifacts wherever the
// surface is reachable from the CLI:
//
//   - Test 1 (Unknown server) drives `ai-env mcp scan` against a real
//     mcp.yaml the test scaffolds via `ai-env mcp add`, then asks the
//     binary to scan a name that was never registered. The CLI's exit
//     code, stderr, and the gateway's deny-by-default error sentinel
//     are all checked.
//
//   - Test 2 (Schema drift) constructs a real internal/mcp.Gateway
//     from a fixture registry written to disk with a pinned schema
//     hash, then asks the gateway to AuthorizeLaunch with a live hash
//     that does not match. Two policy modes are exercised:
//     ServerPolicyAllow must produce Block (hard fail-closed) and
//     ServerPolicyWarn must produce Warn (soft drift signal). The
//     CLI surface `ai-env mcp scan --schema-hash` is exercised against
//     the same fixture so the operator-facing exit code matches.
//
//   - Test 3 (Filesystem out-of-workspace) constructs a real
//     FilesystemScopeEnforcer anchored to a per-test workspace
//     directory, registers it with a real Gateway, and asks the
//     gateway to AuthorizeCall against paths that resolve outside the
//     workspace (/etc/passwd, a symlinked-out path, an absolute path
//     elsewhere on disk). Each must produce Block with
//     ErrFilesystemPathOutsideWorkspace; an in-workspace path must
//     produce Allow.
//
//   - Test 4 (Audit log readback) constructs a real run directory via
//     run.CreateRunDirectory, opens a real run.MCPCallsWriter against
//     it, wires a bridge that satisfies mcp.CallLogger into a real
//     Gateway, drives the gateway through one block and one allow
//     decision, then reads back mcp-calls.jsonl via run.ReadMCPCalls
//     to confirm every decision landed on disk with the expected
//     stage/decision/server fields.
//
// Gating mirrors section32_test.go and the other mvp_demo_* files: the
// build tag `acceptance` is the static gate and AI_ENV_ACCEPTANCE=1
// (via TestMain in section32_test.go) is the dynamic gate. The binary
// is built once by section32_test.go's TestMain and reused via
// suite.binPath.
//
// Why test against the real types (no mocks):
//
//   - The plan calls out the gateway as "the single chokepoint every
//     MCP request must pass through". Mocking the gateway would defeat
//     the load-bearing assertion that the gateway's verdict reaches
//     mcp-calls.jsonl unchanged.
//   - The FilesystemScopeEnforcer's resolution rules (symlink walk,
//     EvalSymlinks, isWithin guard) are exactly what an attacker would
//     try to bypass; a mocked enforcer would silently pass tests that
//     a regression in the real path math would fail.
//   - Schema-hash compare collapses across the registry, gateway, and
//     schema.go boundaries; the real Gateway.AuthorizeLaunch pipeline
//     is the only surface that exercises every collapse point.

package acceptance

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rivan1986/ai-env/internal/mcp"
	"github.com/rivan1986/ai-env/internal/run"
)

// mcpFixtureRegistry returns a real .ai-env/mcp.yaml body the tests
// scaffold to disk. The shape mirrors the master-plan example in
// plan.md so an operator reading the fixture sees the same YAML
// shape they would author by hand. The fixture declares two
// servers:
//
//   - "filesystem" with a filesystem scope (root: workspace_only),
//     policy: allow, a pinned schema_hash so the schema-drift cases
//     have something concrete to compare against.
//   - "github" with a github scope (current_repo_only, read_only),
//     policy: warn, no pinned schema_hash (first-launch onboarding).
//
// Both servers use placeholder npm sources with version pins
// (validateSource requires the @<version> suffix). The digest /
// schema_hash strings use the canonical "sha256:" prefix the
// registry's validateDigest helper requires.
func mcpFixtureRegistry(pinnedHash string) string {
	return strings.Join([]string{
		"version: 1",
		"default: deny",
		"servers:",
		"  filesystem:",
		"    source: npm:@modelcontextprotocol/server-filesystem@1.2.3",
		"    digest: sha256:abc123def456abc123def456abc123def456abc123def456abc123def456abcd",
		"    schema_hash: " + pinnedHash,
		"    scope:",
		"      filesystem:",
		"        root: workspace_only",
		"    policy: allow",
		"  github:",
		"    source: npm:@modelcontextprotocol/server-github@1.1.0",
		"    digest: sha256:fff111fff111fff111fff111fff111fff111fff111fff111fff111fff1110000",
		"    scope:",
		"      github:",
		"        repos: current_repo_only",
		"        operations: read_only",
		"    policy: warn",
		"",
	}, "\n")
}

// writeMCPFixture writes the mcp.yaml fixture under
// <project>/.ai-env/mcp.yaml so the CLI surfaces (mcp scan, mcp list)
// can find it via findAIEnvDir. The helper is split into two modes:
//
//   - rawOnly=true: just write mcp.yaml under .ai-env/ without
//     scaffolding the rest of the project. Used by tests that drive
//     internal/mcp directly (LoadRegistry, NewGateway) and do not
//     need findAIEnvDir to succeed.
//   - rawOnly=false: scaffold a full project via `ai-env new` first
//     (so findAIEnvDir can locate .ai-env/ai-env.yaml) and then
//     overlay our mcp.yaml fixture. Used by tests that drive the
//     CLI surfaces (`ai-env mcp scan`, `ai-env mcp list`).
//
// The split keeps the no-CLI tests fast (no fixture copy + `ai-env new`
// invocation) while still letting the CLI tests reuse the same
// canonical fixture body.
func writeMCPFixture(t *testing.T, project, pinnedHash string) string {
	t.Helper()
	aiEnvDir := filepath.Join(project, ".ai-env")
	if err := os.MkdirAll(aiEnvDir, 0o755); err != nil {
		t.Fatalf("mkdir .ai-env: %v", err)
	}
	path := filepath.Join(aiEnvDir, "mcp.yaml")
	if err := os.WriteFile(path, []byte(mcpFixtureRegistry(pinnedHash)), 0o644); err != nil {
		t.Fatalf("write mcp.yaml: %v", err)
	}
	return path
}

// scaffoldProjectForMCPCLI scaffolds a real ai-env project rooted at
// the returned directory and writes the mcp.yaml fixture into its
// .ai-env/. The CLI's findAIEnvDir requires both `.ai-env/` AND
// `.ai-env/ai-env.yaml` to be present so it can disambiguate an
// ai-env project from any unrelated `.ai-env` directory; the
// scaffold step provides ai-env.yaml as a side effect of
// `ai-env new`.
//
// Mirrors scaffoldProjectForMCP in internal/cli/mcp_test.go but
// drives the CLI binary rather than calling RunNew in-process so the
// acceptance suite stays at the real subprocess boundary.
func scaffoldProjectForMCPCLI(t *testing.T, pinnedHash string) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skipf("git not on PATH: %v", err)
	}
	src := copyFixture(t, "node-app")
	initGitFixture(t, src)
	if _, _, err := runAIEnvWithOutput(t, src, "new", "demo"); err != nil {
		t.Fatalf("ai-env new demo: %v", err)
	}
	writeMCPFixture(t, src, pinnedHash)
	return src
}

// computeFixtureSchemaHash returns the canonical schema hash for the
// two-tool filesystem-server schema the tests share. Centralized so
// "the operator pinned this hash" and "the live server advertises a
// matching hash" both refer to the exact same string without copy-
// pasting hex digests across the file.
func computeFixtureSchemaHash(t *testing.T) string {
	t.Helper()
	h, err := mcp.ComputeSchemaHash(fixtureServerSchema())
	if err != nil {
		t.Fatalf("ComputeSchemaHash: %v", err)
	}
	return h
}

// fixtureServerSchema is the canonical "current" tool list the
// filesystem MCP server in the fixture advertises. Two tools matches
// the master-plan example (read_file + write_file). Used by both the
// pinned-hash path and the schema-drift path (the latter mutates one
// description to force a hash divergence).
func fixtureServerSchema() mcp.ServerSchema {
	return mcp.ServerSchema{
		Tools: []mcp.ToolSchema{
			{
				Name:        "read_file",
				Description: "Read a file from the workspace.",
				InputSchema: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"path": map[string]any{"type": "string"},
					},
					"required": []any{"path"},
				},
			},
			{
				Name:        "write_file",
				Description: "Write a file to the workspace.",
				InputSchema: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"path":    map[string]any{"type": "string"},
						"content": map[string]any{"type": "string"},
					},
					"required": []any{"path", "content"},
				},
			},
		},
	}
}

// driftedFixtureServerSchema returns a schema whose read_file
// description has been changed. The hash must differ from
// fixtureServerSchema's hash so the schema-drift cases produce a
// meaningful Block / Warn verdict. The change targets the
// description (the MCP-poisoning vector the master plan calls out)
// rather than a structural field.
func driftedFixtureServerSchema() mcp.ServerSchema {
	s := fixtureServerSchema()
	// Mutate the read_file description so the canonical hash diverges.
	// Find by name rather than by index so a future reorder of the
	// fixture does not silently undo the drift.
	for i, tool := range s.Tools {
		if tool.Name == "read_file" {
			s.Tools[i].Description = "Read a file. NOW ALSO READS /etc/passwd."
			break
		}
	}
	return s
}

// -----------------------------------------------------------------------------
// Plan 09 step 9 bullet 1: Unknown MCP server is blocked
// -----------------------------------------------------------------------------

// TestAcceptance_MCPGateway_UnknownServerBlocked implements plan.md
// line 84 (plan 09 step 9 bullet 1). The acceptance bar is that an
// agent asking for a server that was never registered in mcp.yaml is
// hard-refused: the gateway returns Block with ErrUnknownServer and
// the CLI's `ai-env mcp scan` surface exits non-zero with an
// operator-readable message.
//
// Two layers are exercised because the master plan calls them out:
//
//  1. The in-process internal/mcp.Gateway pipeline (AuthorizeLaunch
//     and AuthorizeCall) must produce GatewayOutcomeBlock with an
//     error chain that surfaces ErrUnknownServer via errors.Is.
//  2. The CLI's `ai-env mcp scan <unknown>` must exit non-zero and
//     print "unknown server" so an operator running it in CI sees the
//     failure without parsing exit codes alone.
func TestAcceptance_MCPGateway_UnknownServerBlocked(t *testing.T) {
	pinned := computeFixtureSchemaHash(t)
	project := t.TempDir()
	registryPath := writeMCPFixture(t, project, pinned)

	// 1. In-process gateway verdict. Load the real registry so we are
	//    not constructing a synthetic *Registry that could mask a
	//    regression in LoadRegistry.
	reg, err := mcp.LoadRegistry(registryPath)
	if err != nil {
		t.Fatalf("LoadRegistry %s: %v", registryPath, err)
	}
	gw, err := mcp.NewGateway(reg, nil)
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	t.Run("AuthorizeLaunch", func(t *testing.T) {
		dec, logErr := gw.AuthorizeLaunch(mcp.LaunchRequest{Server: "definitely-not-registered"})
		if logErr != nil {
			t.Fatalf("logger error from noop logger: %v", logErr)
		}
		if dec.Outcome != mcp.GatewayOutcomeBlock {
			t.Errorf("Outcome = %v, want Block", dec.Outcome)
		}
		if !errors.Is(dec.Err, mcp.ErrUnknownServer) {
			t.Errorf("dec.Err = %v, want ErrUnknownServer", dec.Err)
		}
		if !strings.Contains(dec.Reason, "unknown server") {
			t.Errorf("dec.Reason = %q, want mention of 'unknown server'", dec.Reason)
		}
	})

	t.Run("AuthorizeCall", func(t *testing.T) {
		dec, logErr := gw.AuthorizeCall(mcp.CallRequest{
			Server: "also-not-registered",
			Tool:   "read_file",
			Path:   "anything",
		})
		if logErr != nil {
			t.Fatalf("logger error from noop logger: %v", logErr)
		}
		if dec.Outcome != mcp.GatewayOutcomeBlock {
			t.Errorf("Outcome = %v, want Block", dec.Outcome)
		}
		if !errors.Is(dec.Err, mcp.ErrUnknownServer) {
			t.Errorf("dec.Err = %v, want ErrUnknownServer", dec.Err)
		}
	})

	// 2. CLI surface: `ai-env mcp scan <unknown>` must exit non-zero
	//    with an operator-readable message mentioning the unknown name.
	//    The CLI's findAIEnvDir requires both `.ai-env/` and
	//    `.ai-env/ai-env.yaml` to be present, so we scaffold a real
	//    project via `ai-env new` and overlay our mcp.yaml fixture.
	t.Run("CLIScanUnknownServerExitsNonZero", func(t *testing.T) {
		cliProject := scaffoldProjectForMCPCLI(t, pinned)
		stdout, stderr, err := runAIEnv(t, cliProject, "mcp", "scan", "definitely-not-registered")
		if err == nil {
			t.Fatalf("ai-env mcp scan <unknown> exited 0; want non-zero. stdout=%s stderr=%s", stdout, stderr)
		}
		combined := stdout + stderr
		if !strings.Contains(combined, "unknown server") &&
			!strings.Contains(combined, "definitely-not-registered") {
			t.Errorf("scan output did not mention the unknown server; stdout=%q stderr=%q", stdout, stderr)
		}
	})
}

// -----------------------------------------------------------------------------
// Plan 09 step 9 bullet 2: Changed tool schema triggers warning or block
// -----------------------------------------------------------------------------

// TestAcceptance_MCPGateway_SchemaDriftWarnOrBlock implements plan.md
// line 85 (plan 09 step 9 bullet 2). The acceptance bar is the master
// plan's "warn or block" rule: a server whose live schema hash does
// not match the pinned hash must produce either a warning (for
// operators who chose policy: warn) or a hard block (for operators
// who chose policy: allow, the fail-closed default).
//
// We exercise both branches against the same fixture registry. The
// "filesystem" entry has policy: allow, so a drift produces Block;
// the "github" entry has policy: warn but no pinned schema_hash, so
// we additionally construct an in-process registry that mirrors the
// warn case with a pinned hash to cover the policy-driven Warn
// outcome end-to-end.
func TestAcceptance_MCPGateway_SchemaDriftWarnOrBlock(t *testing.T) {
	pinned := computeFixtureSchemaHash(t)
	driftedHash, err := mcp.ComputeSchemaHash(driftedFixtureServerSchema())
	if err != nil {
		t.Fatalf("ComputeSchemaHash drifted: %v", err)
	}
	if pinned == driftedHash {
		t.Fatalf("drifted schema produced identical hash %q; test fixture is broken", pinned)
	}

	project := t.TempDir()
	registryPath := writeMCPFixture(t, project, pinned)

	reg, err := mcp.LoadRegistry(registryPath)
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	gw, err := mcp.NewGateway(reg, nil)
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}

	t.Run("FilesystemPolicyAllow_DriftBlocks", func(t *testing.T) {
		// The fixture's filesystem server has policy: allow with a
		// pinned schema_hash. A drift in the live hash must produce
		// Block (hard fail-closed) with ErrSchemaMismatch.
		dec, logErr := gw.AuthorizeLaunch(mcp.LaunchRequest{
			Server:         "filesystem",
			LiveSchemaHash: driftedHash,
		})
		if logErr != nil {
			t.Fatalf("logger error: %v", logErr)
		}
		if dec.Outcome != mcp.GatewayOutcomeBlock {
			t.Errorf("Outcome = %v, want Block", dec.Outcome)
		}
		if !errors.Is(dec.Err, mcp.ErrSchemaMismatch) {
			t.Errorf("dec.Err = %v, want ErrSchemaMismatch", dec.Err)
		}
		if !strings.Contains(dec.Reason, "schema") {
			t.Errorf("dec.Reason did not mention 'schema': %q", dec.Reason)
		}
	})

	t.Run("FilesystemPolicyAllow_MatchAllows", func(t *testing.T) {
		// Sanity: the same registry must allow a launch when the live
		// hash matches the pinned hash. A regression that always
		// blocked would otherwise hide behind the drift case above.
		dec, logErr := gw.AuthorizeLaunch(mcp.LaunchRequest{
			Server:         "filesystem",
			LiveSchemaHash: pinned,
		})
		if logErr != nil {
			t.Fatalf("logger error: %v", logErr)
		}
		if dec.Outcome != mcp.GatewayOutcomeAllow {
			t.Errorf("Outcome = %v (reason=%s), want Allow", dec.Outcome, dec.Reason)
		}
	})

	t.Run("WarnPolicy_DriftWarns", func(t *testing.T) {
		// Build a real Registry whose single server has policy: warn
		// AND a pinned schema_hash, so a drifted live hash produces
		// GatewayOutcomeWarn rather than Block. The fixture's "github"
		// entry has policy: warn but no pinned hash (first-launch
		// onboarding), which produces SchemaOutcomeRecord, not Warn;
		// constructing an in-process registry here pins the policy-
		// driven Warn outcome without forcing the fixture to carry a
		// fake warn-pinned entry.
		cfg := &mcp.RegistryConfig{
			Version: 1,
			Default: mcp.DefaultPolicyDeny,
			Servers: map[string]mcp.RegistryServer{
				"warn-pinned": {
					Source:     "npm:@modelcontextprotocol/server-filesystem@1.2.3",
					SchemaHash: pinned,
					Policy:     mcp.ServerPolicyWarn,
				},
			},
		}
		if err := mcp.ValidateRegistry(cfg); err != nil {
			t.Fatalf("ValidateRegistry: %v", err)
		}
		warnReg := mcp.NewRegistry(cfg)
		warnGW, err := mcp.NewGateway(warnReg, nil)
		if err != nil {
			t.Fatalf("NewGateway warn: %v", err)
		}
		dec, logErr := warnGW.AuthorizeLaunch(mcp.LaunchRequest{
			Server:         "warn-pinned",
			LiveSchemaHash: driftedHash,
		})
		if logErr != nil {
			t.Fatalf("logger error: %v", logErr)
		}
		if dec.Outcome != mcp.GatewayOutcomeWarn {
			t.Errorf("Outcome = %v (reason=%s), want Warn", dec.Outcome, dec.Reason)
		}
		if !strings.Contains(strings.ToLower(dec.Reason), "schema") &&
			!strings.Contains(strings.ToLower(dec.Reason), "warn") {
			t.Errorf("dec.Reason did not mention schema/warn: %q", dec.Reason)
		}
	})

	t.Run("FirstLaunchOnboardingRecords", func(t *testing.T) {
		// The fixture's "github" server has no pinned schema_hash
		// (first-launch state). The gateway must allow the launch and
		// surface a "first launch; pin hash" reason so the operator
		// knows to run `ai-env mcp pin` after the first success. This
		// pins the master-plan onboarding path so a regression that
		// hard-blocked the first launch (and so blocked every
		// onboarding) would fail here.
		dec, logErr := gw.AuthorizeLaunch(mcp.LaunchRequest{
			Server:         "github",
			LiveSchemaHash: pinned, // any non-empty hash works
		})
		if logErr != nil {
			t.Fatalf("logger error: %v", logErr)
		}
		if dec.Outcome != mcp.GatewayOutcomeAllow {
			t.Errorf("Outcome = %v (reason=%s), want Allow for first-launch onboarding",
				dec.Outcome, dec.Reason)
		}
		if !strings.Contains(strings.ToLower(dec.Reason), "first launch") &&
			!strings.Contains(strings.ToLower(dec.Reason), "pin") {
			t.Errorf("first-launch reason did not mention 'first launch' / 'pin': %q", dec.Reason)
		}
	})

	t.Run("CLIScanWithDriftedHashExitsNonZero", func(t *testing.T) {
		// `ai-env mcp scan filesystem --schema-hash <drifted>` is the
		// operator-facing surface that runs CompareSchemaHash. The
		// CLI must exit non-zero when the verdict is Block so CI
		// pipelines fail-closed on drift. The CLI's findAIEnvDir
		// requires both `.ai-env/` and `ai-env.yaml`, so scaffold a
		// real project first and overlay the fixture.
		cliProject := scaffoldProjectForMCPCLI(t, pinned)
		stdout, stderr, err := runAIEnv(t, cliProject,
			"mcp", "scan", "filesystem",
			"--schema-hash", driftedHash,
		)
		if err == nil {
			t.Fatalf("ai-env mcp scan with drifted hash exited 0; want non-zero.\nstdout=%s\nstderr=%s",
				stdout, stderr)
		}
		combined := stdout + stderr
		if !strings.Contains(combined, "schema") {
			t.Errorf("scan output did not mention 'schema'; stdout=%q stderr=%q", stdout, stderr)
		}
	})
}

// -----------------------------------------------------------------------------
// Plan 09 step 9 bullet 3: Filesystem MCP cannot read outside workspace
// -----------------------------------------------------------------------------

// TestAcceptance_MCPGateway_FilesystemOutsideWorkspaceBlocked implements
// plan.md line 86 (plan 09 step 9 bullet 3). The acceptance bar is
// that the FilesystemScopeEnforcer, wired into a real Gateway with a
// real Registry that declares "scope.filesystem.root: workspace_only",
// hard-refuses any path that resolves outside the configured
// workspace root.
//
// The test wires the real types end-to-end:
//
//  1. Workspace directory is created on disk so EvalSymlinks /
//     canonicalization paths exercise real inodes.
//  2. The Registry is constructed from a real mcp.yaml fixture so
//     the gateway loads the same metadata an operator would author.
//  3. The Gateway routes filesystem-kind calls to a real
//     FilesystemScopeEnforcer whose workspace root is the per-test
//     directory created in step 1.
//
// Five paths are exercised:
//
//   - "/etc/passwd": absolute, outside the workspace -> Block.
//   - "../escape": relative, climbs out of the workspace -> Block.
//   - "" (empty): missing required field -> Block with ErrFilesystemEmptyPath.
//   - "subdir/file.txt": relative, inside the workspace -> Allow.
//   - <symlinked-out path>: a symlink inside the workspace that
//     points at /etc must not slip past the resolver -> Block.
func TestAcceptance_MCPGateway_FilesystemOutsideWorkspaceBlocked(t *testing.T) {
	pinned := computeFixtureSchemaHash(t)
	project := t.TempDir()
	registryPath := writeMCPFixture(t, project, pinned)

	// Construct a real workspace directory on disk. The enforcer
	// canonicalizes this path at construction time so a workspace that
	// is itself a symlink does not produce spurious rejections.
	workspaceRoot := filepath.Join(project, "workspace")
	if err := os.MkdirAll(workspaceRoot, 0o755); err != nil {
		t.Fatalf("mkdir workspace: %v", err)
	}
	// Create a known in-workspace file so the allow case has a real
	// inode to point at.
	allowedFile := filepath.Join(workspaceRoot, "subdir", "file.txt")
	if err := os.MkdirAll(filepath.Dir(allowedFile), 0o755); err != nil {
		t.Fatalf("mkdir subdir: %v", err)
	}
	if err := os.WriteFile(allowedFile, []byte("agent content\n"), 0o644); err != nil {
		t.Fatalf("write allowed file: %v", err)
	}

	// Create a symlink INSIDE the workspace that points at /etc so the
	// resolver's EvalSymlinks step is exercised. The enforcer must
	// reject this path because the resolved target is outside the
	// workspace.
	symlinkInside := filepath.Join(workspaceRoot, "trap")
	if err := os.Symlink("/etc", symlinkInside); err != nil {
		t.Skipf("symlink creation not permitted on host: %v", err)
	}

	reg, err := mcp.LoadRegistry(registryPath)
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	fsEnforcer, err := mcp.NewFilesystemScopeEnforcer(workspaceRoot)
	if err != nil {
		t.Fatalf("NewFilesystemScopeEnforcer: %v", err)
	}
	gw, err := mcp.NewGateway(reg, &mcp.GatewayOptions{
		Enforcers: map[string]mcp.ScopeEnforcer{
			mcp.ScopeKindFilesystem: fsEnforcer,
		},
	})
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}

	t.Run("AbsolutePathOutsideBlocked", func(t *testing.T) {
		dec, logErr := gw.AuthorizeCall(mcp.CallRequest{
			Server: "filesystem",
			Tool:   "read_file",
			Path:   "/etc/passwd",
		})
		if logErr != nil {
			t.Fatalf("logger error: %v", logErr)
		}
		if dec.Outcome != mcp.GatewayOutcomeBlock {
			t.Errorf("Outcome = %v (reason=%s), want Block", dec.Outcome, dec.Reason)
		}
		if !errors.Is(dec.Err, mcp.ErrScopeViolation) {
			t.Errorf("dec.Err = %v, want errors.Is(..., ErrScopeViolation)", dec.Err)
		}
		if !errors.Is(dec.Err, mcp.ErrFilesystemPathOutsideWorkspace) {
			t.Errorf("dec.Err = %v, want errors.Is(..., ErrFilesystemPathOutsideWorkspace)", dec.Err)
		}
	})

	t.Run("RelativeEscapeBlocked", func(t *testing.T) {
		dec, logErr := gw.AuthorizeCall(mcp.CallRequest{
			Server: "filesystem",
			Tool:   "read_file",
			Path:   "../escape",
		})
		if logErr != nil {
			t.Fatalf("logger error: %v", logErr)
		}
		if dec.Outcome != mcp.GatewayOutcomeBlock {
			t.Errorf("Outcome = %v (reason=%s), want Block", dec.Outcome, dec.Reason)
		}
		if !errors.Is(dec.Err, mcp.ErrFilesystemPathOutsideWorkspace) {
			t.Errorf("dec.Err = %v, want ErrFilesystemPathOutsideWorkspace", dec.Err)
		}
	})

	t.Run("EmptyPathBlocked", func(t *testing.T) {
		dec, logErr := gw.AuthorizeCall(mcp.CallRequest{
			Server: "filesystem",
			Tool:   "read_file",
			Path:   "",
		})
		if logErr != nil {
			t.Fatalf("logger error: %v", logErr)
		}
		if dec.Outcome != mcp.GatewayOutcomeBlock {
			t.Errorf("Outcome = %v (reason=%s), want Block", dec.Outcome, dec.Reason)
		}
		if !errors.Is(dec.Err, mcp.ErrFilesystemEmptyPath) {
			t.Errorf("dec.Err = %v, want ErrFilesystemEmptyPath", dec.Err)
		}
	})

	t.Run("SymlinkOutsideBlocked", func(t *testing.T) {
		// "trap" is a symlink inside the workspace whose target is
		// /etc. A naive HasPrefix check on the literal path string
		// would let this through; the enforcer's EvalSymlinks resolve
		// step is the load-bearing defense.
		dec, logErr := gw.AuthorizeCall(mcp.CallRequest{
			Server: "filesystem",
			Tool:   "read_file",
			Path:   "trap/passwd",
		})
		if logErr != nil {
			t.Fatalf("logger error: %v", logErr)
		}
		if dec.Outcome != mcp.GatewayOutcomeBlock {
			t.Errorf("Outcome = %v (reason=%s), want Block (symlink-out smuggling)",
				dec.Outcome, dec.Reason)
		}
		if !errors.Is(dec.Err, mcp.ErrFilesystemPathOutsideWorkspace) {
			t.Errorf("dec.Err = %v, want ErrFilesystemPathOutsideWorkspace", dec.Err)
		}
	})

	t.Run("InWorkspacePathAllowed", func(t *testing.T) {
		dec, logErr := gw.AuthorizeCall(mcp.CallRequest{
			Server: "filesystem",
			Tool:   "read_file",
			Path:   "subdir/file.txt",
		})
		if logErr != nil {
			t.Fatalf("logger error: %v", logErr)
		}
		if dec.Outcome != mcp.GatewayOutcomeAllow {
			t.Errorf("Outcome = %v (reason=%s), want Allow for in-workspace path",
				dec.Outcome, dec.Reason)
		}
	})

	t.Run("NewFileInWorkspaceAllowed", func(t *testing.T) {
		// The enforcer must allow writes to a not-yet-existing file
		// inside the workspace (the resolveSymlinksBestEffort path).
		// A regression that required the file to exist would block
		// every "create file" call.
		dec, logErr := gw.AuthorizeCall(mcp.CallRequest{
			Server: "filesystem",
			Tool:   "write_file",
			Path:   "newdir/newfile.txt",
		})
		if logErr != nil {
			t.Fatalf("logger error: %v", logErr)
		}
		if dec.Outcome != mcp.GatewayOutcomeAllow {
			t.Errorf("Outcome = %v (reason=%s), want Allow for not-yet-existing in-workspace path",
				dec.Outcome, dec.Reason)
		}
	})
}

// -----------------------------------------------------------------------------
// Plan 09 step 9 bullet 4: MCP calls appear in audit logs
// -----------------------------------------------------------------------------

// mcpCallsBridge satisfies mcp.CallLogger by forwarding each
// mcp.CallRecord verbatim to a run.MCPCallsWriter. The bridge is the
// production wiring point between internal/mcp (which owns the
// gateway semantics) and internal/run (which owns the on-disk JSONL
// shape); a test that mocked the bridge would defeat the load-
// bearing assertion that the gateway's decision reaches
// mcp-calls.jsonl unchanged.
//
// The two structs share JSON tags by design so the bridge is a
// pure field-by-field copy. Defining the bridge here (rather than
// reaching into internal/cli's wiring) keeps the test self-
// contained and pins the wire format the production bridge must
// also satisfy.
type mcpCallsBridge struct {
	writer *run.MCPCallsWriter
}

// Log implements mcp.CallLogger by mapping every field on
// mcp.CallRecord to the matching field on run.MCPCallRecord. The
// Stage field is mapped via direct token equality (the two packages
// pin the same "launch" / "call" tokens by contract); a runtime
// mismatch would surface as a writer rejection because Stage is
// required.
func (b *mcpCallsBridge) Log(rec mcp.CallRecord) error {
	return b.writer.Write(run.MCPCallRecord{
		Timestamp:    rec.Timestamp,
		Stage:        string(rec.Stage),
		Server:       rec.Server,
		Decision:     rec.Decision,
		Reason:       rec.Reason,
		Tool:         rec.Tool,
		Source:       rec.Source,
		Digest:       rec.Digest,
		ExpectedHash: rec.ExpectedHash,
		ActualHash:   rec.ActualHash,
		Path:         rec.Path,
		Repo:         rec.Repo,
		Operation:    rec.Operation,
		ScopeKinds:   rec.ScopeKinds,
	})
}

// TestAcceptance_MCPGateway_CallsAppearInAuditLog implements plan.md
// line 87 (plan 09 step 9 bullet 4). The acceptance bar is that every
// gateway decision (allow, warn, block) lands as one JSON line in
// mcp-calls.jsonl inside the run directory. The audit log is the
// operator's after-the-fact record of every MCP action the agent
// attempted; a gateway that returned a verdict without persisting it
// would defeat the master plan's "all MCP calls logged" guarantee.
//
// Pipeline:
//
//  1. Create a real run directory via run.CreateRunDirectory.
//  2. Open a real run.MCPCallsWriter against it.
//  3. Wire the writer into a real internal/mcp.Gateway via the
//     mcpCallsBridge.
//  4. Drive the gateway through a representative sample:
//     - Unknown-server Block (deny-by-default branch).
//     - Allow launch against a pinned filesystem server.
//     - Block AuthorizeCall against an out-of-workspace path.
//     - Allow AuthorizeCall against an in-workspace path.
//  5. Close the writer (flushes the final record).
//  6. Read mcp-calls.jsonl via run.ReadMCPCalls and assert that every
//     decision appears with the expected stage, server, decision
//     token, and that decision-specific fields (Path, ExpectedHash,
//     ActualHash) are populated where the gateway promised they would
//     be.
func TestAcceptance_MCPGateway_CallsAppearInAuditLog(t *testing.T) {
	pinned := computeFixtureSchemaHash(t)
	project := t.TempDir()
	registryPath := writeMCPFixture(t, project, pinned)

	// 1. Real run directory.
	runsRoot := t.TempDir()
	runID, err := run.GenerateRunID()
	if err != nil {
		t.Fatalf("GenerateRunID: %v", err)
	}
	runDir, err := run.CreateRunDirectory(runsRoot, runID, time.Now())
	if err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}

	// 2. Real MCPCallsWriter.
	writer, err := run.OpenMCPCallsWriter(runDir.Path, run.MCPCallsWriterOptions{
		RunID: runDir.ID,
	})
	if err != nil {
		t.Fatalf("OpenMCPCallsWriter: %v", err)
	}
	bridge := &mcpCallsBridge{writer: writer}

	// 3. Real Gateway wired to the bridge plus a real filesystem
	//    enforcer so the AuthorizeCall path produces meaningful
	//    audit records (scope_kinds, path).
	workspaceRoot := filepath.Join(project, "workspace")
	if err := os.MkdirAll(workspaceRoot, 0o755); err != nil {
		t.Fatalf("mkdir workspace: %v", err)
	}
	inFile := filepath.Join(workspaceRoot, "ok.txt")
	if err := os.WriteFile(inFile, []byte("inside\n"), 0o644); err != nil {
		t.Fatalf("write inside file: %v", err)
	}
	fsEnforcer, err := mcp.NewFilesystemScopeEnforcer(workspaceRoot)
	if err != nil {
		t.Fatalf("NewFilesystemScopeEnforcer: %v", err)
	}
	reg, err := mcp.LoadRegistry(registryPath)
	if err != nil {
		t.Fatalf("LoadRegistry: %v", err)
	}
	gw, err := mcp.NewGateway(reg, &mcp.GatewayOptions{
		Logger: bridge,
		Enforcers: map[string]mcp.ScopeEnforcer{
			mcp.ScopeKindFilesystem: fsEnforcer,
		},
	})
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}

	// 4. Drive the gateway through representative decisions.

	// 4a. Unknown server (Block).
	if _, err := gw.AuthorizeLaunch(mcp.LaunchRequest{Server: "no-such-server"}); err != nil {
		t.Fatalf("AuthorizeLaunch unknown: writer error %v", err)
	}

	// 4b. Allow launch with matching schema.
	if _, err := gw.AuthorizeLaunch(mcp.LaunchRequest{
		Server:         "filesystem",
		Source:         "npm:@modelcontextprotocol/server-filesystem@1.2.3",
		LiveSchemaHash: pinned,
	}); err != nil {
		t.Fatalf("AuthorizeLaunch allow: writer error %v", err)
	}

	// 4c. AuthorizeCall blocked (out-of-workspace path).
	if _, err := gw.AuthorizeCall(mcp.CallRequest{
		Server: "filesystem",
		Tool:   "read_file",
		Path:   "/etc/passwd",
	}); err != nil {
		t.Fatalf("AuthorizeCall block: writer error %v", err)
	}

	// 4d. AuthorizeCall allowed (in-workspace path).
	if _, err := gw.AuthorizeCall(mcp.CallRequest{
		Server: "filesystem",
		Tool:   "read_file",
		Path:   "ok.txt",
	}); err != nil {
		t.Fatalf("AuthorizeCall allow: writer error %v", err)
	}

	// 5. Close the writer so the final record is fsync'd.
	if err := writer.Close(); err != nil {
		t.Fatalf("writer.Close: %v", err)
	}

	// 6. Readback. The audit log must contain exactly four records in
	//    the order they were emitted.
	records, err := run.ReadMCPCalls(runDir.Path)
	if err != nil {
		t.Fatalf("ReadMCPCalls: %v", err)
	}
	if len(records) != 4 {
		t.Fatalf("ReadMCPCalls returned %d records, want 4. records=%+v", len(records), records)
	}

	// 6a. Unknown server: Stage=launch, Decision=block, Server echoed.
	unknown := records[0]
	if unknown.Stage != run.MCPCallStageLaunch {
		t.Errorf("rec[0].Stage = %q, want %q", unknown.Stage, run.MCPCallStageLaunch)
	}
	if unknown.Decision != run.MCPCallDecisionBlock {
		t.Errorf("rec[0].Decision = %q, want %q", unknown.Decision, run.MCPCallDecisionBlock)
	}
	if unknown.Server != "no-such-server" {
		t.Errorf("rec[0].Server = %q, want %q", unknown.Server, "no-such-server")
	}
	if !strings.Contains(unknown.Reason, "unknown") {
		t.Errorf("rec[0].Reason did not mention 'unknown': %q", unknown.Reason)
	}

	// 6b. Allow launch: Stage=launch, Decision=allow, ExpectedHash and
	//     ActualHash both equal to pinned (the schema-compare path
	//     stamped them into the record).
	allowLaunch := records[1]
	if allowLaunch.Stage != run.MCPCallStageLaunch {
		t.Errorf("rec[1].Stage = %q, want %q", allowLaunch.Stage, run.MCPCallStageLaunch)
	}
	if allowLaunch.Decision != run.MCPCallDecisionAllow {
		t.Errorf("rec[1].Decision = %q, want %q", allowLaunch.Decision, run.MCPCallDecisionAllow)
	}
	if allowLaunch.Server != "filesystem" {
		t.Errorf("rec[1].Server = %q, want filesystem", allowLaunch.Server)
	}
	if allowLaunch.ExpectedHash != pinned {
		t.Errorf("rec[1].ExpectedHash = %q, want %q", allowLaunch.ExpectedHash, pinned)
	}
	if allowLaunch.ActualHash != pinned {
		t.Errorf("rec[1].ActualHash = %q, want %q", allowLaunch.ActualHash, pinned)
	}
	if allowLaunch.Source != "npm:@modelcontextprotocol/server-filesystem@1.2.3" {
		t.Errorf("rec[1].Source = %q, want pinned npm source", allowLaunch.Source)
	}

	// 6c. Block AuthorizeCall: Stage=call, Decision=block, Path
	//     populated, scope_kinds includes filesystem.
	blockCall := records[2]
	if blockCall.Stage != run.MCPCallStageCall {
		t.Errorf("rec[2].Stage = %q, want %q", blockCall.Stage, run.MCPCallStageCall)
	}
	if blockCall.Decision != run.MCPCallDecisionBlock {
		t.Errorf("rec[2].Decision = %q, want %q", blockCall.Decision, run.MCPCallDecisionBlock)
	}
	if blockCall.Path != "/etc/passwd" {
		t.Errorf("rec[2].Path = %q, want /etc/passwd", blockCall.Path)
	}
	if blockCall.Tool != "read_file" {
		t.Errorf("rec[2].Tool = %q, want read_file", blockCall.Tool)
	}
	if !containsString(blockCall.ScopeKinds, "filesystem") {
		t.Errorf("rec[2].ScopeKinds = %v, want to contain 'filesystem'", blockCall.ScopeKinds)
	}

	// 6d. Allow AuthorizeCall: Stage=call, Decision=allow, Path
	//     populated, scope_kinds includes filesystem.
	allowCall := records[3]
	if allowCall.Stage != run.MCPCallStageCall {
		t.Errorf("rec[3].Stage = %q, want %q", allowCall.Stage, run.MCPCallStageCall)
	}
	if allowCall.Decision != run.MCPCallDecisionAllow {
		t.Errorf("rec[3].Decision = %q, want %q", allowCall.Decision, run.MCPCallDecisionAllow)
	}
	if allowCall.Path != "ok.txt" {
		t.Errorf("rec[3].Path = %q, want ok.txt", allowCall.Path)
	}
	if !containsString(allowCall.ScopeKinds, "filesystem") {
		t.Errorf("rec[3].ScopeKinds = %v, want to contain 'filesystem'", allowCall.ScopeKinds)
	}

	// The audit file must exist at the canonical path the rest of
	// ai-env consumes ([rundir]/mcp-calls.jsonl). A regression that
	// wrote to a different path would break operator tooling.
	mcpPath := run.MCPCallsPath(runDir.Path)
	if _, statErr := os.Stat(mcpPath); statErr != nil {
		t.Errorf("mcp-calls.jsonl missing at canonical path %s: %v", mcpPath, statErr)
	}

	// Every record must carry a non-empty Timestamp. The gateway
	// stamps RFC3339; the writer would also stamp one if it were
	// empty. The plan requires the audit log to be self-contained,
	// so a missing timestamp is a regression.
	for i, r := range records {
		if r.Timestamp == "" {
			t.Errorf("rec[%d].Timestamp empty; audit log not self-contained", i)
		}
	}
}

// -----------------------------------------------------------------------------
// Plan 09 step 9 supporting bullet: `ai-env mcp list` shows registered servers
// -----------------------------------------------------------------------------

// TestAcceptance_MCPGateway_ListShowsRegisteredServers pins acceptance
// criterion 5 from plan.md line 95: "`ai-env mcp list` shows
// registered servers with their version and schema hash." The list
// surface is the operator's read-side view of mcp.yaml; a regression
// that dropped the version or schema_hash column would silently break
// the documented "I can see what is registered" workflow.
//
// The test scaffolds an mcp.yaml fixture, runs `ai-env mcp list` as a
// real subprocess, and asserts that:
//
//   - The output mentions both fixture servers ("filesystem", "github").
//   - The pinned source string for at least one server appears in the
//     output (proving the version dimension is surfaced).
//   - The pinned schema_hash for the filesystem server appears
//     (proving the schema_hash dimension is surfaced).
//   - The default policy ("deny") is surfaced so the operator sees
//     the registry-wide stance.
func TestAcceptance_MCPGateway_ListShowsRegisteredServers(t *testing.T) {
	pinned := computeFixtureSchemaHash(t)
	// The CLI's findAIEnvDir requires both `.ai-env/` and ai-env.yaml,
	// so scaffold a real project first and overlay the mcp.yaml
	// fixture. Mirrors the unknown-server / drift CLI subtests.
	project := scaffoldProjectForMCPCLI(t, pinned)

	stdout, stderr, err := runAIEnv(t, project, "mcp", "list")
	if err != nil {
		t.Fatalf("ai-env mcp list: %v\nstdout=%s\nstderr=%s", err, stdout, stderr)
	}
	for _, want := range []string{
		"filesystem",
		"github",
		"npm:@modelcontextprotocol/server-filesystem@1.2.3",
		pinned,
		"deny", // default policy
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("ai-env mcp list stdout missing %q. full stdout:\n%s", want, stdout)
		}
	}
}

// containsString reports whether haystack contains needle. Used by
// the audit-log readback to assert ScopeKinds membership without
// dragging in sort/strings semantics that would obscure the
// intent ("the gateway recorded this scope kind").
func containsString(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

// Compile-time sanity: mcpCallsBridge must satisfy mcp.CallLogger so
// a future refactor that changes the interface fails the build here
// rather than at the first test that exercises the bridge.
var _ mcp.CallLogger = (*mcpCallsBridge)(nil)

// Keep the fmt import referenced even when only one bullet uses it.
// Without this, a future test refactor that drops the only call site
// would leave a dangling import that breaks the rest of the suite's
// build.
var _ = fmt.Sprintf
