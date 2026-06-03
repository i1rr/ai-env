package cli

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/i1rr/ai-env/internal/mcp"
	"github.com/i1rr/ai-env/internal/run"
)

// TestMCPCallLogger_BridgesGatewayToFile is the end-to-end integration
// for plan 09 step 7. It exercises the full path that the supervisor
// will use once it constructs a per-run gateway:
//
//  1. Build a real run directory on disk so mcp-calls.jsonl is in the
//     right place.
//  2. Open a run.MCPCallsWriter against the run dir.
//  3. Wrap it in an MCPCallLogger.
//  4. Construct an mcp.Gateway with the bridge as its Logger.
//  5. Drive AuthorizeLaunch and AuthorizeCall against a fixture
//     registry.
//  6. Read mcp-calls.jsonl back and assert the records landed at the
//     right path with the right shape.
//
// This is the test the task description requires ("confirming records
// actually land in the right path with correct JSON shape").
func TestMCPCallLogger_BridgesGatewayToFile(t *testing.T) {
	// --- step 1: run directory --------------------------------------
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	runID := "20260530-120000-deadbe"
	now := time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC)
	dir, err := run.CreateRunDirectory(aiEnvDir, runID, now)
	if err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}

	// --- step 2: open the writer ------------------------------------
	t1 := now
	t2 := now.Add(time.Second)
	writer, err := run.OpenMCPCallsWriter(dir.Path, run.MCPCallsWriterOptions{
		RunID: dir.ID,
		Now:   fixedTimes(t1, t2),
	})
	if err != nil {
		t.Fatalf("OpenMCPCallsWriter: %v", err)
	}
	defer writer.Close()

	// --- step 3: bridge --------------------------------------------
	bridge, err := NewMCPCallLogger(writer)
	if err != nil {
		t.Fatalf("NewMCPCallLogger: %v", err)
	}

	// --- step 4: gateway -------------------------------------------
	// Use the public mcp.NewRegistry + ValidateRegistry path so the
	// test exercises the production registry shape rather than poking
	// internals. RegistryConfig.Default is hard-pinned to "deny" by
	// the validator; the per-server Policy supplies the per-entry
	// allow/warn/deny verdict.
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
	registry := mcp.NewRegistry(&regCfg)

	gatewayClock := fixedTimes(t1, t2)
	gw, err := mcp.NewGateway(registry, &mcp.GatewayOptions{
		Logger: bridge,
		Now:    gatewayClock,
	})
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}

	// --- step 5: drive decisions -----------------------------------
	// AuthorizeLaunch produces a launch-stage record.
	launchDec, err := gw.AuthorizeLaunch(mcp.LaunchRequest{
		Server: "filesystem",
		Source: "npm:@modelcontextprotocol/server-filesystem@1.2.3",
	})
	if err != nil {
		t.Fatalf("AuthorizeLaunch: %v", err)
	}
	if launchDec.Outcome != mcp.GatewayOutcomeAllow {
		t.Fatalf("launch outcome = %v, want Allow", launchDec.Outcome)
	}

	// AuthorizeCall produces a call-stage record. The fixture server
	// declares no scope, so the decision short-circuits to the
	// per-server policy (allow).
	callDec, err := gw.AuthorizeCall(mcp.CallRequest{
		Server: "filesystem",
		Tool:   "read_file",
	})
	if err != nil {
		t.Fatalf("AuthorizeCall: %v", err)
	}
	if callDec.Outcome != mcp.GatewayOutcomeAllow {
		t.Fatalf("call outcome = %v, want Allow", callDec.Outcome)
	}

	// --- step 6: assert on-disk shape ------------------------------
	// Close the writer so the OS buffer is flushed before we read.
	if err := writer.Close(); err != nil {
		t.Fatalf("writer Close: %v", err)
	}

	records, err := run.ReadMCPCalls(dir.Path)
	if err != nil {
		t.Fatalf("ReadMCPCalls: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d (%v)", len(records), records)
	}

	// Record 0: launch-stage allow.
	r0 := records[0]
	if r0.Stage != run.MCPCallStageLaunch {
		t.Errorf("records[0].Stage = %q, want %q", r0.Stage, run.MCPCallStageLaunch)
	}
	if r0.Server != "filesystem" {
		t.Errorf("records[0].Server = %q, want filesystem", r0.Server)
	}
	if r0.Decision != run.MCPCallDecisionAllow {
		t.Errorf("records[0].Decision = %q, want %q", r0.Decision, run.MCPCallDecisionAllow)
	}
	if r0.Reason == "" {
		t.Errorf("records[0].Reason is empty")
	}
	if r0.Source != "npm:@modelcontextprotocol/server-filesystem@1.2.3" {
		t.Errorf("records[0].Source = %q, want pinned npm source", r0.Source)
	}
	// Gateway uses its own clock to stamp Timestamp; the value should
	// be the first time from gatewayClock.
	if r0.Timestamp != t1.Format(time.RFC3339) {
		t.Errorf("records[0].Timestamp = %q, want %q (gateway-stamped)", r0.Timestamp, t1.Format(time.RFC3339))
	}

	// Record 1: call-stage allow with the tool name.
	r1 := records[1]
	if r1.Stage != run.MCPCallStageCall {
		t.Errorf("records[1].Stage = %q, want %q", r1.Stage, run.MCPCallStageCall)
	}
	if r1.Server != "filesystem" {
		t.Errorf("records[1].Server = %q, want filesystem", r1.Server)
	}
	if r1.Decision != run.MCPCallDecisionAllow {
		t.Errorf("records[1].Decision = %q, want %q", r1.Decision, run.MCPCallDecisionAllow)
	}
	if r1.Tool != "read_file" {
		t.Errorf("records[1].Tool = %q, want read_file", r1.Tool)
	}
	if r1.Timestamp != t2.Format(time.RFC3339) {
		t.Errorf("records[1].Timestamp = %q, want %q", r1.Timestamp, t2.Format(time.RFC3339))
	}
}

// TestMCPCallLogger_BridgesBlockDecision drives a Block verdict
// through the bridge to confirm the unknown-server path lands the
// right Decision token and a non-empty Reason on disk.
func TestMCPCallLogger_BridgesBlockDecision(t *testing.T) {
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	runID := "20260530-120000-deadbe"
	now := time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC)
	dir, err := run.CreateRunDirectory(aiEnvDir, runID, now)
	if err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}
	writer, err := run.OpenMCPCallsWriter(dir.Path, run.MCPCallsWriterOptions{
		RunID: dir.ID,
		Now:   fixedTimes(now),
	})
	if err != nil {
		t.Fatalf("OpenMCPCallsWriter: %v", err)
	}
	defer writer.Close()

	bridge, err := NewMCPCallLogger(writer)
	if err != nil {
		t.Fatalf("NewMCPCallLogger: %v", err)
	}

	// Validator requires at least one server even though this test
	// exercises the unknown-server-lookup path; register one server
	// and then look up a different name to drive the Block verdict.
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
	registry := mcp.NewRegistry(&regCfg)
	gw, err := mcp.NewGateway(registry, &mcp.GatewayOptions{
		Logger: bridge,
		Now:    fixedTimes(now),
	})
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}

	dec, _ := gw.AuthorizeLaunch(mcp.LaunchRequest{Server: "unknown-server"})
	if dec.Outcome != mcp.GatewayOutcomeBlock {
		t.Fatalf("outcome = %v, want Block", dec.Outcome)
	}

	if err := writer.Close(); err != nil {
		t.Fatalf("writer Close: %v", err)
	}

	records, err := run.ReadMCPCalls(dir.Path)
	if err != nil {
		t.Fatalf("ReadMCPCalls: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].Decision != run.MCPCallDecisionBlock {
		t.Errorf("Decision = %q, want %q", records[0].Decision, run.MCPCallDecisionBlock)
	}
	if records[0].Server != "unknown-server" {
		t.Errorf("Server = %q, want unknown-server", records[0].Server)
	}
	if records[0].Reason == "" {
		t.Errorf("Reason is empty")
	}
}

// TestNewMCPCallLogger_RejectsNilWriter enforces the constructor's
// fail-loud contract for a missing writer.
func TestNewMCPCallLogger_RejectsNilWriter(t *testing.T) {
	if _, err := NewMCPCallLogger(nil); err == nil {
		t.Errorf("nil writer: expected error, got nil")
	}
}

// fixedTimes returns a now() closure that hands back the supplied
// times in order. After the slice is exhausted, every subsequent call
// returns the last time so a test that writes more events than it
// pre-staged still produces parseable JSON.
func fixedTimes(times ...time.Time) func() time.Time {
	i := 0
	return func() time.Time {
		if i >= len(times) {
			return times[len(times)-1]
		}
		t := times[i]
		i++
		return t
	}
}
