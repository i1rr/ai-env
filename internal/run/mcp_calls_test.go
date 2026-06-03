package run

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestMCPCallsWriter_AppendsValidJSONL covers the writer's primary
// contract for plan 09 step 7: each Write call appends exactly one
// valid JSON object followed by a newline to mcp-calls.jsonl at the
// root of the run directory, every line round-trips back to an
// MCPCallRecord, and Close finalizes the file cleanly (subsequent
// Write fails, Close is idempotent). The test uses a real temp
// directory and the real JSON encoder/decoder — no mocks of the
// filesystem or encoding layers.
func TestMCPCallsWriter_AppendsValidJSONL(t *testing.T) {
	// Build a real run directory on disk via the production helper so
	// the writer cooperates with the placeholder CreateRunDirectory
	// leaves behind, exactly as it will at supervisor wire-up time.
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	runID := "20260530-120000-deadbe"
	now := time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC)
	dir, err := CreateRunDirectory(aiEnvDir, runID, now)
	if err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}

	t1 := now
	t2 := now.Add(time.Second)
	t3 := now.Add(2 * time.Second)

	w, err := OpenMCPCallsWriter(dir.Path, MCPCallsWriterOptions{
		RunID: dir.ID,
		Now:   fixedTimes(t1, t2, t3),
	})
	if err != nil {
		t.Fatalf("OpenMCPCallsWriter: %v", err)
	}

	// Exercise a representative mix: a launch-stage allow with the
	// pinning fields populated, a call-stage block carrying scope
	// context, and a call-stage warn with no scope (per-server warn
	// policy on a scope-free server). All three families share the
	// MCPCallRecord struct so we catch encoder regressions across the
	// omitempty fields too.
	records := []MCPCallRecord{
		{
			Stage:        MCPCallStageLaunch,
			Server:       "filesystem",
			Decision:     MCPCallDecisionAllow,
			Reason:       "server \"filesystem\" allowed",
			Source:       "npm:@modelcontextprotocol/server-filesystem@1.2.3",
			Digest:       "sha256:abc123",
			ExpectedHash: "sha256:expected",
			ActualHash:   "sha256:expected",
		},
		{
			Stage:      MCPCallStageCall,
			Server:     "filesystem",
			Decision:   MCPCallDecisionBlock,
			Reason:     "server \"filesystem\" scope \"filesystem\" rejected: path outside workspace",
			Tool:       "read_file",
			Path:       "/etc/passwd",
			ScopeKinds: []string{"filesystem"},
		},
		{
			Stage:    MCPCallStageCall,
			Server:   "github",
			Decision: MCPCallDecisionWarn,
			Reason:   "server \"github\" policy is warn (tool \"create_issue\")",
			Tool:     "create_issue",
			Repo:     "i1rr/ai-env",
		},
	}

	for i, rec := range records {
		// The writer leaves the caller's Timestamp empty so it can
		// inject its own; passing an empty value exercises the
		// fixed-clock fallback.
		if err := w.Write(rec); err != nil {
			t.Fatalf("Write(records[%d] stage=%s server=%s): %v", i, rec.Stage, rec.Server, err)
		}
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Close is idempotent per its contract.
	if err := w.Close(); err != nil {
		t.Fatalf("Close (second call): %v", err)
	}

	// Write after Close must fail loudly.
	if err := w.Write(MCPCallRecord{Stage: MCPCallStageLaunch, Server: "x", Decision: MCPCallDecisionAllow, Reason: "x"}); err == nil {
		t.Fatalf("Write after Close: expected error, got nil")
	}

	// Verify the file lives where the plan requires (run dir root) and
	// the writer materialized real bytes there.
	path := filepath.Join(dir.Path, "mcp-calls.jsonl")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat %s: %v", path, err)
	}
	if info.Size() == 0 {
		t.Fatalf("mcp-calls.jsonl is empty; expected at least one record")
	}

	// Read the file back and round-trip each line through
	// json.Unmarshal into a fresh MCPCallRecord so we are exercising
	// real encoding/decoding, not mocks.
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()

	expectedTimestamps := []string{
		t1.Format(time.RFC3339),
		t2.Format(time.RFC3339),
		t3.Format(time.RFC3339),
	}

	scanner := bufio.NewScanner(f)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(lines) != len(records) {
		t.Fatalf("expected %d lines, got %d (lines=%v)", len(records), len(lines), lines)
	}

	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
			t.Fatalf("line[%d] is empty", i)
		}
		var got MCPCallRecord
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Fatalf("Unmarshal line[%d]=%q: %v", i, line, err)
		}
		if got.Timestamp != expectedTimestamps[i] {
			t.Errorf("line[%d] Timestamp = %q, want %q", i, got.Timestamp, expectedTimestamps[i])
		}
		if got.Stage != records[i].Stage {
			t.Errorf("line[%d] Stage = %q, want %q", i, got.Stage, records[i].Stage)
		}
		if got.Server != records[i].Server {
			t.Errorf("line[%d] Server = %q, want %q", i, got.Server, records[i].Server)
		}
		if got.Decision != records[i].Decision {
			t.Errorf("line[%d] Decision = %q, want %q", i, got.Decision, records[i].Decision)
		}
		if got.Reason != records[i].Reason {
			t.Errorf("line[%d] Reason = %q, want %q", i, got.Reason, records[i].Reason)
		}
		if got.Tool != records[i].Tool {
			t.Errorf("line[%d] Tool = %q, want %q", i, got.Tool, records[i].Tool)
		}
		if got.Source != records[i].Source {
			t.Errorf("line[%d] Source = %q, want %q", i, got.Source, records[i].Source)
		}
		if got.Digest != records[i].Digest {
			t.Errorf("line[%d] Digest = %q, want %q", i, got.Digest, records[i].Digest)
		}
		if got.ExpectedHash != records[i].ExpectedHash {
			t.Errorf("line[%d] ExpectedHash = %q, want %q", i, got.ExpectedHash, records[i].ExpectedHash)
		}
		if got.ActualHash != records[i].ActualHash {
			t.Errorf("line[%d] ActualHash = %q, want %q", i, got.ActualHash, records[i].ActualHash)
		}
		if got.Path != records[i].Path {
			t.Errorf("line[%d] Path = %q, want %q", i, got.Path, records[i].Path)
		}
		if got.Repo != records[i].Repo {
			t.Errorf("line[%d] Repo = %q, want %q", i, got.Repo, records[i].Repo)
		}
		if !equalStringSlice(got.ScopeKinds, records[i].ScopeKinds) {
			t.Errorf("line[%d] ScopeKinds = %v, want %v", i, got.ScopeKinds, records[i].ScopeKinds)
		}
	}
}

// TestMCPCallsWriter_PreservesCallerTimestamp covers the contract that
// when the caller (the gateway) supplies its own Timestamp, the writer
// preserves it rather than stamping its own. The gateway is the
// authoritative source for decision-time timestamps; the writer's
// clock is only a fallback for direct-use callers (tests).
func TestMCPCallsWriter_PreservesCallerTimestamp(t *testing.T) {
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	runID := "20260530-120000-deadbe"
	now := time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC)
	dir, err := CreateRunDirectory(aiEnvDir, runID, now)
	if err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}

	// The writer's own clock returns a different time; the test
	// asserts the caller-supplied Timestamp wins.
	writerClock := now.Add(time.Hour)
	gatewayStamp := now.Add(5 * time.Second).Format(time.RFC3339)

	w, err := OpenMCPCallsWriter(dir.Path, MCPCallsWriterOptions{
		RunID: dir.ID,
		Now:   fixedTimes(writerClock),
	})
	if err != nil {
		t.Fatalf("OpenMCPCallsWriter: %v", err)
	}
	defer w.Close()

	rec := MCPCallRecord{
		Timestamp: gatewayStamp,
		Stage:     MCPCallStageLaunch,
		Server:    "filesystem",
		Decision:  MCPCallDecisionAllow,
		Reason:    "allowed",
	}
	if err := w.Write(rec); err != nil {
		t.Fatalf("Write: %v", err)
	}

	records, err := ReadMCPCalls(dir.Path)
	if err != nil {
		t.Fatalf("ReadMCPCalls: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].Timestamp != gatewayStamp {
		t.Errorf("Timestamp = %q, want %q (caller-supplied stamp)", records[0].Timestamp, gatewayStamp)
	}
}

// TestMCPCallsWriter_RejectsIncomplete enforces the "fail loudly"
// rules: an empty Stage / Server / Decision / Reason should be
// rejected before the line lands on disk so a misconfigured caller
// does not silently produce an unidentifiable record.
func TestMCPCallsWriter_RejectsIncomplete(t *testing.T) {
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	runID := "20260530-120000-deadbe"
	now := time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC)
	dir, err := CreateRunDirectory(aiEnvDir, runID, now)
	if err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}
	w, err := OpenMCPCallsWriter(dir.Path, MCPCallsWriterOptions{RunID: dir.ID, Now: fixedTimes(now)})
	if err != nil {
		t.Fatalf("OpenMCPCallsWriter: %v", err)
	}
	defer w.Close()

	cases := []struct {
		name string
		rec  MCPCallRecord
	}{
		{
			name: "missing Stage",
			rec:  MCPCallRecord{Server: "x", Decision: MCPCallDecisionAllow, Reason: "x"},
		},
		{
			name: "missing Server",
			rec:  MCPCallRecord{Stage: MCPCallStageLaunch, Decision: MCPCallDecisionAllow, Reason: "x"},
		},
		{
			name: "missing Decision",
			rec:  MCPCallRecord{Stage: MCPCallStageLaunch, Server: "x", Reason: "x"},
		},
		{
			name: "missing Reason",
			rec:  MCPCallRecord{Stage: MCPCallStageLaunch, Server: "x", Decision: MCPCallDecisionAllow},
		},
	}
	for _, c := range cases {
		if err := w.Write(c.rec); err == nil {
			t.Errorf("%s: expected error, got nil", c.name)
		}
	}
}

// TestOpenMCPCallsWriter_RejectsMissingOptions enforces that the
// constructor rejects an empty runDir / RunID so a misconfigured
// caller fails at construction rather than producing a record-less
// writer.
func TestOpenMCPCallsWriter_RejectsMissingOptions(t *testing.T) {
	if _, err := OpenMCPCallsWriter("", MCPCallsWriterOptions{RunID: "r"}); err == nil {
		t.Errorf("empty runDir: expected error, got nil")
	}
	if _, err := OpenMCPCallsWriter(t.TempDir(), MCPCallsWriterOptions{}); err == nil {
		t.Errorf("empty RunID: expected error, got nil")
	}
}

// TestMCPCallsWriter_AppendsToPlaceholder confirms the writer
// cooperates with the empty placeholder CreateRunDirectory leaves
// behind: opening the writer against a fresh run directory does not
// fail, and the first Write lands on disk without overwriting the
// placeholder.
func TestMCPCallsWriter_AppendsToPlaceholder(t *testing.T) {
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	runID := "20260530-120000-deadbe"
	now := time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC)
	dir, err := CreateRunDirectory(aiEnvDir, runID, now)
	if err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}

	// Placeholder must exist after CreateRunDirectory.
	if _, err := os.Stat(MCPCallsPath(dir.Path)); err != nil {
		t.Fatalf("placeholder mcp-calls.jsonl missing: %v", err)
	}

	w, err := OpenMCPCallsWriter(dir.Path, MCPCallsWriterOptions{RunID: dir.ID, Now: fixedTimes(now)})
	if err != nil {
		t.Fatalf("OpenMCPCallsWriter: %v", err)
	}
	if err := w.Write(MCPCallRecord{
		Stage:    MCPCallStageLaunch,
		Server:   "filesystem",
		Decision: MCPCallDecisionAllow,
		Reason:   "allowed",
	}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	records, err := ReadMCPCalls(dir.Path)
	if err != nil {
		t.Fatalf("ReadMCPCalls: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
}

// TestReadMCPCalls_EmptyAndMissing covers the read-side fallbacks: an
// absent file returns (nil, nil); an empty (placeholder) file returns
// (nil, nil).
func TestReadMCPCalls_EmptyAndMissing(t *testing.T) {
	// Missing file: ReadMCPCalls returns (nil, nil).
	tmp := t.TempDir()
	got, err := ReadMCPCalls(tmp)
	if err != nil {
		t.Fatalf("ReadMCPCalls(missing): %v", err)
	}
	if got != nil {
		t.Errorf("ReadMCPCalls(missing) = %v, want nil", got)
	}

	// Empty placeholder file: ReadMCPCalls returns (nil, nil).
	aiEnvDir := filepath.Join(t.TempDir(), ".ai-env")
	runID := "20260530-120000-deadbe"
	now := time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC)
	dir, err := CreateRunDirectory(aiEnvDir, runID, now)
	if err != nil {
		t.Fatalf("CreateRunDirectory: %v", err)
	}
	got, err = ReadMCPCalls(dir.Path)
	if err != nil {
		t.Fatalf("ReadMCPCalls(placeholder): %v", err)
	}
	if got != nil {
		t.Errorf("ReadMCPCalls(placeholder) = %v, want nil", got)
	}
}

// equalStringSlice is the tiny equality helper the test uses for
// ScopeKinds round-trip checks. It treats nil and []string{} as
// equivalent so the JSON encoder's "omitempty on empty slice" behavior
// does not cause a spurious failure.
func equalStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
