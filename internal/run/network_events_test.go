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

// TestNetworkEventsWriter_AppendsValidJSONL covers the writer's primary
// contract for plan 05 step 6: each Write call appends exactly one valid
// JSON object followed by a newline to network-events.jsonl at the root
// of the run directory, every line round-trips back to a NetworkEvent,
// and Close finalizes the file cleanly (subsequent Write fails, Close is
// idempotent). The test uses a real temp directory and the real JSON
// encoder/decoder — no mocks of the filesystem or encoding layers.
func TestNetworkEventsWriter_AppendsValidJSONL(t *testing.T) {
	// Build a real run directory on disk via the production helper so the
	// writer cooperates with the placeholder CreateRunDirectory left
	// behind, exactly as it will at supervisor wire-up time.
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

	w, err := OpenNetworkEventsWriter(dir.Path, NetworkEventsWriterOptions{
		RunID:   dir.ID,
		Backend: "docker-sbx",
		Now:     fixedTimes(t1, t2, t3),
	})
	if err != nil {
		t.Fatalf("OpenNetworkEventsWriter: %v", err)
	}

	// Exercise a representative mix: a policy-lifecycle event (carrying
	// allowdomains and blocked CIDRs/hosts), a per-destination event
	// (carrying destination/decision), and a failure event (carrying an
	// error). All three families share the NetworkEvent struct so we
	// catch encoder regressions across the omitempty fields too.
	events := []NetworkEvent{
		{
			Event:        NetworkEventPolicyApplyAttempt,
			EnvID:        "env-abc",
			Default:      "deny",
			AllowDomains: []string{"api.anthropic.com"},
			BlockedCIDRs: []string{"10.0.0.0/8", "169.254.169.254/32"},
			BlockedHosts: []string{"localhost", "host.docker.internal"},
		},
		{
			Event:       NetworkEventOutboundBlocked,
			EnvID:       "env-abc",
			Destination: "169.254.169.254:80",
			Decision:    "deny",
		},
		{
			Event: NetworkEventPolicyApplyFailed,
			EnvID: "env-abc",
			Error: "adapter refused policy",
		},
	}

	for i, evt := range events {
		if err := w.Write(evt); err != nil {
			t.Fatalf("Write(events[%d]=%q): %v", i, evt.Event, err)
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
	if err := w.Write(NetworkEvent{Event: NetworkEventPolicyApplied}); err == nil {
		t.Fatalf("Write after Close: expected error, got nil")
	}

	// Verify the file lives where the plan requires (run dir root) and
	// the writer materialized real bytes there.
	path := filepath.Join(dir.Path, "network-events.jsonl")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat %s: %v", path, err)
	}
	if info.Size() == 0 {
		t.Fatalf("network-events.jsonl is empty; expected at least one record")
	}

	// Read the file back and round-trip each line through json.Unmarshal
	// into a fresh NetworkEvent so we are exercising real encoding/
	// decoding, not mocks.
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
	if len(lines) != len(events) {
		t.Fatalf("expected %d lines, got %d (lines=%v)", len(events), len(lines), lines)
	}

	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
			t.Fatalf("line[%d] is empty", i)
		}
		var got NetworkEvent
		if err := json.Unmarshal([]byte(line), &got); err != nil {
			t.Fatalf("Unmarshal line[%d]=%q: %v", i, line, err)
		}
		// The writer pins RunID, Backend, and Timestamp; assert each so a
		// regression in the writer's fill-in code is caught.
		if got.RunID != dir.ID {
			t.Errorf("line[%d] RunID = %q, want %q", i, got.RunID, dir.ID)
		}
		if got.Backend != "docker-sbx" {
			t.Errorf("line[%d] Backend = %q, want %q", i, got.Backend, "docker-sbx")
		}
		if got.Timestamp != expectedTimestamps[i] {
			t.Errorf("line[%d] Timestamp = %q, want %q", i, got.Timestamp, expectedTimestamps[i])
		}
		if got.Event != events[i].Event {
			t.Errorf("line[%d] Event = %q, want %q", i, got.Event, events[i].Event)
		}
	}

	// Spot-check the typed payload fields on the first (policy-lifecycle)
	// record so an encoder that lost the slice fields shows up here.
	var first NetworkEvent
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("re-unmarshal first line: %v", err)
	}
	if first.Default != "deny" {
		t.Errorf("first.Default = %q, want %q", first.Default, "deny")
	}
	if len(first.AllowDomains) != 1 || first.AllowDomains[0] != "api.anthropic.com" {
		t.Errorf("first.AllowDomains = %v, want [api.anthropic.com]", first.AllowDomains)
	}
	if len(first.BlockedCIDRs) != 2 {
		t.Errorf("first.BlockedCIDRs = %v, want 2 entries", first.BlockedCIDRs)
	}
	if len(first.BlockedHosts) != 2 {
		t.Errorf("first.BlockedHosts = %v, want 2 entries", first.BlockedHosts)
	}
}
